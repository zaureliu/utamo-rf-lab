from __future__ import annotations

import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from queue import Queue

from flask import current_app, has_app_context

from app.database.db import add_audit
from app.rf.protocol_catalog import SAFE_COMMAND_DESCRIPTIONS, classify_command, classify_smart_acquisition_command

log_queue = Queue()
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
PORT_RE = re.compile(r"^(COM\d{1,3}|/dev/(tty|cu\.)[A-Za-z0-9._-]+)$", re.IGNORECASE)
SHELL_META_RE = re.compile(r"[\r\n&|<>^%!`()\"]")

LAB_COMMANDS = SAFE_COMMAND_DESCRIPTIONS
SAFE_COMMANDS = LAB_COMMANDS


def timestamp_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def limpar_ansi(texto) -> str:
    if texto is None:
        return ""
    return ANSI_ESCAPE_RE.sub("", str(texto)).replace("\r", "").strip()


def emitir_log(node_id="local", output="", status="INFO", command="") -> dict:
    item = {
        "node": node_id,
        "port": node_id,
        "command": command,
        "output": limpar_ansi(output),
        "status": status,
        "timestamp": timestamp_now(),
    }
    log_queue.put(item)
    return item


def normalizar_comando(command) -> str:
    return " ".join(str(command or "").strip().lower().split())


def current_mode() -> str:
    if has_app_context():
        return current_app.config.get("PM3_MODE", "ANALYSIS_ONLY")
    return os.environ.get("UTAMO_PM3_MODE", "ANALYSIS_ONLY").strip().upper() or "ANALYSIS_ONLY"


def is_command_allowed(command, mode: str | None = None):
    result = classify_command(command, mode or current_mode())
    return bool(result.get("allowed")), result.get("reason", "")


def _validate_command_text(command: str) -> None:
    if not command or len(command) > 2048:
        raise ValueError("Comando vazio ou acima de 2048 caracteres.")
    if SHELL_META_RE.search(command):
        raise ValueError("Comando contém metacaracteres de shell proibidos.")
    if any(ord(ch) < 32 and ch not in "\t" for ch in command):
        raise ValueError("Comando contém caracteres de controle.")


def _validate_port(port: str) -> str:
    value = str(port or "").strip()
    if not PORT_RE.fullmatch(value):
        raise ValueError("Porta Proxmark3 inválida.")
    return value


def _allowed_roots() -> list[Path]:
    if has_app_context():
        return list(current_app.config.get("PM3_ALLOWED_ROOTS", []))
    return [Path(p).expanduser().resolve() for p in os.environ.get("UTAMO_PM3_ALLOWED_ROOTS", "").split(os.pathsep) if p.strip()]


def _validate_client_path(caminho_cliente: str) -> Path:
    path = Path(str(caminho_cliente or "").strip().strip('"')).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Cliente Proxmark3 não encontrado: {path}")
    if path.suffix.lower() not in {".exe", ".bat", ".cmd", ""}:
        raise ValueError("Somente executáveis Proxmark3 ou wrappers .bat/.cmd são aceitos.")
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise PermissionError("Cliente Proxmark3 não possui permissão de execução.")
    roots = _allowed_roots()
    if roots and not any(path == root or root in path.parents for root in roots):
        raise PermissionError("Cliente Proxmark3 fora dos diretórios permitidos.")
    return path


def montar_comando(caminho_cliente, comando, porta) -> list[str]:
    path = _validate_client_path(caminho_cliente)
    command = str(comando).strip()
    _validate_command_text(command)
    port = _validate_port(porta)

    if path.suffix.lower() in {".bat", ".cmd"}:
        if os.name != "nt":
            raise RuntimeError("Wrappers .bat/.cmd só podem ser executados no Windows.")
        comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
        # shell=False; metacharacters were rejected before reaching cmd.exe.
        return [comspec, "/d", "/s", "/c", "call", str(path), "-p", port, "-c", command]
    return [str(path), "-p", port, "-c", command]


def _max_timeout() -> int:
    if has_app_context():
        return int(current_app.config.get("PM3_MAX_TIMEOUT", 180))
    return max(5, min(600, int(os.environ.get("UTAMO_PM3_MAX_TIMEOUT", "180"))))


def _terminate_process(process: subprocess.Popen) -> None:
    """Terminate the PM3 client and, on Windows, its wrapper/child process tree."""
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            taskkill = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "taskkill.exe"
            subprocess.run(  # noqa: S603 - fixed executable and numeric PID; shell is disabled.
                [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                shell=False,
                timeout=10,
            )
            return
        except (OSError, subprocess.SubprocessError):
            pass
    process.kill()


def executar_comando_sync(caminho_cliente, comando, node_id="COM5", timeout=180, confirm_sensitive=False, working_directory=None, policy_context=None, cancel_check=None):
    logs = []

    def add(output, status="INFO"):
        item = emitir_log(node_id, output, status, comando)
        logs.append(item)

    mode = current_mode()
    classification = classify_smart_acquisition_command(comando) if policy_context == "smart_acquisition" else classify_command(comando, mode)
    if not classification.get("allowed"):
        add(classification.get("reason", "Comando bloqueado."), "BLOCKED")
        add_audit("local", "pm3.command", str(node_id), "blocked", str(classification))
        return {
            "status": "blocked",
            "reason": "command_not_allowed",
            "classification": classification,
            "logs": logs,
            "output": "",
        }
    if classification.get("requires_confirmation") and not bool(confirm_sensitive):
        add("Este comando exige confirmação explícita no modo OPERATOR_LAB.", "CONFIRMATION_REQUIRED")
        add_audit("local", "pm3.command", str(node_id), "confirmation_required", str(classification))
        return {
            "status": "confirmation_required",
            "reason": "sensitive_confirmation_required",
            "classification": classification,
            "logs": logs,
            "output": "",
        }

    try:
        command = str(comando or "").strip()
        _validate_command_text(command)
        port = _validate_port(str(node_id or "COM5"))
        client = _validate_client_path(str(caminho_cliente or ""))
        timeout_value = max(5, min(_max_timeout(), int(timeout or 180)))
        cmd = montar_comando(client, command, port)
        workdir = None
        if working_directory is not None:
            workdir = Path(working_directory).expanduser().resolve()
            workdir.mkdir(parents=True, exist_ok=True)
            if has_app_context():
                root = Path(current_app.config.get("SMART_SCAN_DIR")).expanduser().resolve()
                if workdir != root and root not in workdir.parents:
                    raise PermissionError("Diretório de trabalho fora da área de aquisição permitida.")
    except Exception as exc:
        add(str(exc), "ERROR")
        add_audit("local", "pm3.command", str(node_id), "rejected", str(exc))
        return {"status": "error", "reason": "validation_error", "logs": logs, "output": "", "classification": classification}

    add(f"Modo de proteção: {mode}", "INFO")
    add(f"Cliente: {client}", "INFO")
    add(f"Porta: {port}", "INFO")
    add(f"Comando: {command}", "INFO")

    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "TERM": "dumb", "PYTHONIOENCODING": "utf-8"})
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    try:
        process = subprocess.Popen(  # noqa: S603 - command/path/port are validated above; shell is disabled.
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            creationflags=creationflags,
            shell=False,
            cwd=str(workdir) if workdir else None,
        )
        timed_out = False
        cancelled = False
        deadline = time.monotonic() + timeout_value
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate_process(process)
                stdout, _ = process.communicate()
                add("Tempo limite excedido; processo encerrado.", "TIMEOUT")
                break
            try:
                stdout, _ = process.communicate(timeout=min(0.5, remaining))
                break
            except subprocess.TimeoutExpired:
                if callable(cancel_check) and bool(cancel_check()):
                    cancelled = True
                    _terminate_process(process)
                    stdout, _ = process.communicate()
                    add("Execução cancelada pelo operador; processo encerrado.", "CANCELLED")
                    break

        output = limpar_ansi(stdout or "")
        for line in output.splitlines():
            if line.strip():
                add(line, "OK")
        if not output:
            add("Nenhuma saída retornada pelo cliente Proxmark3.", "WARN")

        status = "cancelled" if cancelled else ("timeout" if timed_out else ("ok" if process.returncode == 0 else "error"))
        add(f"Processo finalizado com código {process.returncode}.", status.upper())
        add_audit("local", "pm3.command", port, status, f"mode={mode}; command={command}")
        return {
            "status": status,
            "returncode": process.returncode,
            "classification": classification,
            "logs": logs,
            "output": output,
            "working_directory": str(workdir) if workdir else "",
        }
    except Exception as exc:
        add(f"Erro ao executar Proxmark3: {exc}", "ERROR")
        add_audit("local", "pm3.command", port, "error", str(exc))
        return {"status": "error", "reason": str(exc), "classification": classification, "logs": logs, "output": ""}


def executar_comando(caminho_cliente, comando, node_id="COM5", confirm_sensitive=False):
    return executar_comando_sync(caminho_cliente, comando, node_id, confirm_sensitive=confirm_sensitive)
