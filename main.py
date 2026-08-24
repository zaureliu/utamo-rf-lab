from __future__ import annotations

import os
from ipaddress import ip_address

from app import create_app
from app.config import env_bool, env_int

app = create_app()


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False

if __name__ == "__main__":
    host = os.environ.get("UTAMO_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port = env_int("UTAMO_PORT", 5000, 1, 65535)
    debug = env_bool("UTAMO_DEBUG", False)
    if not _is_loopback_host(host) and not env_bool("UTAMO_ALLOW_REMOTE", False):
        raise RuntimeError(
            "Bind remoto bloqueado. Defina UTAMO_ALLOW_REMOTE=1 somente atras de TLS."
        )
    if debug and not _is_loopback_host(host):
        raise RuntimeError("UTAMO_DEBUG nao pode ser usado em bind remoto.")
    print("[UTAMO RFID / PROXMARK3 LAB] Iniciando...")
    print(f"[UTAMO RFID / PROXMARK3 LAB] Acesse: http://{host}:{port}")
    print(f"[UTAMO RFID / PROXMARK3 LAB] PM3 mode: {app.config['PM3_MODE']}")
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=debug)
