"use strict";

document.documentElement.classList.add("js");

const csrfMeta = document.querySelector('meta[name="csrf-token"]');
const csrfToken = csrfMeta ? csrfMeta.content : "";
const safeMethods = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);
const nativeFetch = window.fetch.bind(window);

window.fetch = (input, init = {}) => {
  const url = typeof input === "string" ? input : input.url;
  const requestMethod = typeof input === "string" ? "GET" : (input.method || "GET");
  const method = (init.method || requestMethod).toUpperCase();
  if (!safeMethods.has(method) && new URL(url, window.location.href).origin === window.location.origin) {
    const headers = new Headers(init.headers || (typeof input === "string" ? undefined : input.headers) || {});
    headers.set("X-CSRF-Token", csrfToken);
    init = { ...init, headers };
  }
  return nativeFetch(input, init);
};

function activateTab(name, updateHash = true) {
  document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.remove("active"));
  document.querySelectorAll(".tab-btn").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === name);
    button.setAttribute("aria-selected", String(button.dataset.tab === name));
  });
  const panel = document.getElementById(`tab-${name}`);
  if (panel) panel.classList.add("active");
  if (updateHash) history.replaceState(null, "", `#tab-${name}`);
}

function filterBlocks(kind) {
  document.querySelectorAll("[data-block]").forEach((element) => {
    const flags = (element.dataset.flags || "").split(",");
    element.hidden = kind !== "all" && !flags.includes(kind);
  });
}

function addCsrfToForms() {
  if (!csrfToken) return;
  document.querySelectorAll("form").forEach((form) => {
    const method = (form.method || "get").toLowerCase();
    if (method === "get" || form.querySelector('input[name="_csrf_token"]')) return;
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = "_csrf_token";
    input.value = csrfToken;
    form.prepend(input);
  });
}

function initializeInteractions() {
  document.querySelectorAll(".tab-btn[data-tab]").forEach((button) => {
    button.type = "button";
    button.setAttribute("role", "tab");
    button.addEventListener("click", () => activateTab(button.dataset.tab));
  });
  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => filterBlocks(button.dataset.filter));
  });
  document.querySelectorAll("[data-command-picker]").forEach((select) => {
    select.addEventListener("change", () => {
      const target = document.querySelector(select.dataset.commandPicker);
      if (target && select.value) target.value = select.value;
    });
  });
  document.querySelectorAll("[data-use-command]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = document.getElementById("pm3-command");
      if (target) {
        target.value = button.dataset.useCommand || "";
        target.focus();
      }
    });
  });

  const requestedTab = (window.location.hash || "").replace("#tab-", "");
  if (requestedTab && document.getElementById(`tab-${requestedTab}`)) {
    activateTab(requestedTab, false);
  }
}

function createElement(tag, options = {}) {
  const element = document.createElement(tag);
  if (options.className) element.className = options.className;
  if (options.text !== undefined) element.textContent = String(options.text);
  if (options.href) element.href = options.href;
  if (options.sensitive) element.dataset.sensitive = options.sensitive;
  if (options.sensitiveText) element.dataset.sensitiveText = "";
  return element;
}

function initializeSmartScan() {
  const form = document.getElementById("smart-scan-form");
  if (!form) return;

  const live = document.getElementById("smart-scan-live");
  const progress = document.getElementById("smart-scan-progress");
  const start = document.getElementById("smart-scan-start");
  const cancel = document.getElementById("smart-scan-cancel");
  const message = document.getElementById("smart-scan-message");
  const stepsContainer = document.getElementById("smart-scan-steps");
  const actionsContainer = document.getElementById("smart-scan-actions");

  const NORMAL_POLL_MS = 1000;
  const BACKGROUND_POLL_MS = 3000;
  const ERROR_POLL_MS = 2500;
  const MAX_RENDERED_STEPS = 24;

  let activeJob = null;
  let pollTimer = null;
  let pollController = null;
  let pollInFlight = false;
  let lastJobSignature = "";
  let lastStepsSignature = "";
  let lastActionsSignature = "";

  function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value ?? "--";
  }

  function clearPollTimer() {
    if (pollTimer !== null) {
      window.clearTimeout(pollTimer);
      pollTimer = null;
    }
  }

  function stopPolling(clearJob = false) {
    clearPollTimer();
    if (pollController) {
      pollController.abort();
      pollController = null;
    }
    if (clearJob) activeJob = null;
  }

  function schedulePoll(delay = NORMAL_POLL_MS) {
    clearPollTimer();
    if (!activeJob) return;
    const effectiveDelay = document.hidden ? Math.max(delay, BACKGROUND_POLL_MS) : delay;
    pollTimer = window.setTimeout(poll, effectiveDelay);
  }

  function renderSteps(steps) {
    const visibleSteps = (Array.isArray(steps) ? steps : []).slice(-MAX_RENDERED_STEPS);
    const signature = JSON.stringify(visibleSteps.map((step) => [
      step.id,
      step.status,
      step.stage,
      step.command,
      String(step.output_excerpt || "").slice(-500),
    ]));
    if (signature === lastStepsSignature) return;
    lastStepsSignature = signature;

    stepsContainer.replaceChildren();
    if (!visibleSteps.length) {
      stepsContainer.append(createElement("p", { className: "muted", text: "Aguardando primeira etapa." }));
      return;
    }

    visibleSteps.forEach((step) => {
      const row = createElement("div", { className: "logline" });
      row.append(createElement("span", { className: "pill", text: step.status || "--" }));
      row.append(" ", createElement("strong", { text: step.stage || "--" }), " ");
      row.append(createElement("span", { className: "mono", text: step.command || "--" }));
      row.append(document.createElement("br"));
      row.append(createElement("span", {
        className: "muted",
        text: String(step.output_excerpt || "").slice(-500),
        sensitiveText: true,
      }));
      stepsContainer.append(row);
    });
  }

  function renderActions(job) {
    const signature = `${job.id}:${job.dump_id || ""}:${Boolean(job.terminal)}`;
    if (signature === lastActionsSignature) return;
    lastActionsSignature = signature;

    actionsContainer.replaceChildren();
    actionsContainer.append(createElement("a", {
      className: "btn",
      href: `/smart-scan/${job.id}`,
      text: "Abrir evidências",
    }));
    if (job.dump_id) {
      actionsContainer.append(createElement("a", {
        className: "btn",
        href: `/card-dump/${job.dump_id}`,
        text: "Abrir análise do dump",
      }));
    }
  }

  function render(job) {
    const evidence = job.result?.facts?.evidence || [];
    const jobSignature = JSON.stringify([
      job.id,
      job.progress,
      job.status,
      job.stage,
      job.card_type,
      job.family,
      job.uid,
      job.acquisition_status,
      job.dump_id,
      job.error,
      Boolean(job.terminal),
      evidence,
      (job.steps || []).map((step) => [step.id, step.status, step.stage, step.command, String(step.output_excerpt || "").slice(-500)]),
    ]);
    if (jobSignature === lastJobSignature) return;
    lastJobSignature = jobSignature;

    live.hidden = false;
    progress.style.width = `${Math.max(0, Math.min(100, Number(job.progress || 0)))}%`;
    setText("smart-status", job.status || "--");
    setText("smart-card", job.card_type || job.family || "identificando");
    setText("smart-uid", job.uid || "--");
    setText("smart-acquisition", job.acquisition_status || "em andamento");
    setText("smart-scan-title", `Leitura inteligente #${job.id} — ${job.stage || job.status}`);
    setText("smart-scan-subtitle", `Progresso ${job.progress || 0}%`);

    message.className = job.error ? "warning spacer-top" : "notice spacer-top";
    message.textContent = job.error || evidence.join(" • ") || "Mantenha o cartão sobre a antena.";

    renderSteps(job.steps || []);
    renderActions(job);
    window.UtamoPresentationMode?.refresh(live);
    cancel.hidden = Boolean(job.terminal);
    start.disabled = !job.terminal;
  }

  async function poll() {
    if (!activeJob || pollInFlight) return;

    const jobId = activeJob;
    const controller = new AbortController();
    pollController = controller;
    pollInFlight = true;
    let nextDelay = NORMAL_POLL_MS;

    try {
      const response = await fetch(`/api/smart-scan/${jobId}`, { signal: controller.signal });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Falha ao consultar leitura.");
      if (activeJob !== jobId) return;

      render(data.job);
      if (data.job.terminal) {
        activeJob = null;
        clearPollTimer();
      }
    } catch (error) {
      if (error.name !== "AbortError" && activeJob === jobId) {
        message.className = "warning spacer-top";
        message.textContent = error.message;
        nextDelay = ERROR_POLL_MS;
      }
    } finally {
      if (pollController === controller) pollController = null;
      pollInFlight = false;
      if (activeJob === jobId) schedulePoll(nextDelay);
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    stopPolling(true);

    lastJobSignature = "";
    lastStepsSignature = "";
    lastActionsSignature = "";
    start.disabled = true;
    live.hidden = false;
    message.className = "notice spacer-top";
    message.textContent = "Iniciando aquisição segura...";

    const formData = new FormData(form);
    const payload = {
      auto_dump: formData.has("auto_dump"),
      read_ndef: formData.has("read_ndef"),
      enforce_uid: formData.has("enforce_uid"),
      session_id: formData.get("session_id") || null,
    };

    try {
      const response = await fetch("/api/smart-scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || "Não foi possível iniciar a leitura.");
      activeJob = data.job.id;
      render(data.job);
      await poll();
    } catch (error) {
      start.disabled = false;
      message.className = "warning spacer-top";
      message.textContent = error.message;
    }
  });

  cancel.addEventListener("click", async () => {
    if (activeJob) await fetch(`/api/smart-scan/${activeJob}/cancel`, { method: "POST" });
  });

  document.addEventListener("visibilitychange", () => {
    if (activeJob && !pollInFlight) schedulePoll(document.hidden ? BACKGROUND_POLL_MS : 0);
  });

  window.addEventListener("pagehide", () => stopPolling(true), { once: true });
}

document.addEventListener("DOMContentLoaded", () => {
  addCsrfToForms();
  initializeInteractions();
  initializeSmartScan();
});
