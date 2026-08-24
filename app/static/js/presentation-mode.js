"use strict";

(function exposePresentationMode(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.UtamoPresentationMode = api;
  if (typeof document !== "undefined") api.initialize(document, root);
})(typeof window !== "undefined" ? window : null, () => {
  const STORAGE_KEY = "utamo.presentationMode";
  const explicitState = new WeakMap();
  const textState = new WeakMap();
  let active = false;
  let pageDocument = null;
  let pageWindow = null;

  const PLACEHOLDERS = Object.freeze({
    credential: "[CREDENCIAL OCULTA]",
    key: "[CHAVE OCULTA]",
    serial: "[SERIAL OCULTO]",
    token: "[TOKEN OCULTO]",
    uid: "[UID OCULTO]",
  });

  function maskMifareTrailer(value) {
    const source = String(value ?? "");
    const hexPositions = [];
    for (let index = 0; index < source.length; index += 1) {
      if (/[0-9a-f]/i.test(source[index])) hexPositions.push(index);
    }
    if (hexPositions.length !== 32) return PLACEHOLDERS.key;

    const maskedPositions = new Set([...hexPositions.slice(0, 12), ...hexPositions.slice(20)]);
    return Array.from(source, (character, index) => maskedPositions.has(index) ? "•" : character).join("");
  }

  function maskValue(value, kind = "credential") {
    const source = String(value ?? "");
    if (!source || source === "--") return source;
    if (kind === "mifare-trailer") return maskMifareTrailer(source);
    return PLACEHOLDERS[kind] || PLACEHOLDERS.credential;
  }

  function maskTrailerObjects(value) {
    return value.replace(/\{[^{}]{0,2500}\}/g, (objectText) => {
      if (!/["']is_trailer["']\s*:\s*true/i.test(objectText)) return objectText;
      return objectText.replace(
        /(["']block_hex["']\s*:\s*["'])([0-9a-f][0-9a-f\s:-]{30,}[0-9a-f])(["'])/i,
        (_match, prefix, trailer, suffix) => `${prefix}${maskMifareTrailer(trailer)}${suffix}`,
      );
    });
  }

  function maskSensitiveText(value) {
    let masked = maskTrailerObjects(String(value ?? ""));
    const replacements = [
      {
        pattern: /(\b(?:card\s*)?uids?\b["']?\s*[:=]\s*["']?)([0-9a-f][0-9a-f\s:-]{3,}[0-9a-f])/gi,
        placeholder: PLACEHOLDERS.uid,
      },
      {
        pattern: /((?:\b(?:device\s+)?serial(?:\s+(?:number|no\.?))?|\bs\/?n|\bsn\b)["']?\s*[:=#]\s*["']?)([a-z0-9][a-z0-9._:-]{2,})/gi,
        placeholder: PLACEHOLDERS.serial,
      },
      {
        pattern: /(\b(?:api[_ -]?key|auth(?:entication)?[_ -]?key|key[_ -]?[ab])\b["']?\s*[:=]\s*["']?)([0-9a-z+/_.:-]{6,}={0,2})/gi,
        placeholder: PLACEHOLDERS.key,
      },
      {
        pattern: /(\bkey\b["']?\s*[:=]\s*["']?)([0-9a-f]{8,})/gi,
        placeholder: PLACEHOLDERS.key,
      },
      {
        pattern: /(\b(?:access[_ -]?token|refresh[_ -]?token|id[_ -]?token|token)\b["']?\s*[:=]\s*["']?)([^\s,"']{6,})/gi,
        placeholder: PLACEHOLDERS.token,
      },
      {
        pattern: /(\b(?:username|user|login|password|passwd|senha|credential|credencial)\b["']?\s*[:=]\s*["']?)([^\s,"']{2,})/gi,
        placeholder: PLACEHOLDERS.credential,
      },
    ];

    replacements.forEach(({ pattern, placeholder }) => {
      masked = masked.replace(pattern, (_match, prefix) => `${prefix}${placeholder}`);
    });
    masked = masked.replace(/\bBearer\s+[a-z0-9._~+/-]+=*/gi, `Bearer ${PLACEHOLDERS.token}`);
    masked = masked.replace(/\beyJ[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+\b/gi, PLACEHOLDERS.token);
    return masked;
  }

  function nodesWithin(rootNode, selector) {
    const nodes = [];
    if (rootNode?.nodeType === 1 && rootNode.matches(selector)) nodes.push(rootNode);
    if (rootNode?.querySelectorAll) nodes.push(...rootNode.querySelectorAll(selector));
    return nodes;
  }

  function updateExplicitElement(element, shouldMask) {
    if (element.matches("input, textarea, select")) return;
    const current = element.textContent;
    const prior = explicitState.get(element);
    if (shouldMask) {
      const original = prior && current === prior.masked ? prior.original : current;
      const masked = maskValue(original, element.dataset.sensitive);
      explicitState.set(element, { original, masked });
      if (current !== masked) element.textContent = masked;
    } else if (prior) {
      if (current === prior.masked) element.textContent = prior.original;
      explicitState.delete(element);
    }
  }

  function updateTextNode(node, shouldMask) {
    if (node.parentElement?.closest("[data-sensitive]")) return;
    const current = node.nodeValue;
    const prior = textState.get(node);
    if (shouldMask) {
      const original = prior && current === prior.masked ? prior.original : current;
      const masked = maskSensitiveText(original);
      textState.set(node, { original, masked });
      if (current !== masked) node.nodeValue = masked;
    } else if (prior) {
      if (current === prior.masked) node.nodeValue = prior.original;
      textState.delete(node);
    }
  }

  function updateTextContainer(container, shouldMask) {
    const walker = pageDocument.createTreeWalker(container, 4);
    while (walker.nextNode()) updateTextNode(walker.currentNode, shouldMask);
  }

  function refresh(rootNode = pageDocument) {
    if (!rootNode || !active) return;
    nodesWithin(rootNode, "[data-sensitive]").forEach((element) => updateExplicitElement(element, true));
    nodesWithin(rootNode, "[data-sensitive-text]").forEach((element) => updateTextContainer(element, true));
  }

  function restore(rootNode = pageDocument) {
    if (!rootNode) return;
    nodesWithin(rootNode, "[data-sensitive]").forEach((element) => updateExplicitElement(element, false));
    nodesWithin(rootNode, "[data-sensitive-text]").forEach((element) => updateTextContainer(element, false));
  }

  function updateButton() {
    const button = pageDocument?.getElementById("presentation-mode-toggle");
    if (!button) return;
    button.setAttribute("aria-pressed", String(active));
    button.textContent = active ? "Apresentação ativa" : "Apresentação";
    button.title = active ? "Desativar máscaras de dados sensíveis" : "Mascarar dados sensíveis na interface";
  }

  function persist(value) {
    try {
      pageWindow?.localStorage.setItem(STORAGE_KEY, value ? "on" : "off");
    } catch (_error) {
      // O modo continua funcional quando o armazenamento do navegador estiver indisponível.
    }
  }

  function setActive(value, options = {}) {
    active = Boolean(value);
    pageDocument?.documentElement.classList.toggle("presentation-mode", active);
    if (pageDocument) pageDocument.documentElement.dataset.presentationMode = active ? "on" : "off";
    if (active) refresh(); else restore();
    pageDocument?.documentElement.classList.add("presentation-mode-ready");
    updateButton();
    if (options.persist !== false) persist(active);
    return active;
  }

  function initialize(doc, win) {
    pageDocument = doc;
    pageWindow = win;
    let stored = false;
    try {
      stored = pageWindow?.localStorage.getItem(STORAGE_KEY) === "on";
    } catch (_error) {
      stored = false;
    }
    active = stored;
    pageDocument.documentElement.classList.toggle("presentation-mode", active);

    const ready = () => {
      setActive(active, { persist: false });
      pageDocument.getElementById("presentation-mode-toggle")?.addEventListener("click", () => setActive(!active));
    };
    if (pageDocument.readyState === "loading") pageDocument.addEventListener("DOMContentLoaded", ready, { once: true });
    else ready();
  }

  return Object.freeze({
    initialize,
    isActive: () => active,
    maskMifareTrailer,
    maskSensitiveText,
    maskValue,
    refresh,
    setActive,
  });
});
