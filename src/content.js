(function() {
  const styleId = "input-finder-style";
  const ensureStyle = () => {
  if (document.getElementById(styleId)) return;
  const s = document.createElement("style");
  s.id = styleId;
  s.textContent = `
    @keyframes inputFinderFlash {
      0% { box-shadow: 0 0 0 0 rgba(255, 71, 87, 0.8); }
      50% { box-shadow: 0 0 0 4px rgba(255, 71, 87, 0.4); }
      100% { box-shadow: 0 0 0 0 rgba(255, 71, 87, 0.0); }
    }
    .input-finder-highlight {
      outline: 2px solid #ff4757;
      outline-offset: 2px;
      border-radius: 4px;
      animation: inputFinderFlash 900ms ease-in-out;
      transition: outline-color 200ms ease-in-out;
    }
    @keyframes inputFinderLed {
      0%, 100% { opacity: 0.6; box-shadow: 0 0 3px rgba(255,71,87,0.5); }
      50% { opacity: 1; box-shadow: 0 0 9px rgba(255,71,87,0.9); }
    }
    .input-finder-led {
      position: fixed;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: #ff4757;
      animation: inputFinderLed 1.4s ease-in-out;
      z-index: 2147483647;
    }
  `;
  (document.head || document.documentElement).appendChild(s);
};
const truncate = (v, n = 160) => (v && v.length > n ? v.slice(0, n) + "…" : v || "");

const collectElements = () => {
  const inputs = [];
  const seen = new Set();
  const roots = [document];

  const collectFromRoot = (root) => {
    const sets = [
      root.querySelectorAll('input, textarea, select, button'),
      root.querySelectorAll('[contenteditable]'),
      root.querySelectorAll('[role="textbox"], [role="searchbox"], [role="combobox"]')
    ];
    const merged = [];
    sets.forEach((nl) => merged.push(...Array.from(nl)));
    const uniq = [];
    const mark = new Set();
    merged.forEach((el) => {
      if (!mark.has(el)) {
        mark.add(el);
        uniq.push(el);
      }
    });
    return uniq.filter((el) => {
      if (el.matches('[contenteditable]')) return el.isContentEditable;
      return true;
    });
  };

  for (let i = 0; i < roots.length; i++) {
    const r = roots[i];
    try {
      const list = collectFromRoot(r);
      list.forEach(el => inputs.push(el));
      
      const walker = document.createTreeWalker(r, NodeFilter.SHOW_ELEMENT);
      let node = walker.currentNode;
      while (node) {
        const sr = node.shadowRoot;
        if (sr && !seen.has(sr)) {
          seen.add(sr);
          roots.push(sr);
        }
        node = walker.nextNode();
      }
    } catch (_) {}
  }

  return inputs.map((el, index) => {
    const tag = (el.tagName || "").toLowerCase();
    const isInput = tag === "input";
    const isTextarea = tag === "textarea";
    const isSelect = tag === "select";
    const isButton = tag === "button";
    const role = (el.getAttribute("role") || "").toLowerCase();
    const isCE = !isInput && !isTextarea && !isSelect && !isButton && el.isContentEditable;
    const type = isInput
      ? (el.type || "")
      : isTextarea
        ? "textarea"
        : isSelect
          ? "select"
          : isButton
            ? "button"
            : isCE
              ? "contenteditable"
              : role
                ? `role:${role}`
                : "";
    const placeholder = isInput || isTextarea ? truncate(el.getAttribute("placeholder") || "") : "";

    // Attach original element reference to the returned object for internal use
    // Note: When sending via sendMessage, this property will be lost, which is fine.
    // We only need it for HIGHLIGHT action within this script context.
    return {
      element: el, 
      index,
      id: truncate(el.id || ""),
      name: truncate(el.name || ""),
      type: truncate(type || ""),
      placeholder,
      tag
    };
  });
};
const labelFor = (item) => {
  const a = item.id || item.name || item.placeholder || item.type || "input";
  return truncate(a, 120);
};
const highlight = (el) => {
  ensureStyle();
  try {
    // Attempt to focus first
    el.focus();
    el.scrollIntoView({ behavior: "auto", block: "center", inline: "nearest" });
  } catch (_) {
    el.scrollIntoView(true);
  }
  el.classList.add("input-finder-highlight");
  setTimeout(() => el.classList.remove("input-finder-highlight"), 1200);
};
const ledMark = (el) => {
  ensureStyle();
  const rect = el.getBoundingClientRect();
  const d = document.createElement("div");
  d.className = "input-finder-led";
  d.style.left = `${Math.max(4, rect.left + (rect.width / 2))}px`;
  d.style.top = `${Math.max(4, rect.top + (rect.height / 2))}px`;
  document.documentElement.appendChild(d);
  setTimeout(() => d.remove(), 1400);
};
const collectForms = () => {
    const masterList = collectElements();
    const forms = Array.from(document.querySelectorAll('form'));
    
    // 收集属于 form 的元素
    const formElements = new Set();

    const formResults = forms.map((form, idx) => {
      const fields = Array.from(form.elements).map((el) => {
        formElements.add(el);
        const tag = el.tagName.toLowerCase();
        if (tag === 'button' && !el.name && !el.value) return null;
        if (tag === 'fieldset') return null;

        const match = masterList.find((item) => item.element === el);
        const isHidden = el.type === "hidden" || el.style.display === "none" || el.style.visibility === "hidden";
        
        let fieldName = el.name;
        if (!fieldName) {
          if (el.id) fieldName = el.id;
          else if (el.placeholder) fieldName = `[ph:${truncate(el.placeholder, 20)}]`;
          else fieldName = `[${el.type || tag}_${match ? match.index : '?'}]`;
        }

        return {
          name: fieldName,
          originalName: el.name,
          value: el.value,
          type: el.type || tag,
          hidden: isHidden,
          index: match ? match.index : -1,
          label: el.id || el.name
        };
      }).filter(Boolean);

      return {
        index: idx,
        action: form.action,
        method: form.method,
        enctype: form.enctype,
        fields
      };
    });

    // 查找孤立字段 (Orphaned Fields)
    const orphanedFields = masterList.filter(item => {
        const el = item.element;
        if (formElements.has(el)) return false;
        if (el.form) return false; // 已经被归属到某个 form（虽然可能 querySelectorAll('form') 没抓到？理论上 form.elements 应该包含）
        return true;
    }).map(item => {
        const el = item.element;
        const tag = el.tagName.toLowerCase();
        // 排除一些显然不是数据输入点的
        if (tag === 'button' && !el.name && !el.value) return null;
        
        const isHidden = el.type === "hidden" || el.style.display === "none" || el.style.visibility === "hidden";
        let fieldName = el.name;
        if (!fieldName) {
          if (el.id) fieldName = el.id;
          else if (el.placeholder) fieldName = `[ph:${truncate(el.placeholder, 20)}]`;
          else fieldName = `[${el.type || tag}_${item.index}]`;
        }

        return {
          name: fieldName,
          originalName: el.name,
          value: el.value,
          type: el.type || tag,
          hidden: isHidden,
          index: item.index,
          label: el.id || el.name
        };
    }).filter(Boolean);

    if (orphanedFields.length > 0) {
        formResults.push({
            index: -1, // 特殊标记
            action: "(No Form Context)",
            method: "N/A",
            enctype: "N/A",
            fields: orphanedFields
        });
    }

    return formResults;
  };

  const collectSecurityInfo = () => {
    // 1. Storage Tokens
    const storageKeys = [];
    const tokenRegex = /token|auth|jwt|sess|key/i;
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (tokenRegex.test(k)) storageKeys.push({ type: 'localStorage', key: k, value: truncate(localStorage.getItem(k), 50) });
      }
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        if (tokenRegex.test(k)) storageKeys.push({ type: 'sessionStorage', key: k, value: truncate(sessionStorage.getItem(k), 50) });
      }
    } catch (_) {}

    // 2. CSRF
    const csrf = [];
    // Meta tags
    document.querySelectorAll('meta[name*="csrf" i], meta[name*="token" i]').forEach(m => {
      csrf.push({ type: 'Meta', name: m.name, value: truncate(m.content, 50) });
    });
    // Hidden inputs
    document.querySelectorAll('input[type="hidden"]').forEach(i => {
      if (/csrf|token|authenticity/i.test(i.name || i.id)) {
        csrf.push({ type: 'Hidden Input', name: i.name || i.id, value: truncate(i.value, 50) });
      }
    });

    // 3. PostMessage
    let hasPostMessage = false;
    if (window.onmessage) hasPostMessage = true;
    // Heuristic scan for addEventListener
    // Note: This is not 100% accurate as it scans static HTML source, not runtime listeners
    const html = document.documentElement.outerHTML.slice(0, 500000); // Limit size
    if (!hasPostMessage && /addEventListener\s*\(\s*["']message["']/.test(html)) {
      hasPostMessage = true;
    }

    // 4. Critical Interfaces (Forms & Links)
    const critical = [];
    const critRegex = /admin|login|upload|pay|delete|update|api/i;
    Array.from(document.forms).forEach(f => {
      if (critRegex.test(f.action)) critical.push({ type: 'Form Action', url: f.action });
    });
    // Sample some links (limit to first 100 to avoid perf hit)
    Array.from(document.querySelectorAll('a[href]')).slice(0, 100).forEach(a => {
       if (critRegex.test(a.href)) critical.push({ type: 'Link', url: a.href });
    });

    return {
      storageKeys,
      csrf,
      hasPostMessage,
      critical
    };
  };
  window.__XMCVE_collectSecurityInfo = collectSecurityInfo;

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || !message.type) return;
    if (message.type === "GET_INPUTS") {
      try {
        const items = collectElements().map((i) => {
          const { element, ...rest } = i; 
          return { ...rest, label: labelFor(i) };
        });
        sendResponse({ ok: true, inputs: items });
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
      return true;
    }
    if (message.type === "GET_FORMS") {
      try {
        const forms = collectForms();
        sendResponse({ ok: true, forms });
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
      return true;
    }
    if (message.type === "HIGHLIGHT") {
    try {
      const items = collectElements();
      const item = items[message.index];
      const el = item ? item.element : null;
      
      if (el) {
        const isHiddenInput = el.tagName.toLowerCase() === "input" && (el.type || "").toLowerCase() === "hidden";
        if (isHiddenInput) {
          try {
            el.scrollIntoView({ behavior: "auto", block: "center", inline: "nearest" });
          } catch (_) {
            el.scrollIntoView(true);
          }
          ledMark(el);
        } else {
          highlight(el);
        }
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false, error: "not_found" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
    return true;
  }
  if (message.type === "UNHIDE") {
    try {
      const items = collectElements();
      const item = items[message.index];
      const el = item ? item.element : null;
      if (el) {
        el.removeAttribute("hidden");
        el.style.display = "";
        el.style.visibility = "";
        if (el.tagName.toLowerCase() === "input" && el.type === "hidden") {
          el.type = "text";
        }
        highlight(el);
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false, error: "not_found" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
    return true;
  }
  if (message.type === "UPDATE_VAL") {
    try {
      const items = collectElements();
      const item = items[message.index];
      const el = item ? item.element : null;
      if (el) {
        el.value = message.value;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
        highlight(el);
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false, error: "not_found" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
    return true;
  }
});
window.__XMCVE_collectForms = collectForms;
})();
