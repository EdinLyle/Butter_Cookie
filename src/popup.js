const q = (sel) => document.querySelector(sel);
const refreshBtn = q("#refresh");
const ledEl = q("#led");
const statusTextEl = q("#statusText");
const fuzzAllBtn = q("#fuzzAll");
const cspListEl = q("#csp-list");
const readCspBtn = q("#readCsp");
const encoderInputEl = q("#encoderInput");
const encHtmlBtn = q("#encHtml");
const decHtmlBtn = q("#decHtml");
const encUrlBtn = q("#encUrl");
const encHexBtn = q("#encHex");
const decHexBtn = q("#decHex");
const encoderListEl = q("#encoderList");
const sqlMethodEl = q("#sqlMethod");
const sqlUrlEl = q("#sqlUrl");
const sqlFillBtn = q("#sqlFill");
const sqlSendBtn = q("#sqlSend");
const sqlEntryEl = q("#sqlEntry");
const sqlKeyEl = q("#sqlKey");
const sqlPayloadEl = q("#sqlPayload");
const sqlAppendBtn = q("#sqlAppend");
const sqlReplaceBtn = q("#sqlReplace");
const sqlHeadersEl = q("#sqlHeaders");
const sqlCookiesEl = q("#sqlCookies");
const sqlBodyTypeEl = q("#sqlBodyType");
const sqlBodyEl = q("#sqlBody");
const sqlCurlBtn = q("#sqlCurl");
const sqlClearBtn = q("#sqlClear");
const sqlRespMetaEl = q("#sqlRespMeta");
const sqlRespHeadersEl = q("#sqlRespHeaders");
const sqlRespBodyEl = q("#sqlRespBody");
const jsSiteEl = q("#jsSite");
const jsStateEl = q("#jsState");
const jsDisableBtn = q("#jsDisable");
const jsEnableBtn = q("#jsEnable");
const jsBypassResizeBtn = q("#jsBypassResize");
const jsBypassInfiniteDebuggerBtn = q("#jsBypassInfiniteDebugger");
const jsBypassEvalDebuggerBtn = q("#jsBypassEvalDebugger");
const jsBypassToStringBtn = q("#jsBypassToString");
const uaSiteEl = q("#uaSite");
const uaInputEl = q("#uaInput");
const uaApplyBtn = q("#uaApply");
const uaClearBtn = q("#uaClear");
const cookieSiteEl = q("#cookieSite");
const cookieInputEl = q("#cookieInput");
const xffInputEl = q("#xffInput");
const refererInputEl = q("#refererInput");
const clientIpInputEl = q("#clientIpInput");
const xRealIpInputEl = q("#xRealIpInput");
const sniffBtn = q("#sniffAssets");
const sniffListEl = q("#sniff-list");
const fpBtn = q("#sniffFP");
const fpListEl = q("#fp-list");
const formsContainer = q("#forms-container");
const exportJsonBtn = q("#exportJson");
const exportTxtBtn = q("#exportTxt");
const exportCsvBtn = q("#exportCsv");
const exportXlsxBtn = q("#exportXlsx");
const vueDetectBtn = q("#vueDetect");
const vueDumpRoutesBtn = q("#vueDumpRoutes");
const vueBypassBtn = q("#vueBypass");
const vueCopyUrlsBtn = q("#vueCopyUrls");
const vueOpenAllBtn = q("#vueOpenAll");
const vueStatusEl = q("#vueStatus");
const vueDetectListEl = q("#vueDetectList");
const vueUrlsEl = q("#vueUrls");
const fuzzJsOpenAllBtn = q("#fuzzJsOpenAll");
const fuzzJsPauseBtn = q("#fuzzJsPause");
const fuzzApiPauseBtn = q("#fuzzApiPause");
const fuzzParamPauseBtn = q("#fuzzParamPause");
const state = { tabId: null, scanning: false, sniffOut: null, fuzzOut: { js: [], api: [], param: [] }, vueUrls: "", timeouts: [], openedUrlsCount: 0, actualUrlsCount: 0 };
const fuzzCtl = { js: null, api: null, param: null };

// Bulk URL Opener Elements
const urlListEl = q("#urlList");
const focusTabsEl = q("#focusTabs");
const openDelayRangeEl = q("#openDelayRange");
const openDelayValueEl = q("#openDelayValue");
const openUrlListBtn = q("#openUrlList");
const stopUrlListBtn = q("#stopUrlList");
const getTabUrlListBtn = q("#getTabUrlList");
const clearUrlListBtn = q("#clearUrlList");
const urlProgressBarEl = q("#urlProgressBar");
const urlOpenStatusContainerEl = q("#urlOpenStatusContainer");
const urlListComboEl = q("#urlListCombo");
const listNameEl = q("#listName");
const loadListBtn = q("#loadList");
const editListBtn = q("#editList");
const updateListBtn = q("#updateList");
const deleteListBtn = q("#deleteList");
const saveListBtn = q("#saveList");
const urlListStatusContainerEl = q("#urlListStatusContainer");
const getActiveTab = () =>
  new Promise((resolve, reject) =>
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) =>
      tabs && tabs[0] ? resolve(tabs[0]) : reject(new Error("no_active_tab"))
    )
  );
const readCsp = (tabId) =>
  new Promise((resolve, reject) =>
    chrome.runtime.sendMessage({ type: "GET_CSP", tabId }, (res) =>
      chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res)
    )
  );
const loadFingerRules = async () => {
  try {
    const res = await fetch(chrome.runtime.getURL('data/finger.json'));
    const json = await res.json();
    return json.fingerprint || [];
  } catch (e) {
    return [];
  }
};
const getHeaders = (tabId) =>
  new Promise((resolve) =>
    chrome.runtime.sendMessage({ type: "GET_HEADERS", tabId }, (res) =>
      resolve((res && res.ok && res.data && res.data.headers) ? res.data.headers : [])
    )
  );
const getPageContent = (tabId) =>
  new Promise((resolve) =>
    chrome.scripting.executeScript(
      {
        target: { tabId },
        func: () => ({
          title: document.title || "",
          html: document.documentElement.outerHTML || ""
        })
      },
      (res) => resolve(res && res[0] && res[0].result ? res[0].result : { title: "", html: "" })
    )
  );

const getPageUrl = (tabId) =>
  new Promise((resolve) =>
    chrome.scripting.executeScript(
      { target: { tabId }, func: () => location.href },
      (res) => resolve(res && res[0] && res[0].result ? res[0].result : null)
    )
  );

const execInTab = (tabId, options) =>
  new Promise((resolve, reject) =>
    chrome.scripting.executeScript(
      { target: { tabId }, ...options },
      (res) => (chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res))
    )
  );

const execInTabMain = async (tabId, func, args) => {
  try {
    return await execInTab(tabId, { world: "MAIN", func, args });
  } catch (_) {
    return await execInTab(tabId, { func, args });
  }
};

// VueCrack 完整检测逻辑 - 作为独立函数供 executeScript 使用
const executeVueDetect = () => {
  // 工具函数：广度优先查找 Vue 根实例
  function findVueRoot(root, maxDepth = 1000) {
    const queue = [{ node: root, depth: 0 }];
    while (queue.length > 0) {
      const { node, depth } = queue.shift();
      if (depth > maxDepth) break;
      
      if (node.__vue_app__ || node.__vue__ || node._vnode) {
        return node;
      }
      
      if (node.nodeType === 1 && node.childNodes && node.childNodes.length > 0) {
        for (let i = 0; i < node.childNodes.length; i++) {
          queue.push({ node: node.childNodes[i], depth: depth + 1 });
        }
      }
    }
    return null;
  }
  
  // 获取 Vue 版本
  function getVueVersion(vueRoot) {
    let version = '';
    try {
      if (vueRoot.__vue_app__) {
        version = vueRoot.__vue_app__.version || '';
      }
      if (!version && vueRoot.__vue__ && vueRoot.__vue__.$options && vueRoot.__vue__.$options._base) {
        version = vueRoot.__vue__.$options._base.version || '';
      }
      if (!version && window.Vue && window.Vue.version) {
        version = window.Vue.version;
      }
      if (!version && window.__VUE_DEVTOOLS_GLOBAL_HOOK__ && window.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue) {
        version = window.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue.version;
      }
    } catch (e) {}
    return version || 'unknown';
  }
  
  // 查找 Vue Router 实例
  function findVueRouter(vueRoot) {
    try {
      if (vueRoot.__vue_app__) {
        const app = vueRoot.__vue_app__;
        if (app.config && app.config.globalProperties && app.config.globalProperties.$router) {
          return app.config.globalProperties.$router;
        }
        if (app._instance) {
          const instance = app._instance;
          if (instance.appContext && instance.appContext.config && instance.appContext.config.globalProperties && instance.appContext.config.globalProperties.$router) {
            return instance.appContext.config.globalProperties.$router;
          }
          if (instance.ctx && instance.ctx.$router) {
            return instance.ctx.$router;
          }
        }
      }
      
      if (vueRoot.__vue__) {
        const vue = vueRoot.__vue__;
        return vue.$router || 
               (vue.$root && vue.$root.$router) ||
               (vue.$root && vue.$root.$options && vue.$root.$options.router) ||
               vue._router;
      }
    } catch (e) {
      console.error('[VueDetect] findVueRouter error:', e);
    }
    return null;
  }
  
  // 路径拼接
  function joinPath(base, path) {
    if (!path) return base || '/';
    if (path.startsWith('/')) return path;
    if (!base || base === '/') return '/' + path;
    return (base.endsWith('/') ? base.slice(0, -1) : base) + '/' + path;
  }
  
  // 判断 meta.auth 是否表示需要鉴权
  function isAuthTrue(val) {
    return val === true || val === 'true' || val === 1 || val === '1';
  }
  
  // 提取 Router 基础路径
  function extractRouterBase(router) {
    try {
      return router.options ? router.options.base : '' || 
             router.history ? router.history.base : '';
    } catch (e) {
      return '';
    }
  }
  
  // 分析页面链接
  function analyzePageLinks() {
    const result = { detectedBasePath: '', commonPrefixes: [] };
    try {
      const links = Array.from(document.querySelectorAll('a[href]'))
        .map(a => a.getAttribute('href'))
        .filter(href => href && href.startsWith('/') && !href.startsWith('//') && !href.includes('.') && href.length > 1);
      
      if (links.length < 3) return result;
      
      const pathSegments = links.map(link => link.split('/').filter(Boolean));
      const firstSegments = {};
      
      pathSegments.forEach(segments => {
        if (segments.length > 0) {
          const first = segments[0];
          firstSegments[first] = (firstSegments[first] || 0) + 1;
        }
      });
      
      const sortedPrefixes = Object.entries(firstSegments)
        .sort((a, b) => b[1] - a[1])
        .map(entry => ({ prefix: entry[0], count: entry[1] }));
      
      result.commonPrefixes = sortedPrefixes;
      
      if (sortedPrefixes.length > 0 && sortedPrefixes[0].count / links.length > 0.6) {
        result.detectedBasePath = '/' + sortedPrefixes[0].prefix;
      }
    } catch (e) {
      console.error('[VueDetect] analyzePageLinks error:', e);
    }
    
    return result;
  }
  
  // 修改路由 meta auth 字段
  function patchAllRouteAuth(router) {
    const modified = [];
    
    function patchMeta(route) {
      if (route.meta && typeof route.meta === 'object') {
        Object.keys(route.meta).forEach(key => {
          if (key.toLowerCase().includes('auth') && isAuthTrue(route.meta[key])) {
            route.meta[key] = false;
            modified.push({ path: route.path || '', name: route.name || '' });
          }
        });
      }
    }
    
    try {
      if (typeof router.getRoutes === 'function') {
        router.getRoutes().forEach(patchMeta);
      } else if (router.options && Array.isArray(router.options.routes)) {
        function walkRoutes(routes) {
          if (!Array.isArray(routes)) return;
          routes.forEach(route => {
            patchMeta(route);
            if (Array.isArray(route.children)) walkRoutes(route.children);
          });
        }
        walkRoutes(router.options.routes);
      } else if (router.matcher) {
        if (typeof router.matcher.getRoutes === 'function') {
          router.matcher.getRoutes().forEach(patchMeta);
        }
      }
    } catch (e) {
      console.error('[VueDetect] patchAllRouteAuth error:', e);
    }
    
    return modified;
  }
  
  // 清除路由守卫
  function patchRouterGuards(router) {
    try {
      ['beforeEach', 'beforeResolve', 'afterEach'].forEach(hook => {
        if (typeof router[hook] === 'function') {
          router[hook] = () => {};
        }
      });
      
      ['beforeGuards', 'beforeResolveGuards', 'afterGuards', 'beforeHooks', 'resolveHooks', 'afterHooks']
        .forEach(prop => {
          if (Array.isArray(router[prop])) {
            router[prop].length = 0;
          }
        });
    } catch (e) {
      console.error('[VueDetect] patchRouterGuards error:', e);
    }
  }
  
  // 数据序列化（避免循环引用）
  function sanitizeRouteObject(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    const sanitized = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        if (value instanceof Function || value instanceof Promise) {
          sanitized[key] = '[Function]';
        } else if (typeof value === 'object' && value !== null) {
          sanitized[key] = '[Object]';
        } else {
          sanitized[key] = value;
        }
      }
    }
    return sanitized;
  }
  
  // 列出所有路由
  function listAllRoutes(router) {
    const list = [];
    try {
      if (typeof router.getRoutes === 'function') {
        router.getRoutes().forEach(r => {
          list.push({ 
            name: r.name || '', 
            path: r.path || '', 
            meta: sanitizeRouteObject(r.meta || {}) 
          });
        });
      } else if (router.options && Array.isArray(router.options.routes)) {
        function traverse(routes, basePath = '') {
          routes.forEach(r => {
            const fullPath = joinPath(basePath, r.path);
            list.push({ 
              name: r.name || '', 
              path: fullPath, 
              meta: sanitizeRouteObject(r.meta || {}) 
            });
            if (Array.isArray(r.children)) traverse(r.children, fullPath);
          });
        }
        traverse(router.options.routes);
      } else if (router.matcher && typeof router.matcher.getRoutes === 'function') {
        router.matcher.getRoutes().forEach(r => {
          list.push({ name: r.name || '', path: r.path || '', meta: sanitizeRouteObject(r.meta || {}) });
        });
      } else if (router.history && router.history.current && Array.isArray(router.history.current.matched)) {
        router.history.current.matched.forEach(r => {
          list.push({ name: r.name || '', path: r.path || '', meta: sanitizeRouteObject(r.meta || {}) });
        });
      }
    } catch (e) {
      console.error('[VueDetect] listAllRoutes error:', e);
    }
    return list;
  }
  
  // 主执行逻辑
  const result = {
    vueDetected: false,
    vueVersion: null,
    routerDetected: false,
    modifiedRoutes: [],
    allRoutes: [],
    routerBase: '',
    pageAnalysis: { detectedBasePath: '', commonPrefixes: [] },
    error: null
  };
  
  try {
    const vueRoot = findVueRoot(document.body);
    if (!vueRoot) {
      result.error = '未检测到 Vue 实例';
      return result;
    }
    
    result.vueDetected = true;
    result.vueVersion = getVueVersion(vueRoot);
    
    const router = findVueRouter(vueRoot);
    if (!router) {
      result.error = '未检测到 Vue Router 实例';
      return result;
    }
    
    result.routerDetected = true;
    result.routerBase = extractRouterBase(router);
    result.pageAnalysis = analyzePageLinks();
    result.modifiedRoutes = patchAllRouteAuth(router);
    patchRouterGuards(router);
    result.allRoutes = listAllRoutes(router);
    
  } catch (e) {
    result.error = e.toString();
  }
  
  return result;
};

const parseHeaderLines = (text) => {
  const out = {};
  const raw = String(text || "");
  raw.split(/\r?\n/).forEach((line) => {
    const s = line.trim();
    if (!s) return;
    const idx = s.indexOf(":");
    if (idx <= 0) return;
    const k = s.slice(0, idx).trim();
    const v = s.slice(idx + 1).trim();
    if (!k) return;
    out[k] = v;
  });
  return out;
};

const stringifyHeaderLines = (obj) => {
  const out = [];
  Object.keys(obj || {}).forEach((k) => {
    const v = obj[k];
    if (v === undefined || v === null) return;
    out.push(`${k}: ${String(v)}`);
  });
  return out.join("\n");
};

const parseCookieString = (text) => {
  const out = {};
  String(text || "")
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean)
    .forEach((pair) => {
      const idx = pair.indexOf("=");
      if (idx <= 0) return;
      const k = pair.slice(0, idx).trim();
      const v = pair.slice(idx + 1).trim();
      if (!k) return;
      out[k] = v;
    });
  return out;
};

const stringifyCookieString = (obj) => {
  const out = [];
  Object.keys(obj || {}).forEach((k) => {
    const v = obj[k];
    if (v === undefined || v === null) return;
    out.push(`${k}=${String(v)}`);
  });
  return out.join("; ");
};

const parseFormBody = (text) => {
  const raw = String(text || "").trim();
  const usp = new URLSearchParams();
  if (!raw) return usp;
  if (raw.includes("&") || (raw.includes("=") && !raw.includes("\n"))) {
    try {
      const tmp = new URLSearchParams(raw);
      tmp.forEach((v, k) => usp.append(k, v));
      return usp;
    } catch (_) {}
  }
  raw.split(/\r?\n/).forEach((line) => {
    const s = line.trim();
    if (!s) return;
    const idx = s.indexOf("=");
    if (idx < 0) {
      usp.append(s, "");
      return;
    }
    const k = s.slice(0, idx).trim();
    const v = s.slice(idx + 1);
    if (!k) return;
    usp.append(k, v);
  });
  return usp;
};

const safeSetText = (el, text) => {
  if (!el) return;
  el.textContent = String(text || "");
};

// Bulk URL Opener Functions

/**
 * Validates a URL
 * @param {string} url - The URL to validate
 * @returns {boolean} - True if the URL is valid, false otherwise
 */
const isUrlValid = (url) => {
  const knownInvalidUrls = ["chrome://extensions/", "chrome://newtab/", "edge://extensions/", "edge://newtab/", "about:addons", "about:newtab", "chrome://startpageshared/"];

  try {
    if (url.length === 0) {
      return false;
    }

    new URL(url);

    return !knownInvalidUrls.includes(url) &&
      !url.startsWith("chrome-extension://") &&
      !url.startsWith("chrome://extensions") &&
      !url.startsWith("edge://extensions") &&
      !url.startsWith("extension://") &&
      !url.startsWith("about:debugging") &&
      !url.startsWith("about:devtools") &&
      !url.startsWith("moz-extension");

  } catch (_) {
    return false;
  }
};

/**
 * Opens a URL in a new tab
 * @param {string} urlLink - The URL to open
 * @param {boolean} focus - Whether to focus the new tab
 * @returns {Promise<number|null>} - The tab ID or null if failed
 */
const openUrlInNewTab = (urlLink, focus) => {
  return new Promise((resolve) => {
    chrome.tabs.create({ url: urlLink, active: focus }, (tab) => {
      if (chrome.runtime.lastError) {
        console.error("Error opening tab:", chrome.runtime.lastError);
        resolve(null);
      } else {
        resolve(tab.id);
      }
    });
  });
};

/**
 * Gets URLs from currently open tabs
 */
const getTabUrlsIntoTextArea = async () => {
  try {
    const tabs = await new Promise((resolve) => {
      chrome.tabs.query({ currentWindow: true }, resolve);
    });

    if (tabs.length > 0) {
      urlListEl.value = "";
      tabs.forEach(tab => {
        const tabUrl = tab.url;
        if (isUrlValid(tabUrl)) {
          urlListEl.value += tabUrl + "\n";
        }
      });
      urlListEl.value = urlListEl.value.replace(/(?:(?:\r\n|\r|\n)\s*){2}/gm, "");
      urlListEl.select();
    }
  } catch (error) {
    console.error("Error getting tab URLs:", error);
    displayUrlAlert("获取标签页 URL 时出错", "danger");
  }
};

/**
 * Starts the URL opening process
 */
const startUrlOpeningProcess = () => {
  // Reset state
  state.timeouts = [];
  state.openedUrlsCount = 0;
  state.actualUrlsCount = 0;
  hideUrlResults();

  // Get URLs and settings
  const urls = urlListEl.value.split("\n").filter(url => url.trim() !== "" && isUrlValid(url));
  if (urls.length === 0) {
    displayUrlAlert("请输入有效的 URL", "danger");
    return;
  }

  // Update UI
  urlListEl.classList.remove("is-invalid");
  urlProgressBarEl.style.display = "block";
  disableUrlControls();
  showStopButton();

  // Set up and start opening URLs
  state.actualUrlsCount = urls.length;
  const delay = parseInt(openDelayRangeEl.value) * 1000;
  const focus = focusTabsEl.classList.contains("switch-active");

  openUrlsSequentially(urls, delay, focus);
};

/**
 * Opens URLs sequentially with delay
 * @param {string[]} urls - Array of URLs to open
 * @param {number} delay - Delay between opening URLs (ms)
 * @param {boolean} focus - Whether to focus new tabs
 */
const openUrlsSequentially = async (urls, delay, focus) => {
  for (let index = 0; index < urls.length; index++) {
    const url = urls[index];
    const timeoutId = setTimeout(async () => {
      try {
        await openUrlInNewTab(url, focus);
        state.openedUrlsCount++;
        updateUrlProgressBar(index + 1, urls.length);

        if (index === urls.length - 1) {
          finishUrlOpeningProcess(urls.length);
        }
      } catch (error) {
        console.error(`Error opening URL: ${url}`, error);
        state.openedUrlsCount++;
        updateUrlProgressBar(index + 1, urls.length);
        if (index === urls.length - 1) {
          finishUrlOpeningProcess(urls.length);
        }
      }
    }, index * delay);
    state.timeouts.push(timeoutId);
  }
};

/**
 * Updates the URL progress bar
 * @param {number} current - Current progress
 * @param {number} total - Total URLs
 */
const updateUrlProgressBar = (current, total) => {
  if (!urlProgressBarEl) return;
  const progressValue = urlProgressBarEl.querySelector(".pf-progress-value");
  if (progressValue) {
    const percentage = Math.round((current / total) * 100);
    progressValue.style.width = `${percentage}%`;
  }
};

/**
 * Finishes the URL opening process
 * @param {number} totalUrls - Total number of URLs
 */
const finishUrlOpeningProcess = (totalUrls) => {
  enableUrlControls();
  hideStopButton();
  urlProgressBarEl.style.display = "none";
  showUrlResults(state.openedUrlsCount, totalUrls);
};

/**
 * Stops the URL opening process
 */
const stopUrlOpeningProcess = () => {
  state.timeouts.forEach(timeoutId => clearTimeout(timeoutId));
  state.timeouts = [];
  enableUrlControls();
  hideStopButton();
  urlProgressBarEl.style.display = "none";
  showUrlResults(state.openedUrlsCount, state.actualUrlsCount);
};

/**
 * Disables URL controls during opening process
 */
const disableUrlControls = () => {
  if (focusTabsEl) focusTabsEl.style.pointerEvents = "none";
  if (urlListEl) urlListEl.disabled = true;
  if (openDelayRangeEl) openDelayRangeEl.disabled = true;
  if (openUrlListBtn) openUrlListBtn.disabled = true;
  if (getTabUrlListBtn) getTabUrlListBtn.disabled = true;
  if (clearUrlListBtn) clearUrlListBtn.disabled = true;
  if (urlListComboEl) urlListComboEl.disabled = true;
  if (loadListBtn) loadListBtn.disabled = true;
  if (editListBtn) editListBtn.disabled = true;
  if (updateListBtn) updateListBtn.disabled = true;
  if (deleteListBtn) deleteListBtn.disabled = true;
  if (listNameEl) listNameEl.disabled = true;
  if (saveListBtn) saveListBtn.disabled = true;
};

/**
 * Enables URL controls
 */
const enableUrlControls = () => {
  if (focusTabsEl) focusTabsEl.style.pointerEvents = "auto";
  if (urlListEl) urlListEl.disabled = false;
  if (openDelayRangeEl) openDelayRangeEl.disabled = false;
  if (openUrlListBtn) openUrlListBtn.disabled = false;
  if (getTabUrlListBtn) getTabUrlListBtn.disabled = false;
  if (clearUrlListBtn) clearUrlListBtn.disabled = false;
  if (urlListComboEl) urlListComboEl.disabled = false;
  if (loadListBtn) loadListBtn.disabled = false;
  if (editListBtn) editListBtn.disabled = false;
  if (updateListBtn) updateListBtn.disabled = false;
  if (deleteListBtn) deleteListBtn.disabled = false;
  if (listNameEl) listNameEl.disabled = false;
  if (saveListBtn) saveListBtn.disabled = false;
};

/**
 * Shows the stop button and hides the open button
 */
const showStopButton = () => {
  if (stopUrlListBtn) stopUrlListBtn.classList.remove("pf-hidden");
  if (openUrlListBtn) openUrlListBtn.classList.add("pf-hidden");
};

/**
 * Hides the stop button and shows the open button
 */
const hideStopButton = () => {
  if (stopUrlListBtn) stopUrlListBtn.classList.add("pf-hidden");
  if (openUrlListBtn) openUrlListBtn.classList.remove("pf-hidden");
};

/**
 * Displays an alert for URL operations
 * @param {string} message - Alert message
 * @param {string} type - Alert type (success, danger, warning)
 */
const displayUrlAlert = (message, type) => {
  if (!urlOpenStatusContainerEl) return;
  urlOpenStatusContainerEl.innerHTML = `
    <div class="pf-alert pf-alert-${type}">
      <div>${message}</div>
      <button class="pf-alert-close" onclick="this.parentElement.remove()">&times;</button>
    </div>
  `;
};

/**
 * Shows URL opening results
 * @param {number} openedUrlsCount - Number of URLs opened
 * @param {number} actualUrlsCount - Total number of URLs
 */
const showUrlResults = (openedUrlsCount, actualUrlsCount) => {
  if (openedUrlsCount === actualUrlsCount) {
    displayUrlAlert(`成功打开 ${actualUrlsCount} 个 URL`, "success");
  } else {
    displayUrlAlert(`仅打开 ${openedUrlsCount} 个 URL，共 ${actualUrlsCount} 个`, "warning");
  }
};

/**
 * Hides URL results
 */
const hideUrlResults = () => {
  if (urlOpenStatusContainerEl) {
    urlOpenStatusContainerEl.innerHTML = "";
  }
};

/**
 * Loads URL lists from storage
 */
const loadUrlListsFromStorage = () => {
  chrome.storage.sync.get("FrontReconListOfUrls", (data) => {
    if (data.FrontReconListOfUrls && data.FrontReconListOfUrls.lists) {
      try {
        const lists = JSON.parse(data.FrontReconListOfUrls.lists);
        if (urlListComboEl) {
          // Clear existing options except the first one
          while (urlListComboEl.options.length > 1) {
            urlListComboEl.remove(1);
          }
          // Add lists to combo box
          for (const listName in lists) {
            if (lists.hasOwnProperty(listName)) {
              const option = document.createElement("option");
              option.textContent = listName;
              option.value = listName.replace(" ", "");
              urlListComboEl.appendChild(option);
            }
          }
        }
      } catch (error) {
        console.error("Error parsing URL lists:", error);
      }
    }
  });
};

/**
 * Saves URLs as a named list
 */
const saveUrlsAsList = () => {
  const listName = listNameEl.value.trim();
  if (!listName) {
    displayUrlListAlert("请输入列表名称", "danger");
    return;
  }

  chrome.storage.sync.get("FrontReconListOfUrls", (data) => {
    let lists = data.FrontReconListOfUrls && data.FrontReconListOfUrls.lists ? JSON.parse(data.FrontReconListOfUrls.lists) : {};

    if (lists[listName]) {
      displayUrlListAlert("列表名称已存在，请输入唯一的列表名称", "danger");
      return;
    }

    const urls = urlListEl.value.split("\n").filter(url => url.trim() !== "" && isUrlValid(url));
    if (urls.length === 0) {
      displayUrlListAlert("请输入有效的 URL", "danger");
      return;
    }

    lists[listName] = urls;

    chrome.storage.sync.set({ FrontReconListOfUrls: { lists: JSON.stringify(lists) } }, () => {
      const option = document.createElement("option");
      option.textContent = listName;
      option.value = listName.replace(" ", "");
      if (urlListComboEl) urlListComboEl.appendChild(option);
      listNameEl.value = "";
      displayUrlListAlert("列表创建成功", "success");
    });
  });
};

/**
 * Loads the selected URL list
 */
const loadSelectedUrlList = () => {
  if (!urlListComboEl || urlListComboEl.selectedIndex === 0) {
    displayUrlListAlert("请选择要加载的列表", "danger");
    return;
  }

  const selectedListName = urlListComboEl.options[urlListComboEl.selectedIndex].text;

  chrome.storage.sync.get("FrontReconListOfUrls", (data) => {
    if (data.FrontReconListOfUrls && data.FrontReconListOfUrls.lists) {
      try {
        const lists = JSON.parse(data.FrontReconListOfUrls.lists);
        if (lists[selectedListName]) {
          urlListEl.value = lists[selectedListName].join("\n");
          displayUrlListAlert("列表加载成功", "success");
        } else {
          displayUrlListAlert("列表不存在", "danger");
        }
      } catch (error) {
        console.error("Error parsing URL lists:", error);
        displayUrlListAlert("加载列表时出错", "danger");
      }
    }
  });
};

/**
 * Deletes the selected URL list
 */
const deleteSelectedUrlList = () => {
  if (!urlListComboEl || urlListComboEl.selectedIndex === 0) {
    displayUrlListAlert("请选择要删除的列表", "danger");
    return;
  }

  if (confirm("确定要删除此列表吗？")) {
    const selectedListName = urlListComboEl.options[urlListComboEl.selectedIndex].text;
    urlListComboEl.remove(urlListComboEl.selectedIndex);

    chrome.storage.sync.get("FrontReconListOfUrls", (data) => {
      if (data.FrontReconListOfUrls && data.FrontReconListOfUrls.lists) {
        try {
          const lists = JSON.parse(data.FrontReconListOfUrls.lists);
          delete lists[selectedListName];

          chrome.storage.sync.set({ FrontReconListOfUrls: { lists: JSON.stringify(lists) } }, () => {
            urlListEl.value = "";
            displayUrlListAlert("列表删除成功", "success");
          });
        } catch (error) {
          console.error("Error parsing URL lists:", error);
          displayUrlListAlert("删除列表时出错", "danger");
        }
      }
    });
  }
};

/**
 * Edits the selected URL list
 */
const editSelectedUrlList = () => {
  if (!urlListComboEl || urlListComboEl.selectedIndex === 0) {
    displayUrlListAlert("请选择要编辑的列表", "danger");
    return;
  }

  if (confirm("确定要编辑此列表吗？")) {
    loadSelectedUrlList();
    if (editListBtn) editListBtn.classList.add("pf-hidden");
    if (updateListBtn) updateListBtn.classList.remove("pf-hidden");
    if (saveListBtn) saveListBtn.disabled = true;
    if (urlListComboEl) urlListComboEl.disabled = true;
    if (loadListBtn) loadListBtn.disabled = true;
    if (deleteListBtn) deleteListBtn.disabled = true;
    if (listNameEl) listNameEl.disabled = true;
  }
};

/**
 * Updates the selected URL list
 */
const updateSelectedUrlList = () => {
  if (!urlListComboEl || urlListComboEl.selectedIndex === 0) {
    displayUrlListAlert("请选择要更新的列表", "danger");
    return;
  }

  const selectedListName = urlListComboEl.options[urlListComboEl.selectedIndex].text;
  const urls = urlListEl.value.split("\n").filter(url => url.trim() !== "" && isUrlValid(url));

  if (urls.length === 0) {
    displayUrlListAlert("请输入有效的 URL", "danger");
    return;
  }

  chrome.storage.sync.get("FrontReconListOfUrls", (data) => {
    if (data.FrontReconListOfUrls && data.FrontReconListOfUrls.lists) {
      try {
        const lists = JSON.parse(data.FrontReconListOfUrls.lists);
        lists[selectedListName] = urls;

        chrome.storage.sync.set({ FrontReconListOfUrls: { lists: JSON.stringify(lists) } }, () => {
          displayUrlListAlert("列表更新成功", "success");
          if (editListBtn) editListBtn.classList.remove("pf-hidden");
          if (updateListBtn) updateListBtn.classList.add("pf-hidden");
          if (saveListBtn) saveListBtn.disabled = false;
          if (urlListComboEl) urlListComboEl.disabled = false;
          if (loadListBtn) loadListBtn.disabled = false;
          if (deleteListBtn) deleteListBtn.disabled = false;
          if (listNameEl) listNameEl.disabled = false;
        });
      } catch (error) {
        console.error("Error parsing URL lists:", error);
        displayUrlListAlert("更新列表时出错", "danger");
      }
    }
  });
};

/**
 * Displays an alert for URL list operations
 * @param {string} message - Alert message
 * @param {string} type - Alert type (success, danger, warning)
 */
const displayUrlListAlert = (message, type) => {
  if (!urlListStatusContainerEl) return;
  urlListStatusContainerEl.innerHTML = `
    <div class="pf-alert pf-alert-${type}">
      <div>${message}</div>
      <button class="pf-alert-close" onclick="this.parentElement.remove()">&times;</button>
    </div>
  `;
};

const renderSqlResponse = (data) => {
  if (!sqlRespMetaEl || !sqlRespHeadersEl || !sqlRespBodyEl) return;
  if (!data) {
    safeSetText(sqlRespMetaEl, "");
    safeSetText(sqlRespHeadersEl, "");
    safeSetText(sqlRespBodyEl, "");
    return;
  }
  safeSetText(sqlRespMetaEl, data.meta || "");
  safeSetText(sqlRespHeadersEl, data.headers || "");
  safeSetText(sqlRespBodyEl, data.body || "");
};

const sqlFetchViaTab = (tabId, req) =>
  new Promise((resolve) =>
    chrome.scripting.executeScript(
      {
        target: { tabId },
        func: async (r) => {
          const start = Date.now();
          try {
            const headers = {};
            let userAgent = null;
            
            (r.headers || []).forEach((kv) => {
              if (!kv || kv.length < 2) return;
              const headerName = String(kv[0]).toLowerCase();
              if (headerName === 'user-agent') {
                userAgent = String(kv[1]);
              } else {
                headers[String(kv[0])] = String(kv[1]);
              }
            });
            
            // 检查是否需要设置User-Agent规则
            if (userAgent && typeof chrome !== 'undefined' && chrome.declarativeNetRequest) {
              try {
                // 生成规则ID
                const generateRuleId = () => {
                  return Math.floor(Math.random() * 100000) + 100000;
                };
                
                const ruleId = generateRuleId();
                const url = new URL(String(r.url));
                const urlFilter = `||${url.hostname}^`;
                
                // 创建规则
                const rule = {
                  id: ruleId,
                  priority: 1,
                  action: {
                    type: 'modifyHeaders',
                    requestHeaders: [{
                      header: 'User-Agent',
                      operation: 'set',
                      value: userAgent
                    }]
                  },
                  condition: {
                    urlFilter: urlFilter,
                    resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest', 'fetch']
                  }
                };
                
                // 添加规则
                await new Promise((resolve) => {
                  chrome.declarativeNetRequest.updateDynamicRules(
                    { removeRuleIds: [], addRules: [rule] },
                    () => resolve()
                  );
                });
                
                // 发送请求
                const resp = await fetch(String(r.url), {
                  method: String(r.method || "GET"),
                  headers,
                  body: r.body === undefined ? undefined : String(r.body),
                  credentials: "include"
                });
                
                // 清除规则
                await new Promise((resolve) => {
                  chrome.declarativeNetRequest.updateDynamicRules(
                    { removeRuleIds: [ruleId], addRules: [] },
                    () => resolve()
                  );
                });
                
                const ms = Date.now() - start;
                const h = [];
                resp.headers.forEach((v, k) => h.push(`${k}: ${v}`));
                const text = await resp.text();
                const limit = 220000;
                const bodyOut = text.length > limit ? (text.slice(0, limit) + `\n\n...[TRUNCATED ${text.length - limit} chars]`) : text;
                return {
                  ok: true,
                  meta: `${resp.status} ${resp.statusText}  |  ${ms}ms`,
                  headers: h.join("\n"),
                  body: bodyOut
                };
              } catch (uaError) {
                // 如果设置规则失败，尝试直接发送请求
                const resp = await fetch(String(r.url), {
                  method: String(r.method || "GET"),
                  headers,
                  body: r.body === undefined ? undefined : String(r.body),
                  credentials: "include"
                });
                const ms = Date.now() - start;
                const h = [];
                resp.headers.forEach((v, k) => h.push(`${k}: ${v}`));
                const text = await resp.text();
                const limit = 220000;
                const bodyOut = text.length > limit ? (text.slice(0, limit) + `\n\n...[TRUNCATED ${text.length - limit} chars]`) : text;
                return {
                  ok: true,
                  meta: `${resp.status} ${resp.statusText}  |  ${ms}ms`,
                  headers: h.join("\n"),
                  body: bodyOut
                };
              }
            } else {
              // 直接发送请求
              const resp = await fetch(String(r.url), {
                method: String(r.method || "GET"),
                headers,
                body: r.body === undefined ? undefined : String(r.body),
                credentials: "include"
              });
              const ms = Date.now() - start;
              const h = [];
              resp.headers.forEach((v, k) => h.push(`${k}: ${v}`));
              const text = await resp.text();
              const limit = 220000;
              const bodyOut = text.length > limit ? (text.slice(0, limit) + `\n\n...[TRUNCATED ${text.length - limit} chars]`) : text;
              return {
                ok: true,
                meta: `${resp.status} ${resp.statusText}  |  ${ms}ms`,
                headers: h.join("\n"),
                body: bodyOut
              };
            }
          } catch (e) {
            const ms = Date.now() - start;
            return { ok: false, error: String(e && e.message ? e.message : e), meta: `请求失败 | ${ms}ms` };
          }
        },
        args: [req]
      },
      (res) => {
        const out = res && res[0] && res[0].result ? res[0].result : null;
        resolve(out);
      }
    )
  );

const sqlFetchViaBackground = (req) =>
  new Promise((resolve) =>
    chrome.runtime.sendMessage(
      { type: "SQL_FETCH", url: req.url, method: req.method, headers: req.headersObj || {}, body: req.body },
      (res) => resolve(res || null)
    )
  );

const jsPatternFromUrl = (rawUrl) => {
  const u = new URL(String(rawUrl || ""));
  return `${u.protocol}//${u.hostname}/*`;
};

const getJsSetting = (primaryUrl) =>
  new Promise((resolve) => {
    if (!chrome.contentSettings || !chrome.contentSettings.javascript) return resolve(null);
    chrome.contentSettings.javascript.get({ primaryUrl }, (details) => {
      resolve(details && details.setting ? details.setting : null);
    });
  });

const setJsSetting = (primaryUrl, setting) =>
  new Promise((resolve) => {
    if (!chrome.contentSettings || !chrome.contentSettings.javascript) return resolve(false);
    const primaryPattern = jsPatternFromUrl(primaryUrl);
    chrome.contentSettings.javascript.set({ primaryPattern, setting, scope: "regular" }, () => {
      resolve(!chrome.runtime.lastError);
    });
  });

const uaRuleIdForHost = (host) => {
  const s = String(host || "");
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h) + s.charCodeAt(i);
  const n = Math.abs(h) % 80000;
  return 120000 + n;
};

const uaRuleForHost = (host, ua) => {
  const id = uaRuleIdForHost(host);
  const urlFilter = `||${host}^`;
  return {
    id,
    priority: 1,
    action: {
      type: "modifyHeaders",
      requestHeaders: [
        { header: "User-Agent", operation: "set", value: String(ua || "") }
      ]
    },
    condition: {
      urlFilter,
      resourceTypes: [
        "main_frame",
        "sub_frame",
        "xmlhttprequest",
        "script",
        "stylesheet",
        "image",
        "font",
        "object",
        "other"
      ]
    }
  };
};

const getUaRuleForActiveSite = async () => {
  const tab = await getActiveTab();
  const url = tab.url || "";
  const u = new URL(url);
  const host = u.hostname;
  const id = uaRuleIdForHost(host);
  const rules = await new Promise((resolve) => {
    if (!chrome.declarativeNetRequest) return resolve([]);
    chrome.declarativeNetRequest.getDynamicRules((rs) => resolve(rs || []));
  });
  const rule = rules.find((r) => r && r.id === id) || null;
  return { tab, host, rule };
};

const setUaForActiveSite = async (ua) => {
  const { host } = await getUaRuleForActiveSite();
  const id = uaRuleIdForHost(host);
  const rule = uaRuleForHost(host, ua);
  return await new Promise((resolve) => {
    if (!chrome.declarativeNetRequest) return resolve(false);
    chrome.declarativeNetRequest.updateDynamicRules(
      { removeRuleIds: [id], addRules: [rule] },
      () => resolve(!chrome.runtime.lastError)
    );
  });
};

const clearUaForActiveSite = async () => {
  const { host } = await getUaRuleForActiveSite();
  const id = uaRuleIdForHost(host);
  return await new Promise((resolve) => {
    if (!chrome.declarativeNetRequest) return resolve(false);
    chrome.declarativeNetRequest.updateDynamicRules(
      { removeRuleIds: [id], addRules: [] },
      () => resolve(!chrome.runtime.lastError)
    );
  });
};
const cookieRuleIdForHost = (host) => {
  const s = String(host || "");
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h) + s.charCodeAt(i);
  const n = Math.abs(h) % 80000;
  return 200000 + n;
};

const cookieRuleForHost = (host, cookie) => {
  const id = cookieRuleIdForHost(host);
  const urlFilter = `||${host}^`;
  return {
    id,
    priority: 1,
    action: {
      type: "modifyHeaders",
      requestHeaders: [
        { header: "Cookie", operation: "set", value: String(cookie || "") }
      ]
    },
    condition: {
      urlFilter,
      resourceTypes: [
        "main_frame",
        "sub_frame",
        "xmlhttprequest",
        "script",
        "stylesheet",
        "image",
        "font",
        "object",
        "other"
      ]
    }
  };
};

const getCookieRuleForActiveSite = async () => {
  const tab = await getActiveTab();
  const url = tab.url || "";
  const u = new URL(url);
  const host = u.hostname;
  const id = cookieRuleIdForHost(host);
  const rules = await new Promise((resolve) => {
    if (!chrome.declarativeNetRequest) return resolve([]);
    chrome.declarativeNetRequest.getDynamicRules((rs) => resolve(rs || []));
  });
  const rule = rules.find((r) => r && r.id === id) || null;
  return { tab, host, rule };
};

const setCookieForActiveSite = async (cookie) => {
  const { host } = await getCookieRuleForActiveSite();
  const id = cookieRuleIdForHost(host);
  const rule = cookieRuleForHost(host, cookie);
  return await new Promise((resolve) => {
    if (!chrome.declarativeNetRequest) return resolve(false);
    chrome.declarativeNetRequest.updateDynamicRules(
      { removeRuleIds: [id], addRules: [rule] },
      () => resolve(!chrome.runtime.lastError)
    );
  });
};

const clearCookieForActiveSite = async () => {
  const { host } = await getCookieRuleForActiveSite();
  const id = cookieRuleIdForHost(host);
  return await new Promise((resolve) => {
    if (!chrome.declarativeNetRequest) return resolve(false);
    chrome.declarativeNetRequest.updateDynamicRules(
      { removeRuleIds: [id], addRules: [] },
      () => resolve(!chrome.runtime.lastError)
    );
  });
};
const headerRuleIdForHost = (host, header, base) => {
  const s = `${String(host || "")}|${String(header || "")}`;
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h) + s.charCodeAt(i);
  const n = Math.abs(h) % 80000;
  return base + n;
};

const headerRuleForHost = (host, header, value, base) => {
  const id = headerRuleIdForHost(host, header, base);
  const urlFilter = `||${host}^`;
  return {
    id,
    priority: 1,
    action: {
      type: "modifyHeaders",
      requestHeaders: [
        { header: String(header || ""), operation: "set", value: String(value || "") }
      ]
    },
    condition: {
      urlFilter,
      resourceTypes: [
        "main_frame",
        "sub_frame",
        "xmlhttprequest",
        "script",
        "stylesheet",
        "image",
        "font",
        "object",
        "other"
      ]
    }
  };
};

const getHeaderRuleForActiveSite = async (header, base) => {
  const tab = await getActiveTab();
  const url = tab.url || "";
  const u = new URL(url);
  const host = u.hostname;
  const id = headerRuleIdForHost(host, header, base);
  const rules = await new Promise((resolve) => {
    if (!chrome.declarativeNetRequest) return resolve([]);
    chrome.declarativeNetRequest.getDynamicRules((rs) => resolve(rs || []));
  });
  const rule = rules.find((r) => r && r.id === id) || null;
  return { tab, host, rule };
};

const setHeaderForActiveSite = async (header, value, base) => {
  const { host } = await getHeaderRuleForActiveSite(header, base);
  const id = headerRuleIdForHost(host, header, base);
  const rule = headerRuleForHost(host, header, value, base);
  return await new Promise((resolve) => {
    if (!chrome.declarativeNetRequest) return resolve(false);
    chrome.declarativeNetRequest.updateDynamicRules(
      { removeRuleIds: [id], addRules: [rule] },
      () => resolve(!chrome.runtime.lastError)
    );
  });
};

const clearHeaderForActiveSite = async (header, base) => {
  const { host } = await getHeaderRuleForActiveSite(header, base);
  const id = headerRuleIdForHost(host, header, base);
  return await new Promise((resolve) => {
    if (!chrome.declarativeNetRequest) return resolve(false);
    chrome.declarativeNetRequest.updateDynamicRules(
      { removeRuleIds: [id], addRules: [] },
      () => resolve(!chrome.runtime.lastError)
    );
  });
};
const injectContent = (tabId) =>
  new Promise((resolve, reject) =>
    chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ["content.js"] }, (res) =>
      chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res)
    )
  );

const fuzzAllFrames = (tabId) =>
  new Promise((resolve, reject) =>
    chrome.scripting.executeScript(
      {
        target: { tabId, allFrames: true },
        func: () => {
          const els = Array.from(document.querySelectorAll('input, textarea, select, [contenteditable]')).filter((el) => {
            if (el.matches('[contenteditable]')) return el.isContentEditable;
            return true;
          });
          const payload = '<img src=x onerror=alert(document.domain)>';
          els.forEach((el, idx) => {
            const tag = (el.tagName || "").toLowerCase();
            if (tag === "input" || tag === "textarea") {
              try { el.value = payload; } catch (_) {}
            } else if (tag === "select") {
              const opt = new Option(payload, payload);
              opt.dataset ? (opt.dataset.ispTempOption = "1") : (opt.setAttribute("data-ispTempOption","1"));
              el.appendChild(opt);
              try { el.value = payload; } catch (_) {}
            } else if (el.isContentEditable) {
              try { el.textContent = payload; } catch (_) {}
            }
            try { el.dispatchEvent(new Event("input", { bubbles: true })); } catch (_) {}
            try { el.dispatchEvent(new Event("change", { bubbles: true })); } catch (_) {}
          });
          return true;
        }
      },
      (res) => (chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res))
    )
  );
const highlightIndex = (tabId, frameId, index) =>
  new Promise((resolve, reject) =>
    chrome.tabs.sendMessage(tabId, { type: "HIGHLIGHT", index }, { frameId }, (res) =>
      chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res)
    )
  );

const setScanning = (on) => {
  state.scanning = !!on;
  if (ledEl) ledEl.style.opacity = on ? "1" : "0.6";
  if (statusTextEl) statusTextEl.textContent = on ? "扫描中" : "就绪";
};

const scanSecurity = async (tabId, tabUrl) => {
  try {
    // 1. HttpOnly Cookies via chrome.cookies
    const cookies = await new Promise(resolve => {
      if (chrome.cookies) {
        chrome.cookies.getAll({ url: tabUrl }, (cookies) => resolve(cookies || []));
      } else {
        resolve([]);
      }
    });
    const httpOnly = cookies.filter(c => c.httpOnly).map(c => c.name);

    // 2. In-page security info
    const pageInfo = await new Promise(resolve => {
       chrome.scripting.executeScript({
         target: { tabId },
         func: () => window.__XMCVE_collectSecurityInfo ? window.__XMCVE_collectSecurityInfo() : null
       }, (res) => resolve(res && res[0] && res[0].result ? res[0].result : null));
    });

    return {
      httpOnly,
      ...(pageInfo || {})
    };
  } catch (e) {
    console.error(e);
    return null;
  }
};

const renderSecurity = (data) => {
  securityContainer.innerHTML = "";
  if (!data) return;

  const { httpOnly, storageKeys, csrf, hasPostMessage, critical } = data;
  const hasData = (httpOnly && httpOnly.length) || (storageKeys && storageKeys.length) || (csrf && csrf.length) || hasPostMessage || (critical && critical.length);
  
  if (!hasData) {
    // securityContainer.innerHTML = `<div class="pf-empty">未发现明显安全风险点</div>`;
    return;
  }

  // Helper to create card
  const createCard = (title, items, isFull = false) => {
    const card = document.createElement("div");
    card.className = `pf-sec-card ${isFull ? 'pf-sec-card-full' : ''}`;
    
    const t = document.createElement("div");
    t.className = "pf-sec-title";
    t.textContent = title;
    
    card.appendChild(t);

    if (Array.isArray(items)) {
       const list = document.createElement("div");
       list.className = "pf-sec-list";
       items.forEach(item => {
         const row = document.createElement("div");
         row.className = "pf-sec-item";
         if (typeof item === 'string') {
             row.innerHTML = `<span class="pf-sec-item-key">${item}</span>`;
         } else {
             row.innerHTML = `<span class="pf-sec-item-key">${item.key || item.name || item.type}</span><span class="pf-sec-item-val" title="${item.value || item.url}">${item.value || item.url}</span>`;
         }
         list.appendChild(row);
       });
       card.appendChild(list);
    } else {
       const content = document.createElement("div");
       content.className = "pf-sec-content";
       content.textContent = items;
       card.appendChild(content);
    }
    return card;
  };

  // HttpOnly Cookies
  if (httpOnly && httpOnly.length) {
    securityContainer.appendChild(createCard("HttpOnly Cookies", httpOnly));
  }

  // Storage Tokens
  if (storageKeys && storageKeys.length) {
    securityContainer.appendChild(createCard("Storage Tokens", storageKeys));
  }

  // CSRF
  if (csrf && csrf.length) {
    securityContainer.appendChild(createCard("CSRF Tokens", csrf));
  }

  // PostMessage
  if (hasPostMessage) {
    const card = document.createElement("div");
    card.className = "pf-sec-card";
    card.innerHTML = `
      <div class="pf-sec-title">PostMessage</div>
      <div class="pf-sec-content pf-text-warning">Detected Listener</div>
    `;
    securityContainer.appendChild(card);
  }

  // Critical Interfaces
  if (critical && critical.length) {
    securityContainer.appendChild(createCard("关键接口 / 敏感操作", critical, true));
  }
};

const scanForms = (tabId) =>
  new Promise((resolve, reject) =>
    chrome.scripting.executeScript(
      {
        target: { tabId, allFrames: true },
        func: () => {
           if (window.__XMCVE_collectForms) {
             return window.__XMCVE_collectForms();
           }
           return [];
        }
      },
      (res) => (chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res))
    )
  );

const unhideIndex = (tabId, frameId, index) =>
  new Promise((resolve, reject) =>
    chrome.tabs.sendMessage(tabId, { type: "UNHIDE", index }, { frameId }, (res) =>
      chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res)
    )
  );

const updateValueIndex = (tabId, frameId, index, value) =>
  new Promise((resolve, reject) =>
    chrome.tabs.sendMessage(tabId, { type: "UPDATE_VAL", index, value }, { frameId }, (res) =>
      chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res)
    )
  );

const escapeHtmlForRender = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const renderForms = (forms, frameId) => {
  if (!forms || !forms.length) return;
  forms.forEach(form => {
    const card = document.createElement("div");
    card.className = "pf-form-card";

    // Meta
    const meta = document.createElement("div");
    meta.className = "pf-form-meta";
    meta.innerHTML = `
      <div class="pf-badge">Frame #${frameId}</div>
      <div class="pf-badge pf-badge-accent">${(form.method || "GET").toUpperCase()}</div>
      <div class="pf-form-action">${form.action}</div>
      <div class="pf-badge">${form.enctype || "application/x-www-form-urlencoded"}</div>
    `;

    // Table
    const table = document.createElement("table");
    table.className = "pf-form-table";
    const tbody = form.fields.map(f => `
      <tr class="${f.hidden ? 'pf-row-hidden' : ''}">
        <td>
          ${f.name}
          ${f.hidden ? '<span class="pf-badge pf-badge-accent pf-badge-hidden">Hidden</span>' : ''}
        </td>
        <td>
          <input type="text" class="pf-input-mini pf-code-input" data-idx="${f.index}" value="${escapeHtmlForRender(f.value)}">
        </td>
        <td>${f.type}</td>
        <td>
           <button class="pf-btn-mini" data-action="locate" data-idx="${f.index}" ${f.index === -1 ? 'disabled' : ''}>定位</button>
           ${f.hidden ? `<button class="pf-btn-mini" data-action="unhide" data-idx="${f.index}" ${f.index === -1 ? 'disabled' : ''}>取消隐藏</button>` : ''}
        </td>
      </tr>
    `).join("");
    table.innerHTML = `
      <thead><tr><th>Field</th><th>Value</th><th>Type</th><th>Action</th></tr></thead>
      <tbody>${tbody}</tbody>
    `;

    // Bind events for buttons
    table.querySelectorAll('.pf-btn-mini').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.dataset.idx, 10);
        const action = btn.dataset.action;
        if (idx >= 0) {
           if (action === 'locate') {
             highlightIndex(state.tabId, frameId, idx).catch(() => {});
           } else if (action === 'unhide') {
             unhideIndex(state.tabId, frameId, idx).then((res) => {
               if (res && res.ok) {
                 btn.remove(); // 移除“取消隐藏”按钮，表示操作成功
               }
             }).catch(() => {});
           }
        }
      });
    });

    // Bind events for inputs
    table.querySelectorAll('.pf-code-input').forEach(input => {
      input.addEventListener('change', () => {
        const idx = parseInt(input.dataset.idx, 10);
        const val = input.value;
        if (idx >= 0) {
          updateValueIndex(state.tabId, frameId, idx, val).catch(() => {});
        }
      });
    });

    card.appendChild(meta);
    card.appendChild(table);
    formsContainer.appendChild(card);
  });
};

const refresh = async () => {
  try {
    setScanning(true);
    formsContainer.innerHTML = "";
    
    const tab = await getActiveTab();
    state.tabId = tab.id;
    await injectContent(state.tabId);
    
    const res = await scanForms(state.tabId);
    let found = false;
    
    for (const entry of res || []) {
      const frameId = entry.frameId;
      const forms = entry.result || [];
      if (forms && forms.length > 0) {
        found = true;
        renderForms(forms, frameId);
      }
    }
    
    if (!found) {
      formsContainer.innerHTML = `<div class="pf-empty">未检测到表单或输入点</div>`;
    }
  } catch (e) {
    formsContainer.innerHTML = `<div class="pf-empty">分析出错: ${e.message}</div>`;
  } finally {
    setScanning(false);
  }
};

document.addEventListener("DOMContentLoaded", () => {
  const refreshEl = q("#refresh");
  if (refreshEl) refreshEl.addEventListener("click", refresh);
  refresh();
  const tabs = {
    xss: q("#tab-xss"),
    sql: q("#tab-sql"),
    info: q("#tab-info"),
    "info-extract": q("#tab-info-extract"),
    security: q("#tab-security"),
    cloud: q("#tab-cloud"),
    shodan: q("#tab-shodan"),
    tools: q("#tab-tools"),
    team: q("#tab-team"),
  };
  const mods = {
    xss: q("#mod-xss"),
    sql: q("#mod-sql"),
    info: q("#mod-info"),
    "info-extract": q("#mod-info-extract"),
    security: q("#mod-security"),
    cloud: q("#mod-cloud"),
    shodan: q("#mod-shodan"),
    tools: q("#mod-tools"),
    team: q("#mod-team"),
  };
  const allTabs = Object.values(tabs);
  const allMods = Object.values(mods);
  const switchTab = (name) => {
    allTabs.forEach((b) => b.classList.remove("pf-tab-active"));
    allMods.forEach((m) => m.classList.add("pf-hidden"));
    const btn = tabs[name];
    const mod = mods[name];
    if (btn) btn.classList.add("pf-tab-active");
    if (mod) mod.classList.remove("pf-hidden");
    localStorage.setItem("lastModule", name);
  };
  const refreshJsUi = async () => {
    try {
      const tab = await getActiveTab();
      const url = tab.url || "";
      if (jsSiteEl) {
        try {
          const u = new URL(url);
          jsSiteEl.value = `${u.protocol}//${u.hostname}`;
        } catch (_) {
          jsSiteEl.value = url;
        }
      }
      const setting = await getJsSetting(url);
      if (jsStateEl) jsStateEl.value = setting || "";
    } catch (_) {
      if (jsSiteEl) jsSiteEl.value = "";
      if (jsStateEl) jsStateEl.value = "";
    }
  };
  const refreshUaUi = async () => {
    try {
      const { tab, host, rule } = await getUaRuleForActiveSite();
      if (uaSiteEl) uaSiteEl.value = host || "";
      if (uaInputEl) {
        const v =
          rule &&
          rule.action &&
          Array.isArray(rule.action.requestHeaders) &&
          rule.action.requestHeaders[0] &&
          rule.action.requestHeaders[0].value
            ? String(rule.action.requestHeaders[0].value)
            : "";
        if (!uaInputEl.value) uaInputEl.value = v;
      }
    } catch (_) {
      if (uaSiteEl) uaSiteEl.value = "";
    }
  };
  const refreshCookieUi = async () => {
    try {
      const { host, rule } = await getCookieRuleForActiveSite();
      if (cookieSiteEl) cookieSiteEl.value = host || "";
      if (cookieInputEl) {
        const v =
          rule &&
          rule.action &&
          Array.isArray(rule.action.requestHeaders) &&
          rule.action.requestHeaders[0] &&
          rule.action.requestHeaders[0].value
            ? String(rule.action.requestHeaders[0].value)
            : "";
        if (!cookieInputEl.value) cookieInputEl.value = v;
      }
    } catch (_) {
      if (cookieSiteEl) cookieSiteEl.value = "";
    }
  };
  const refreshHeaderUi = async () => {
    try {
      const xffRule = await getHeaderRuleForActiveSite("X-Forwarded-For", 210000);
      const refererRule = await getHeaderRuleForActiveSite("Referer", 210000);
      const clientIpRule = await getHeaderRuleForActiveSite("Client-IP", 210000);
      const xRealIpRule = await getHeaderRuleForActiveSite("X-Real-IP", 210000);
      if (xffInputEl && !xffInputEl.value) {
        const v = xffRule && xffRule.rule && xffRule.rule.action && Array.isArray(xffRule.rule.action.requestHeaders) && xffRule.rule.action.requestHeaders[0] && xffRule.rule.action.requestHeaders[0].value
          ? String(xffRule.rule.action.requestHeaders[0].value)
          : "";
        xffInputEl.value = v;
      }
      if (refererInputEl && !refererInputEl.value) {
        const v = refererRule && refererRule.rule && refererRule.rule.action && Array.isArray(refererRule.rule.action.requestHeaders) && refererRule.rule.action.requestHeaders[0] && refererRule.rule.action.requestHeaders[0].value
          ? String(refererRule.rule.action.requestHeaders[0].value)
          : "";
        refererInputEl.value = v;
      }
      if (clientIpInputEl && !clientIpInputEl.value) {
        const v = clientIpRule && clientIpRule.rule && clientIpRule.rule.action && Array.isArray(clientIpRule.rule.action.requestHeaders) && clientIpRule.rule.action.requestHeaders[0] && clientIpRule.rule.action.requestHeaders[0].value
          ? String(clientIpRule.rule.action.requestHeaders[0].value)
          : "";
        clientIpInputEl.value = v;
      }
      if (xRealIpInputEl && !xRealIpInputEl.value) {
        const v = xRealIpRule && xRealIpRule.rule && xRealIpRule.rule.action && Array.isArray(xRealIpRule.rule.action.requestHeaders) && xRealIpRule.rule.action.requestHeaders[0] && xRealIpRule.rule.action.requestHeaders[0].value
          ? String(xRealIpRule.rule.action.requestHeaders[0].value)
          : "";
        xRealIpInputEl.value = v;
      }
    } catch (_) {}
  };
  tabs.xss.addEventListener("click", () => switchTab("xss"));
  tabs.sql.addEventListener("click", () => switchTab("sql"));
  tabs.info.addEventListener("click", () => switchTab("info"));
  tabs["info-extract"].addEventListener("click", () => switchTab("info-extract"));
  tabs.security.addEventListener("click", () => switchTab("security"));
  tabs.cloud.addEventListener("click", () => switchTab("cloud"));
  tabs.shodan.addEventListener("click", () => switchTab("shodan"));
  tabs.tools.addEventListener("click", () => switchTab("tools"));
  tabs.team.addEventListener("click", () => switchTab("team"));
  
  const lastMod = localStorage.getItem("lastModule");
  if (lastMod && tabs[lastMod]) {
    switchTab(lastMod);
  } else {
    switchTab("info");
  }

  refreshJsUi().catch(() => {});
  refreshUaUi().catch(() => {});
  refreshCookieUi().catch(() => {});
  refreshHeaderUi().catch(() => {});
  
  // Bulk URL Opener Event Listeners
  if (openDelayRangeEl) {
    openDelayRangeEl.addEventListener("input", () => {
      if (openDelayValueEl) {
        openDelayValueEl.textContent = openDelayRangeEl.value;
      }
    });
  }
  
  if (focusTabsEl) {
    focusTabsEl.addEventListener("click", () => {
      focusTabsEl.classList.toggle("switch-active");
    });
  }
  
  if (getTabUrlListBtn) {
    getTabUrlListBtn.addEventListener("click", getTabUrlsIntoTextArea);
  }
  
  if (clearUrlListBtn) {
    clearUrlListBtn.addEventListener("click", () => {
      if (urlListEl) {
        urlListEl.value = "";
      }
    });
  }
  
  if (openUrlListBtn) {
    openUrlListBtn.addEventListener("click", startUrlOpeningProcess);
  }
  
  if (stopUrlListBtn) {
    stopUrlListBtn.addEventListener("click", stopUrlOpeningProcess);
  }
  
  if (saveListBtn) {
    saveListBtn.addEventListener("click", saveUrlsAsList);
  }
  
  if (loadListBtn) {
    loadListBtn.addEventListener("click", loadSelectedUrlList);
  }
  
  if (editListBtn) {
    editListBtn.addEventListener("click", editSelectedUrlList);
  }
  
  if (updateListBtn) {
    updateListBtn.addEventListener("click", updateSelectedUrlList);
  }
  
  if (deleteListBtn) {
    deleteListBtn.addEventListener("click", deleteSelectedUrlList);
  }
  
  // Load URL lists on init
  loadUrlListsFromStorage();

  if (jsDisableBtn) {
    jsDisableBtn.addEventListener("click", async () => {
      try {
        const tab = await getActiveTab();
        const ok = await setJsSetting(tab.url || "", "block");
        if (ok) {
          await new Promise((resolve) => chrome.tabs.reload(tab.id, () => resolve(true)));
        }
      } catch (_) {}
      refreshJsUi().catch(() => {});
    });
  }
  if (jsBypassResizeBtn) {
    jsBypassResizeBtn.addEventListener("click", async () => {
      try {
        const tab = await getActiveTab();
        await execInTabMain(tab.id, () => {
          (function () {
            var fixedInnerWidth = window.innerWidth;
            var fixedInnerHeight = window.innerHeight;
            var fixedOuterWidth = window.outerWidth;
            var fixedOuterHeight = window.outerHeight;
            function defineConst(obj, prop, value) {
              if (!obj) return;
              try {
                Object.defineProperty(obj, prop, {
                  configurable: true,
                  enumerable: true,
                  get: function () { return value; },
                  set: function () {},
                });
              } catch (e) {}
            }
            defineConst(window, "innerWidth", fixedInnerWidth);
            defineConst(window, "innerHeight", fixedInnerHeight);
            defineConst(window, "outerWidth", fixedOuterWidth);
            defineConst(window, "outerHeight", fixedOuterHeight);
            if (window.visualViewport) {
              defineConst(window.visualViewport, "width", window.visualViewport.width);
              defineConst(window.visualViewport, "height", window.visualViewport.height);
            }
            try {
              var _addEventListener = window.addEventListener;
              window.addEventListener = function (type, listener, options) {
                if (type === "resize") {
                  return;
                }
                return _addEventListener.call(this, type, listener, options);
              };
            } catch (e) {}
            try {
              window.onresize = null;
            } catch (e) {}
            console.log(
              "[anti-resize] viewport spoof installed:",
              "inner", fixedInnerWidth + "x" + fixedInnerHeight,
              "outer", fixedOuterWidth + "x" + fixedOuterHeight
            );
          })();
        });
        if (jsStateEl) {
          jsStateEl.value = "窗口尺寸检测绕过已启用";
        }
      } catch (e) {}
    });
  }
  if (jsBypassInfiniteDebuggerBtn) {
    jsBypassInfiniteDebuggerBtn.addEventListener("click", async () => {
      try {
        const tab = await getActiveTab();
        await execInTabMain(tab.id, () => {
          (function () {
            try {
              var maxId = window.setTimeout(function () {}, 0);
              for (var i = 0; i <= maxId; i++) {
                window.clearTimeout(i);
                window.clearInterval(i);
              }
            } catch (e) {}
            try {
              if (window.requestAnimationFrame && window.cancelAnimationFrame) {
                var rafId = window.requestAnimationFrame(function () {});
                for (var j = 0; j <= rafId; j++) {
                  window.cancelAnimationFrame(j);
                }
              }
            } catch (e) {}
            function looksLikeDebuggerPayload(code) {
              if (!code) return false;
              var src = String(code);
              src = src.replace(/\s+/g, "").toLowerCase();
              if (src.indexOf("debugger") !== -1) return true;
              if (src.indexOf("debu" + "gger") !== -1) return true;
              return false;
            }
            function looksLikeDebuggerFn(fn) {
              if (!fn) return false;
              if (typeof fn === "function") {
                return looksLikeDebuggerPayload(fn.toString());
              }
              if (typeof fn === "string") {
                return looksLikeDebuggerPayload(fn);
              }
              return false;
            }
            try {
              var _eval = window.eval;
              window.eval = function (code) {
                if (looksLikeDebuggerPayload(code)) {
                  console.warn("[anti-debugger] blocked eval with debugger payload");
                  return;
                }
                return _eval.apply(this, arguments);
              };
              var _Function = window.Function;
              window.Function = function () {
                var args = Array.prototype.slice.call(arguments);
                var body = args.length ? args[args.length - 1] : "";
                if (looksLikeDebuggerPayload(body)) {
                  console.warn("[anti-debugger] blocked Function(...) with debugger payload");
                  return function () {};
                }
                return _Function.apply(this, args);
              };
            } catch (e) {}
            try {
              var _setTimeout = window.setTimeout;
              var _setInterval = window.setInterval;
              var _raf = window.requestAnimationFrame;
              window.setTimeout = function (handler, timeout) {
                if (looksLikeDebuggerFn(handler)) {
                  console.warn("[anti-debugger] blocked setTimeout with debugger fn");
                  return 0;
                }
                return _setTimeout.apply(this, arguments);
              };
              window.setInterval = function (handler, timeout) {
                if (looksLikeDebuggerFn(handler)) {
                  console.warn("[anti-debugger] blocked setInterval with debugger fn");
                  return 0;
                }
                return _setInterval.apply(this, arguments);
              };
              if (typeof _raf === "function") {
                window.requestAnimationFrame = function (callback) {
                  if (looksLikeDebuggerFn(callback)) {
                    console.warn("[anti-debugger] blocked requestAnimationFrame with debugger fn");
                    return 0;
                  }
                  return _raf.apply(this, arguments);
                };
              }
            } catch (e) {}
            console.log("[anti-debugger] generic anti-anti-debug hooks installed");
          })();
        });
        if (jsStateEl) {
          jsStateEl.value = "无限 Debugger 绕过已启用";
        }
      } catch (e) {}
    });
  }
  if (jsBypassToStringBtn) {
    jsBypassToStringBtn.addEventListener("click", async () => {
      try {
        const tab = await getActiveTab();
        await execInTabMain(tab.id, () => {
          (function () {
            var iframe = document.createElement("iframe");
            iframe.style.display = "none";
            iframe.src = "about:blank";
            document.documentElement.appendChild(iframe);
            var cleanWin = iframe.contentWindow || (iframe.contentDocument && iframe.contentDocument.defaultView) || null;
            if (!cleanWin) {
              console.warn("[anti-tostring] failed to get clean window");
              document.documentElement.removeChild(iframe);
              return;
            }
            try {
              var cleanToString = cleanWin.Function.prototype.toString;
              Function.prototype.toString = function () {
                try {
                  return cleanToString.call(this);
                } catch (e) {
                  return "function () { }";
                }
              };
              console.log("[anti-tostring] restored native-like Function.prototype.toString from clean iframe");
            } catch (e) {
              console.warn("[anti-tostring] error while patching Function.prototype.toString:", e);
            }
            document.documentElement.removeChild(iframe);
          })();
        });
        if (jsStateEl) {
          jsStateEl.value = "toString 环境检测绕过已启用";
        }
      } catch (e) {}
    });
  }
  if (jsBypassEvalDebuggerBtn) {
    jsBypassEvalDebuggerBtn.addEventListener("click", async () => {
      try {
        const tab = await getActiveTab();
        await execInTabMain(tab.id, () => {
          (function () {
            try {
              var maxId = window.setTimeout(function () {}, 0);
              for (var i = 0; i <= maxId; i++) {
                window.clearTimeout(i);
                window.clearInterval(i);
              }
            } catch (e) {}
            try {
              if (window.requestAnimationFrame && window.cancelAnimationFrame) {
                var rafId = window.requestAnimationFrame(function () {});
                for (var j = 0; j <= rafId; j++) {
                  window.cancelAnimationFrame(j);
                }
              }
            } catch (e) {}
            function looksLikeDebuggerPayload(code) {
              if (!code) return false;
              var src = String(code);
              src = src.replace(/\s+/g, "").toLowerCase();
              if (src.indexOf("debugger") !== -1) return true;
              if (src.indexOf("debu" + "gger") !== -1) return true;
              return false;
            }
            function looksLikeDebuggerFn(fn) {
              if (!fn) return false;
              if (typeof fn === "function") {
                return looksLikeDebuggerPayload(fn.toString());
              }
              if (typeof fn === "string") {
                return looksLikeDebuggerPayload(fn);
              }
              return false;
            }
            try {
              var _eval = window.eval;
              window.eval = function (code) {
                if (looksLikeDebuggerPayload(code)) {
                  console.warn("[anti-adv-debug] 拦截了 eval 注入的 debugger 负载");
                  return;
                }
                return _eval.apply(this, arguments);
              };
              var _Function = window.Function;
              window.Function = function () {
                var args = Array.prototype.slice.call(arguments);
                var body = args.length ? args[args.length - 1] : "";
                if (looksLikeDebuggerPayload(body)) {
                  console.warn("[anti-adv-debug] 拦截了 Function 构造器注入的 debugger");
                  return function () {};
                }
                return _Function.apply(this, args);
              };
            } catch (e) {}
            try {
              var _setInterval = window.setInterval;
              var _setTimeout = window.setTimeout;
              var _raf = window.requestAnimationFrame;
              window.setInterval = function (handler, timeout) {
                if (looksLikeDebuggerFn(handler)) {
                  console.warn("[anti-adv-debug] 拦截了带有 debugger 的定时任务(Interval)");
                  return 0;
                }
                return _setInterval.apply(this, arguments);
              };
              window.setTimeout = function (handler, timeout) {
                if (looksLikeDebuggerFn(handler)) {
                  console.warn("[anti-adv-debug] 拦截了带有 debugger 的延时任务(Timeout)");
                  return 0;
                }
                return _setTimeout.apply(this, arguments);
              };
              if (typeof _raf === "function") {
                window.requestAnimationFrame = function (callback) {
                  if (looksLikeDebuggerFn(callback)) {
                    console.warn("[anti-adv-debug] 拦截了带有 debugger 的动画帧请求");
                    return 0;
                  }
                  return _raf.apply(this, arguments);
                };
              }
            } catch (e) {}
            console.log("[anti-adv-debug] 高级反调试审计系统已就绪");
          })();
        });
        if (jsStateEl) {
          jsStateEl.value = "Eval Debugger 绕过已启用";
        }
      } catch (e) {}
    });
  }
  if (jsEnableBtn) {
    jsEnableBtn.addEventListener("click", async () => {
      try {
        const tab = await getActiveTab();
        const ok = await setJsSetting(tab.url || "", "allow");
        if (ok) {
          await new Promise((resolve) => chrome.tabs.reload(tab.id, () => resolve(true)));
        }
      } catch (_) {}
      refreshJsUi().catch(() => {});
    });
  }

  if (uaApplyBtn) {
    uaApplyBtn.addEventListener("click", async () => {
      try {
        const tab = await getActiveTab();
        const ua = uaInputEl ? (uaInputEl.value || "").trim() : "";
        const cookie = cookieInputEl ? (cookieInputEl.value || "").trim() : "";
        const xff = xffInputEl ? (xffInputEl.value || "").trim() : "";
        const referer = refererInputEl ? (refererInputEl.value || "").trim() : "";
        const clientIp = clientIpInputEl ? (clientIpInputEl.value || "").trim() : "";
        const xRealIp = xRealIpInputEl ? (xRealIpInputEl.value || "").trim() : "";
        if (!ua && !cookie && !xff && !referer && !clientIp && !xRealIp) return;
        const tasks = [];
        if (ua) tasks.push(setUaForActiveSite(ua));
        if (cookie) tasks.push(setCookieForActiveSite(cookie));
        if (xff) tasks.push(setHeaderForActiveSite("X-Forwarded-For", xff, 210000));
        if (referer) tasks.push(setHeaderForActiveSite("Referer", referer, 210000));
        if (clientIp) tasks.push(setHeaderForActiveSite("Client-IP", clientIp, 210000));
        if (xRealIp) tasks.push(setHeaderForActiveSite("X-Real-IP", xRealIp, 210000));
        const results = await Promise.all(tasks);
        if (results.some(Boolean)) {
          await new Promise((resolve) => chrome.tabs.reload(tab.id, () => resolve(true)));
        }
      } catch (_) {}
      refreshUaUi().catch(() => {});
      refreshCookieUi().catch(() => {});
      refreshHeaderUi().catch(() => {});
    });
  }
  if (uaClearBtn) {
    uaClearBtn.addEventListener("click", async () => {
      try {
        const tab = await getActiveTab();
        const results = await Promise.all([
          clearUaForActiveSite(),
          clearCookieForActiveSite(),
          clearHeaderForActiveSite("X-Forwarded-For", 210000),
          clearHeaderForActiveSite("Referer", 210000),
          clearHeaderForActiveSite("Client-IP", 210000),
          clearHeaderForActiveSite("X-Real-IP", 210000)
        ]);
        if (results.some(Boolean)) {
          await new Promise((resolve) => chrome.tabs.reload(tab.id, () => resolve(true)));
        }
      } catch (_) {}
      if (uaInputEl) uaInputEl.value = "";
      if (cookieInputEl) cookieInputEl.value = "";
      if (xffInputEl) xffInputEl.value = "";
      if (refererInputEl) refererInputEl.value = "";
      if (clientIpInputEl) clientIpInputEl.value = "";
      if (xRealIpInputEl) xRealIpInputEl.value = "";
      refreshUaUi().catch(() => {});
      refreshCookieUi().catch(() => {});
      refreshHeaderUi().catch(() => {});
    });
  }
  document.querySelectorAll(".pf-ua-preset").forEach((btn) => {
    btn.addEventListener("click", () => {
      const ua = btn.getAttribute("data-ua") || "";
      if (uaInputEl) uaInputEl.value = ua;
    });
  });

  const honeyBtn = q("#sniffHoney");
  const honeyList = q("#honey-list");
  if (honeyBtn) {
    honeyBtn.addEventListener("click", async () => {
      if (!honeyList) return;
      honeyList.innerHTML = "<li class='pf-list-item'>正在检测蜜罐...</li>";
      try {
        const tab = await getActiveTab();
        if (!tab || !tab.id) {
          honeyList.innerHTML = "<li class='pf-list-item'>无法获取当前标签页</li>";
          return;
        }

        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            const findings = [];
            // Check global objects
            const susVars = [
              "HFish", "HoneyPot", "Miao", "sec_headers", "x_client_data", 
              "AntSword", "Beebeeto", "Honeyd", "Labrea", "FakeNet"
            ];
            susVars.forEach(v => {
              if (window[v] !== undefined) findings.push(`发现全局变量: window.${v}`);
            });
            // Check specific JS paths or elements if possible (simplified for content script)
            if (document.querySelector("script[src*='hfish']")) findings.push("发现 HFish 脚本引用");
            if (document.cookie.includes("hfish_")) findings.push("发现 HFish Cookie");
            
            // Check fake elements
            if (document.getElementById("canvas_fingerprint")) findings.push("发现 Canvas 指纹脚本 (可能为蜜罐)");

            // Check history hijacking (simple heuristic)
            if (history.length > 50) findings.push("历史记录异常 (history.length > 50)");

            return findings;
          }
        });

        // Also check headers via fetch (HEAD)
        let headerFindings = [];
        try {
          const resp = await new Promise(resolve => {
            chrome.runtime.sendMessage({
              type: "SQL_FETCH",
              url: tab.url,
              method: "HEAD",
              headers: { "Cache-Control": "no-store" }
            }, resolve);
          });
          
          let server = "";
          let cookies = "";
          
          if (resp && resp.ok && resp.headers) {
             const lines = resp.headers.split("\n");
             lines.forEach(line => {
               const parts = line.split(":");
               if (parts.length >= 2) {
                 const k = parts[0].trim().toLowerCase();
                 const v = parts.slice(1).join(":").trim();
                 if (k === "server") server = v;
                 if (k === "set-cookie") cookies += v + ";";
               }
             });
          }

          if (/HFish|Honeypot|OpenCanary/i.test(server)) {
            headerFindings.push(`Server 头异常: ${server}`);
          }
          if (/hfish|honeypot/i.test(cookies)) {
            headerFindings.push("Set-Cookie 包含蜜罐特征");
          }
        } catch (e) {
          // ignore network errors
        }

        const scriptFindings = (results && results[0] && results[0].result) ? results[0].result : [];
        const all = [...scriptFindings, ...headerFindings];
        
        honeyList.innerHTML = "";
        if (all.length === 0) {
          const li = document.createElement("li");
          li.className = "pf-list-item";
          li.textContent = "未发现明显蜜罐特征";
          li.style.color = "#4caf50";
          honeyList.appendChild(li);
        } else {
          all.forEach(f => {
            const li = document.createElement("li");
            li.className = "pf-list-item";
            li.textContent = f;
            li.style.color = "#ff5252";
            honeyList.appendChild(li);
          });
        }
      } catch (e) {
        honeyList.innerHTML = `<li class='pf-list-item'>检测出错: ${e.message}</li>`;
      }
    });
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const runFuzzTask = (fuzzKey, btnId, pauseBtnId, statusId, progressId, listId, dictFile, pathBuilder) => {
    const btn = q(btnId);
    const pauseBtn = q(pauseBtnId);
    const statusEl = q(statusId);
    const progressEl = q(progressId);
    const listEl = q(listId);
    if (!btn || !listEl) return;

    btn.addEventListener("click", async () => {
      try {
        if (btn.disabled) return;
        btn.disabled = true;
        if (pauseBtn) {
          pauseBtn.disabled = false;
          pauseBtn.textContent = "暂停";
        }
        listEl.innerHTML = "";
        statusEl.textContent = "加载中...";
        if (state.fuzzOut && fuzzKey) state.fuzzOut[fuzzKey] = [];
        const results = [];

        const ctl = { paused: false, cancelled: false };
        fuzzCtl[fuzzKey] = ctl;
        
        const tab = await getActiveTab();
        if (!tab || !tab.url) {
           statusEl.textContent = "无 URL";
           btn.disabled = false;
           if (pauseBtn) pauseBtn.disabled = true;
           fuzzCtl[fuzzKey] = null;
           return;
        }
        let baseUrlObj;
        try {
            baseUrlObj = new URL(tab.url);
        } catch(e) {
            statusEl.textContent = "URL 无效";
            btn.disabled = false;
            if (pauseBtn) pauseBtn.disabled = true;
            fuzzCtl[fuzzKey] = null;
            return;
        }
        
        const baseUrl = baseUrlObj.origin; 
        
        let dictContent = "";
        try {
            const r = await fetch(chrome.runtime.getURL(dictFile));
            dictContent = await r.text();
        } catch(e) {
            statusEl.textContent = "字典加载失败";
            btn.disabled = false;
            if (pauseBtn) pauseBtn.disabled = true;
            fuzzCtl[fuzzKey] = null;
            return;
        }
        
        const lines = dictContent.split(/\r?\n/).filter(l => l.trim());
        const total = lines.length;
        if (total === 0) {
            statusEl.textContent = "字典为空";
            btn.disabled = false;
            if (pauseBtn) pauseBtn.disabled = true;
            fuzzCtl[fuzzKey] = null;
            return;
        }

        statusEl.textContent = `0/${total}`;
        if (progressEl) {
            progressEl.style.display = "block";
            const val = progressEl.querySelector(".pf-progress-value");
            if(val) val.style.width = "0%";
        }

        let finished = 0;
        const limit = 5; 
        let index = 0;

        const updateProgress = () => {
          finished++;
          statusEl.textContent = `${finished}/${total}`;
          if (progressEl) {
            const val = progressEl.querySelector(".pf-progress-value");
            if (val) val.style.width = `${(finished / total) * 100}%`;
          }
        };

        if (pauseBtn) {
          if (pauseBtn._clickHandler) {
            pauseBtn.removeEventListener("click", pauseBtn._clickHandler);
          }
          const clickHandler = () => {
            const cur = fuzzCtl[fuzzKey];
            if (!cur) return;
            cur.paused = !cur.paused;
            pauseBtn.textContent = cur.paused ? "继续" : "暂停";
            if (cur.paused) statusEl.textContent = `暂停 ${finished}/${total}`;
            else statusEl.textContent = `${finished}/${total}`;
          };
          pauseBtn._clickHandler = clickHandler;
          pauseBtn.addEventListener("click", clickHandler);
        }
        
        const worker = async () => {
           while (index < total) {
               while (ctl.paused) {
                 await sleep(160);
                 if (ctl.cancelled) return;
               }
               if (ctl.cancelled) return;
               const line = lines[index++].trim();
               if (!line) {
                 updateProgress();
                 continue;
               }
               
               let targetUrl = "";
               try {
                   if (pathBuilder) {
                       targetUrl = pathBuilder(baseUrlObj, line);
                   } else {
                       targetUrl = new URL(line.startsWith("/") ? line : "/" + line, baseUrl).toString();
                   }
               } catch(e) {
                 updateProgress();
                 continue;
               }

               try {
                   const resp = await new Promise(resolve => {
                       chrome.runtime.sendMessage({
                           type: "SQL_FETCH",
                           url: targetUrl,
                           method: "HEAD",
                           headers: { "Cache-Control": "no-store" }
                       }, resolve);
                   });
                   
                   if (resp && resp.ok) {
                       const statusMatch = resp.meta ? resp.meta.match(/^(\d+)/) : null;
                       const code = statusMatch ? parseInt(statusMatch[1]) : 0;
                       
                       if ([200, 302, 403].includes(code)) {
                           const headers = resp.headers || "";
                           const lenMatch = headers.match(/Content-Length:\s*(\d+)/i);
                           const size = lenMatch ? parseInt(lenMatch[1], 10) : null;
                           if (size !== null && Number.isFinite(size) && size > 0) {
                             const li = document.createElement("li");
                             li.className = "pf-item";
                             let displayPath = targetUrl;
                             if (targetUrl.startsWith(baseUrl)) {
                                 displayPath = targetUrl.substring(baseUrl.length);
                             }
                             
                             li.innerHTML = `
                               <div class="pf-item-primary" title="${targetUrl}">${displayPath}</div>
                               <div class="pf-item-extra">
                                 <span class="pf-badge ${code === 200 ? 'pf-badge-success' : 'pf-badge-warning'}">${code}</span>
                                 <span class="pf-badge">Size: ${String(size)}</span>
                               </div>
                             `;
                             li.addEventListener("click", () => chrome.tabs.create({ url: targetUrl }));
                             listEl.appendChild(li);
                             results.push({ url: targetUrl, code, size });
                           }
                       }
                   }
               } catch(e) {
                   // ignore
               }

               updateProgress();
           }
        };

        const promises = [];
        for(let i=0; i<limit; i++) promises.push(worker());
        await Promise.all(promises);
        
        statusEl.textContent = "完成";
        if (state.fuzzOut && fuzzKey) state.fuzzOut[fuzzKey] = results;
        btn.disabled = false;
        if (pauseBtn) {
          pauseBtn.disabled = true;
          pauseBtn.textContent = "暂停";
        }
        fuzzCtl[fuzzKey] = null;
        setTimeout(() => { if(progressEl) progressEl.style.display = "none"; }, 2000);

      } catch (e) {
        statusEl.textContent = "Err";
        if (state.fuzzOut && fuzzKey) state.fuzzOut[fuzzKey] = [];
        btn.disabled = false;
        if (pauseBtn) {
          pauseBtn.disabled = true;
          pauseBtn.textContent = "暂停";
        }
        fuzzCtl[fuzzKey] = null;
      }
    });
  };

  runFuzzTask("js", "#fuzzJs", "#fuzzJsPause", "#fuzzJsStatus", "#fuzzJsProgress", "#fuzzJsList", "data/js.txt", (base, line) => {
      const path = base.pathname;
      const dir = path.substring(0, path.lastIndexOf('/') + 1);
      return new URL(dir + line, base.origin).toString();
  });
  runFuzzTask("api", "#fuzzApi", "#fuzzApiPause", "#fuzzApiStatus", "#fuzzApiProgress", "#fuzzApiList", "data/api.txt", (base, line) => {
      return new URL(line.startsWith("/") ? line : "/" + line, base.origin).toString();
  });
  runFuzzTask("param", "#fuzzParam", "#fuzzParamPause", "#fuzzParamStatus", "#fuzzParamProgress", "#fuzzParamList", "data/param.txt", (base, line) => {
      const inputEl = q("#fuzzParamPath");
      const inputPath = inputEl ? inputEl.value.trim() : "";
      let start = inputPath;
      if (!start) return new URL(line.startsWith("/") ? line : "/" + line, base.origin).toString();
      if (!start.startsWith("http")) {
          start = new URL(start.startsWith("/") ? start : "/" + start, base.origin).toString();
      }
      return start + line;
  });

  const fillSqlFromCurrentPage = async () => {
    const tab = await getActiveTab();
    state.tabId = tab.id;
    const pageUrl = await getPageUrl(state.tabId);
    const raw = pageUrl || tab.url || "";
    if (sqlUrlEl) sqlUrlEl.value = raw;

    if (sqlCookiesEl && tab.url) {
      const cookies = await new Promise((resolve) => {
        if (!chrome.cookies) return resolve([]);
        chrome.cookies.getAll({ url: tab.url }, (cs) => resolve(cs || []));
      });
      const visible = {};
      cookies.forEach((c) => {
        if (c && c.name) visible[c.name] = c.value || "";
      });
      sqlCookiesEl.value = stringifyCookieString(visible);
    }
  };

  const applySqlPayload = (mode) => {
    if (!sqlEntryEl || !sqlKeyEl || !sqlPayloadEl) return;
    const entry = sqlEntryEl.value;
    const key = (sqlKeyEl.value || "").trim();
    const payload = sqlPayloadEl.value || "";
    if (!key) return;

    if (entry === "url") {
      if (!sqlUrlEl) return;
      try {
        const tabUrl = (state && state.tabId) ? null : null;
        const base = sqlUrlEl.value || "";
        const u = new URL(base);
        const cur = u.searchParams.get(key) || "";
        u.searchParams.set(key, mode === "append" ? (cur + payload) : payload);
        sqlUrlEl.value = u.toString();
      } catch (_) {}
      return;
    }
    if (entry === "post") {
      if (!sqlBodyTypeEl || !sqlBodyEl) return;
      sqlBodyTypeEl.value = "form";
      const usp = parseFormBody(sqlBodyEl.value || "");
      const cur = usp.get(key) || "";
      usp.set(key, mode === "append" ? (cur + payload) : payload);
      sqlBodyEl.value = usp.toString();
      return;
    }
    if (entry === "json") {
      if (!sqlBodyTypeEl || !sqlBodyEl) return;
      sqlBodyTypeEl.value = "json";
      try {
        const raw = (sqlBodyEl.value || "").trim();
        const obj = raw ? JSON.parse(raw) : {};
        const cur = obj && Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : "";
        obj[key] = mode === "append" ? (String(cur) + payload) : payload;
        sqlBodyEl.value = JSON.stringify(obj, null, 2);
      } catch (_) {}
      return;
    }
    if (entry === "cookie") {
      if (!sqlCookiesEl) return;
      const obj = parseCookieString(sqlCookiesEl.value || "");
      const cur = obj[key] || "";
      obj[key] = mode === "append" ? (cur + payload) : payload;
      sqlCookiesEl.value = stringifyCookieString(obj);
      return;
    }
    if (entry === "header") {
      if (!sqlHeadersEl) return;
      const obj = parseHeaderLines(sqlHeadersEl.value || "");
      const cur = obj[key] || "";
      obj[key] = mode === "append" ? (cur + payload) : payload;
      sqlHeadersEl.value = stringifyHeaderLines(obj);
      return;
    }
  };

  const buildCurl = async () => {
    const tab = await getActiveTab();
    state.tabId = tab.id;
    const urlRaw = (sqlUrlEl && sqlUrlEl.value) ? sqlUrlEl.value : (tab.url || "");
    const u = new URL(urlRaw, tab.url || undefined);
    const method = (sqlMethodEl && sqlMethodEl.value) ? sqlMethodEl.value : "GET";
    const headers = parseHeaderLines(sqlHeadersEl ? sqlHeadersEl.value : "");
    const bodyType = sqlBodyTypeEl ? sqlBodyTypeEl.value : "none";
    const bodyRaw = sqlBodyEl ? (sqlBodyEl.value || "") : "";
    let body = "";
    if (!/^(GET|HEAD)$/i.test(method)) {
      if (bodyType === "form") body = parseFormBody(bodyRaw).toString();
      else if (bodyType === "json") body = bodyRaw.trim();
      else if (bodyType === "raw") body = bodyRaw;
    }
    const parts = ["curl", "-i", "-sS"];
    parts.push("-X", JSON.stringify(method));
    parts.push(JSON.stringify(u.toString()));
    Object.keys(headers).forEach((k) => {
      parts.push("-H", JSON.stringify(`${k}: ${headers[k]}`));
    });
    if (body) {
      parts.push("--data-raw", JSON.stringify(body));
    }
    return parts.join(" ");
  };

  const sendSqlRequest = async () => {
    const tab = await getActiveTab();
    state.tabId = tab.id;

    const urlRaw = (sqlUrlEl && sqlUrlEl.value) ? sqlUrlEl.value : (tab.url || "");
    let urlObj;
    try {
      urlObj = new URL(urlRaw, tab.url || undefined);
    } catch (_) {
      renderSqlResponse({ meta: "URL 解析失败", headers: "", body: "" });
      return;
    }

    const method = (sqlMethodEl && sqlMethodEl.value) ? sqlMethodEl.value : "GET";
    const headers = parseHeaderLines(sqlHeadersEl ? sqlHeadersEl.value : "");
    const bodyType = sqlBodyTypeEl ? sqlBodyTypeEl.value : "none";
    const bodyRaw = sqlBodyEl ? (sqlBodyEl.value || "") : "";

    let body = undefined;
    if (!/^(GET|HEAD)$/i.test(method)) {
      if (bodyType === "form") {
        body = parseFormBody(bodyRaw).toString();
        if (!headers["Content-Type"]) headers["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8";
      } else if (bodyType === "json") {
        const t = bodyRaw.trim();
        try {
          if (t) JSON.parse(t);
        } catch (_) {
          renderSqlResponse({ meta: "JSON 格式错误", headers: "", body: "" });
          return;
        }
        body = t;
        if (!headers["Content-Type"]) headers["Content-Type"] = "application/json;charset=UTF-8";
      } else if (bodyType === "raw") {
        body = bodyRaw;
      }
    }

    const cookieText = sqlCookiesEl ? (sqlCookiesEl.value || "").trim() : "";
    if (cookieText) {
      try {
        const reqOrigin = urlObj.origin;
        const tabOrigin = new URL(tab.url || "").origin;
        if (reqOrigin === tabOrigin) {
          const cookies = parseCookieString(cookieText);
          const entries = Object.keys(cookies).map((k) => [k, cookies[k]]);
          await new Promise((resolve) =>
            chrome.scripting.executeScript(
              {
                target: { tabId: state.tabId },
                func: (pairs) => {
                  try {
                    (pairs || []).forEach(([k, v]) => {
                      document.cookie = `${k}=${v}; path=/`;
                    });
                  } catch (_) {}
                  return true;
                },
                args: [entries]
              },
              () => resolve(true)
            )
          );
        }
      } catch (_) {}
    }

    const start = Date.now();
    try {
      renderSqlResponse({ meta: "请求中...", headers: "", body: "" });
      const tabOrigin = (() => {
        try { return new URL(tab.url || "").origin; } catch (_) { return ""; }
      })();
      const sameOrigin = !!tabOrigin && urlObj.origin === tabOrigin;

      const headersObj = headers;
      const headersArr = Object.keys(headersObj).map((k) => [k, headersObj[k]]);
      const req = { url: urlObj.toString(), method, headers: headersArr, headersObj, body };

      let out = null;
      if (sameOrigin) {
        out = await sqlFetchViaTab(state.tabId, req);
      } else {
        out = await sqlFetchViaBackground(req);
      }
      if (out && out.ok) {
        renderSqlResponse({ meta: out.meta || "", headers: out.headers || "", body: out.body || "" });
      } else {
        const ms = Date.now() - start;
        renderSqlResponse({
          meta: (out && out.meta) ? out.meta : `请求失败 | ${ms}ms`,
          headers: (out && out.error) ? String(out.error) : "request_failed",
          body: ""
        });
      }
    } catch (e) {
      const ms = Date.now() - start;
      renderSqlResponse({ meta: `请求失败 | ${ms}ms`, headers: String(e && e.message ? e.message : e), body: "" });
    }
  };

  if (sqlFillBtn) {
    sqlFillBtn.addEventListener("click", () => {
      fillSqlFromCurrentPage().catch(() => {});
    });
  }
  if (sqlSendBtn) {
    sqlSendBtn.addEventListener("click", () => {
      sendSqlRequest().catch(() => {});
    });
  }
  if (sqlAppendBtn) sqlAppendBtn.addEventListener("click", () => applySqlPayload("append"));
  if (sqlReplaceBtn) sqlReplaceBtn.addEventListener("click", () => applySqlPayload("replace"));
  if (sqlCurlBtn) {
    sqlCurlBtn.addEventListener("click", async () => {
      try {
        const curl = await buildCurl();
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(curl);
        }
        renderSqlResponse({ meta: "Curl 已复制到剪贴板", headers: "", body: curl });
      } catch (_) {}
    });
  }
  if (sqlClearBtn) {
    sqlClearBtn.addEventListener("click", () => {
      if (sqlHeadersEl) sqlHeadersEl.value = "";
      if (sqlCookiesEl) sqlCookiesEl.value = "";
      if (sqlBodyEl) sqlBodyEl.value = "";
      if (sqlPayloadEl) sqlPayloadEl.value = "";
      renderSqlResponse(null);
    });
  }
  document.querySelectorAll(".pf-sql-payload").forEach((btn) => {
    btn.addEventListener("click", () => {
      const p = btn.getAttribute("data-payload") || "";
      if (sqlPayloadEl) sqlPayloadEl.value = p;
    });
  });

  fuzzAllBtn.addEventListener("click", async () => {
    try {
      const tab = await getActiveTab();
      state.tabId = tab.id;
      await fuzzAllFrames(state.tabId);
    } catch (_) {}
  });
  const renderCsp = (data, jsCookieStr) => {
    cspListEl.innerHTML = "";
    const hasCsp = data && data.csp;
    const headers = data && Array.isArray(data.headers) ? data.headers : [];
    const headerCookies = [];
    headers.forEach((h) => {
      const n = (h.name || "").toLowerCase();
      if (n === "set-cookie" && h.value) headerCookies.push(h.value);
    });
    const jsCookie = String(jsCookieStr || "");
    const hasJsCookie = jsCookie.trim().length > 0;
    if (!hasCsp && headerCookies.length === 0 && !hasJsCookie) {
      const li = document.createElement("li");
      li.className = "pf-empty";
      li.textContent = "未检测到 CSP / Cookie 信息";
      cspListEl.appendChild(li);
      return;
    }
    if (hasCsp) {
      const parts = data.csp.split(";").map((s) => s.trim()).filter(Boolean);
      parts.forEach((part) => {
        const li = document.createElement("li");
        li.className = "pf-item";
        li.textContent = part;
        cspListEl.appendChild(li);
      });
    }
    if (headerCookies.length || hasJsCookie) {
      const titleLi = document.createElement("li");
      titleLi.className = "pf-empty";
      titleLi.textContent = "Cookie / HttpOnly 信息";
      cspListEl.appendChild(titleLi);
      headerCookies.forEach((raw) => {
        const parts = String(raw || "").split(";").map((s) => s.trim()).filter(Boolean);
        if (!parts.length) return;
        const first = parts[0];
        const flags = parts.slice(1).map((s) => s.toLowerCase());
        const httpOnly = flags.includes("httponly");
        const li = document.createElement("li");
        li.className = "pf-item";
        const p = document.createElement("div");
        p.className = "pf-item-primary";
        p.textContent = first;
        const s = document.createElement("div");
        s.className = "pf-item-secondary";
        s.textContent = httpOnly ? "HttpOnly（仅服务端可见）" : "非 HttpOnly（前端可见或可被窃取）";
        li.appendChild(p);
        li.appendChild(s);
        cspListEl.appendChild(li);
      });
      if (hasJsCookie) {
        const jsPairs = jsCookie.split(";").map((s) => s.trim()).filter(Boolean);
        jsPairs.forEach((pair) => {
          const li = document.createElement("li");
          li.className = "pf-item";
          const p = document.createElement("div");
          p.className = "pf-item-primary";
          p.textContent = pair;
          const s = document.createElement("div");
          s.className = "pf-item-secondary";
          s.textContent = "document.cookie 可见";
          li.appendChild(p);
          li.appendChild(s);
          cspListEl.appendChild(li);
        });
      }
    }
  };

  readCspBtn.addEventListener("click", async () => {
    try {
      const tab = await getActiveTab();
      const [cspRes, cookieRes] = await Promise.all([
        readCsp(tab.id),
        execInTabMain(tab.id, () => {
          try {
            return document.cookie || "";
          } catch (_) {
            return "";
          }
        })
      ]);
      const obj = cspRes && cspRes.ok ? cspRes.data : null;
      const jsCookie = cookieRes && cookieRes[0] && typeof cookieRes[0].result === "string" ? cookieRes[0].result : "";
      renderCsp(obj, jsCookie);
    } catch (_) {
      renderCsp(null, "");
    }
  });
  const collectResourcesAllFrames = (tabId) =>
    new Promise((resolve, reject) =>
      chrome.scripting.executeScript(
        {
          target: { tabId, allFrames: true },
          func: () => {
            const html = (document.documentElement && document.documentElement.outerHTML) ? document.documentElement.outerHTML.slice(0, 600000) : "";
            const urls = Array.from(document.scripts || []).map((s) => s.src).filter((u) => !!u);
            return { html, urls };
          }
        },
        (res) => (chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res))
      )
    );
  const renderSniffResults = (out) => {
    sniffListEl.textContent = "";
    if (!out) {
      const li = document.createElement("li");
      li.className = "pf-empty";
      li.textContent = "未发现敏感资产";
      sniffListEl.appendChild(li);
      return;
    }
    const labels = {
      site_ip: "站点 IP",
      ip: "IP:端口",
      domain: "域名",
      url: "URL",
      absolute_path: "绝对路径",
      relative_path: "相对路径",
      email: "邮箱",
      phone: "手机号",
      jwt: "JWT",
      key: "可能的密钥",
      crypto: "加密关键词",
      sensitive: "敏感信息"
    };
    const order = ["site_ip","ip","domain","url","absolute_path","relative_path","email","phone","jwt","key","crypto","sensitive"];
    let total = 0;
    order.forEach((k) => {
      const arr = Array.isArray(out[k]) ? out[k] : [];
      const li = document.createElement("li");
      li.className = "pf-item";
      const head = document.createElement("div");
      head.className = "pf-collapse-head";
      const title = document.createElement("div");
      title.className = "pf-item-primary";
      title.textContent = labels[k] || k;
      const right = document.createElement("div");
      right.className = "pf-item-extra";
      const count = document.createElement("span");
      count.className = "pf-collapse-count";
      count.textContent = String(arr.length);
      const arrow = document.createElement("span");
      arrow.textContent = "▶";
      right.appendChild(count);
      right.appendChild(arrow);
      head.appendChild(title);
      head.appendChild(right);
      const body = document.createElement("div");
      body.className = "pf-collapse-body pf-hidden";
      const ul = document.createElement("ul");
      ul.className = "pf-list";
      arr.slice(0, 200).forEach((v) => {
        total++;
        const li2 = document.createElement("li");
        li2.className = "pf-item";
        const p = document.createElement("div");
        p.className = "pf-item-primary";
        p.textContent = v.value || "";
        const s = document.createElement("div");
        s.className = "pf-item-secondary";
        s.classList.add("pf-muted");
        s.textContent = (v.source || "unknown") + ":" + (v.line || "0");
        li2.appendChild(p);
        li2.appendChild(s);
        ul.appendChild(li2);
      });
      body.appendChild(ul);
      head.addEventListener("click", () => {
        const hidden = body.classList.contains("pf-hidden");
        if (hidden) {
          body.classList.remove("pf-hidden");
          arrow.textContent = "▼";
        } else {
          body.classList.add("pf-hidden");
          arrow.textContent = "▶";
        }
      });
      li.appendChild(head);
      li.appendChild(body);
      sniffListEl.appendChild(li);
    });
    if (total === 0) {
      const li = document.createElement("li");
      li.className = "pf-empty";
      li.textContent = "未发现敏感资产";
      sniffListEl.appendChild(li);
    }
  };
  const runSniff = async () => {
    try {
      const tab = await getActiveTab();
      state.tabId = tab.id;
      const frames = await collectResourcesAllFrames(state.tabId);
      const urls = [];
      let html = "";
      for (const r of frames || []) {
        const obj = r.result || {};
        (obj.urls || []).forEach((u) => urls.push(u));
        html += (obj.html || "") + "\n";
      }
      const uSet = new Set(urls.filter(Boolean));
      const uList = Array.from(uSet);
      const r = await new Promise((resolve, reject) =>
        chrome.runtime.sendMessage({ type: "DEEP_SNIFF", urls: uList, html: html.slice(0, 800000) }, (res) =>
          chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res)
        )
      );
      const out = r && r.ok ? r.result : null;
      if (out && tab && tab.url) {
        try {
          const u = new URL(tab.url);
          const host = u.hostname || "";
          const src = (isValidIPv4(host) || isLikelyIPv6(host)) ? "host" : "dns.google";
          const ips = await resolveHostIps(host);
          const uniqIps = Array.from(new Set((ips || []).map((x) => String(x || "").trim()).filter(Boolean)));
          out.site_ip = uniqIps.map((ip) => ({ value: ip, source: src, line: 0 }));
        } catch (_) {}
      }
      state.sniffOut = out;
      renderSniffResults(out);
    } catch (_) {
      state.sniffOut = null;
      renderSniffResults(null);
    }
  };

  const copyText = async (text) => {
    const t = String(text || "");
    if (!t) return false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(t);
        return true;
      }
    } catch (_) {}
    return false;
  };

  const isValidIPv4 = (ip) => {
    const s = String(ip || "").trim();
    const parts = s.split(".");
    if (parts.length !== 4) return false;
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p)) return false;
      const n = Number(p);
      if (n < 0 || n > 255) return false;
    }
    return true;
  };

  const isLikelyIPv6 = (ip) => {
    const s = String(ip || "").trim();
    if (!s.includes(":")) return false;
    if (!/^[0-9a-fA-F:]+$/.test(s.replace(/^\[|\]$/g, ""))) return false;
    return s.replace(/^\[|\]$/g, "").length >= 2;
  };

  const resolveHostIps = async (host) => {
    const h = String(host || "").trim();
    if (!h) return [];
    if (isValidIPv4(h) || isLikelyIPv6(h)) return [h.replace(/^\[|\]$/g, "")];
    const doQuery = async (type) => {
      try {
        const url = `https://dns.google/resolve?name=${encodeURIComponent(h)}&type=${encodeURIComponent(type)}`;
        const resp = await new Promise((resolve) =>
          chrome.runtime.sendMessage({ type: "SQL_FETCH", url, method: "GET", headers: { "Cache-Control": "no-store", "Accept": "application/dns-json" } }, resolve)
        );
        if (!resp || !resp.ok) return [];
        const json = JSON.parse(resp.body || "{}");
        const ans = Array.isArray(json.Answer) ? json.Answer : [];
        const ips = [];
        ans.forEach((a) => {
          const d = a && a.data ? String(a.data).trim() : "";
          if (type === "A" && isValidIPv4(d)) ips.push(d);
          if (type === "AAAA" && isLikelyIPv6(d)) ips.push(d.replace(/^\[|\]$/g, ""));
        });
        return ips;
      } catch (_) {
        return [];
      }
    };
    const [a, aaaa] = await Promise.all([doQuery("A"), doQuery("AAAA")]);
    return Array.from(new Set([...a, ...aaaa]));
  };

  const fingerprintAllFrames = (tabId) =>
    new Promise((resolve, reject) =>
      chrome.scripting.executeScript(
        {
          target: { tabId, allFrames: true },
          func: () => {
            const out = [];
            const push = (name, version, source) => out.push({ name, version: version || "", source: source || "" });
            try {
              if (window.jQuery) push("jQuery", (window.jQuery.fn && window.jQuery.fn.jquery) || "", "global");
              if (window.Vue) push("Vue", window.Vue.version || "", "global");
              if (window.angular && window.angular.version) push("Angular", (window.angular.version.full || ""), "global");
              if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) push("React", "", "global");
              if (window.bootstrap) push("Bootstrap", "", "global");
            } catch (_) {}
            try {
              const scripts = Array.from(document.scripts || []).map((s) => s.src).filter(Boolean);
              const regs = [
                { name: "jQuery", re: /jquery(?:\.|[-_])(\d+\.\d+\.\d+)/i },
                { name: "Vue", re: /vue(?:\.|[-_])(\d+\.\d+\.\d+)/i },
                { name: "React", re: /react(?:\.|[-_])(\d+\.\d+\.\d+)/i },
                { name: "Angular", re: /angular(?:\.|[-_])(\d+\.\d+\.\d+)/i },
                { name: "Bootstrap", re: /bootstrap(?:\.|[-_])(\d+\.\d+\.\d+)/i }
              ];
              scripts.forEach((src) => {
                const low = src.toLowerCase();
                regs.forEach((r) => {
                  if (low.includes(r.name.toLowerCase())) {
                    const m = low.match(r.re);
                    const ver = m && m[1] ? m[1] : "";
                    push(r.name, ver, "script:" + src.split("/").pop());
                  }
                });
              });
            } catch (_) {}
            // dedupe
            const key = (o) => `${o.name}|${o.version}|${o.source}`;
            const set = new Set();
            const out2 = [];
            out.forEach((o) => {
              const k = key(o);
              if (!set.has(k)) { set.add(k); out2.push(o); }
            });
            return out2.slice(0, 100);
          }
        },
        (res) => (chrome.runtime.lastError ? reject(chrome.runtime.lastError) : resolve(res))
      )
    );
  const renderFP = (list) => {
    fpListEl.textContent = "";
    const arr = Array.isArray(list) ? list : [];
    if (!arr.length) {
      const li = document.createElement("li");
      li.className = "pf-empty";
      li.textContent = "未识别到前端框架";
      fpListEl.appendChild(li);
      return;
    }
    arr.forEach((it) => {
      const li = document.createElement("li");
      li.className = "pf-item";
      const p = document.createElement("div");
      p.className = "pf-item-primary";
      p.textContent = it.version ? `${it.name} ${it.version}` : it.name;
      li.appendChild(p);
      const s = document.createElement("div");
      if (it.source) {
        s.className = "pf-item-secondary";
        s.textContent = it.source;
        li.appendChild(s);
      }
      fpListEl.appendChild(li);
    });
  };

  const setVueStatus = (text) => {
    if (!vueStatusEl) return;
    vueStatusEl.textContent = String(text || "");
  };

  const renderVueFindings = (items) => {
    if (!vueDetectListEl) return;
    vueDetectListEl.textContent = "";
    const arr = Array.isArray(items) ? items : [];
    if (!arr.length) {
      const li = document.createElement("li");
      li.className = "pf-empty";
      li.textContent = "无结果";
      vueDetectListEl.appendChild(li);
      return;
    }
    arr.forEach((it) => {
      const li = document.createElement("li");
      li.className = "pf-item";
      const p = document.createElement("div");
      p.className = "pf-item-primary";
      p.textContent = String(it.k || it.title || it.key || "");
      const s = document.createElement("div");
      s.className = "pf-item-secondary";
      s.textContent = String(it.v || it.value || "");
      li.appendChild(p);
      li.appendChild(s);
      vueDetectListEl.appendChild(li);
    });
  };

  // 渲染 URL 列表，每个 URL 带复制和打开按钮
  const renderVueUrlsList = (urls) => {
    if (!vueDetectListEl) return;
    vueDetectListEl.textContent = "";
    
    if (!urls || !urls.length) {
      const li = document.createElement("li");
      li.className = "pf-empty";
      li.textContent = "无 URL";
      vueDetectListEl.appendChild(li);
      return;
    }
    
    const headerLi = document.createElement("li");
    headerLi.className = "pf-item pf-item-header";
    headerLi.innerHTML = `
      <div class="pf-item-primary">页面完整 URL 列表（${urls.length} 条）</div>
    `;
    vueDetectListEl.appendChild(headerLi);
    
    urls.forEach((url, index) => {
      const li = document.createElement("li");
      li.className = "pf-item pf-url-item";
      
      // 序号
      const numSpan = document.createElement("span");
      numSpan.textContent = `${index + 1}.`;
      numSpan.className = "pf-url-num";
      li.appendChild(numSpan);
      
      // URL 文本
      const urlSpan = document.createElement("span");
      urlSpan.textContent = url;
      urlSpan.className = "pf-url-text";
      urlSpan.title = url;
      li.appendChild(urlSpan);
      
      // 复制按钮
      const copyBtn = document.createElement("button");
      copyBtn.className = "pf-btn pf-btn-sm";
      copyBtn.textContent = "复制";
      copyBtn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(url);
          copyBtn.textContent = "已复制";
          copyBtn.classList.add("pf-btn-success");
          setTimeout(() => {
            copyBtn.textContent = "复制";
            copyBtn.classList.remove("pf-btn-success");
          }, 1500);
        } catch (e) {
          copyBtn.textContent = "失败";
          setTimeout(() => {
            copyBtn.textContent = "复制";
          }, 1500);
        }
      });
      li.appendChild(copyBtn);
      
      // 打开按钮
      const openBtn = document.createElement("button");
      openBtn.className = "pf-btn pf-btn-sm";
      openBtn.textContent = "打开";
      openBtn.addEventListener("click", () => {
        chrome.tabs.create({ url, active: false });
        openBtn.textContent = "已打开";
        openBtn.classList.add("pf-btn-primary");
        setTimeout(() => {
          openBtn.textContent = "打开";
          openBtn.classList.remove("pf-btn-primary");
        }, 1500);
      });
      li.appendChild(openBtn);
      
      vueDetectListEl.appendChild(li);
    });
  };

  const setVueUrls = (urls) => {
    const text = Array.isArray(urls) ? urls.join("\n") : String(urls || "");
    state.vueUrls = text;
    if (vueUrlsEl) vueUrlsEl.value = text;
  };

  const normalizeRoutePath = (p) => {
    const s = String(p || "");
    if (!s) return "";
    if (s === "/" || s.startsWith("/")) return s;
    return "/" + s;
  };

  const uniqueLines = (lines) => {
    const out = [];
    const seen = new Set();
    (Array.isArray(lines) ? lines : []).forEach((x) => {
      const s = String(x || "").trim();
      if (!s) return;
      if (seen.has(s)) return;
      seen.add(s);
      out.push(s);
    });
    return out;
  };

  const buildAbsoluteUrls = (origin, mode, paths) => {
    const o = String(origin || "").replace(/\/+$/g, "");
    const m = String(mode || "");
    const out = [];
    (Array.isArray(paths) ? paths : []).forEach((p) => {
      const path = normalizeRoutePath(p);
      if (!path) return;
      if (m === "hash") out.push(`${o}/#${path}`);
      else out.push(`${o}${path}`);
    });
    return out;
  };

  // Vue 检测 - 完整迁移 VueCrack 功能
  if (vueDetectBtn) {
    vueDetectBtn.addEventListener("click", async () => {
      try {
        setVueStatus("检测中...");
        const tab = await getActiveTab();
        
        // 使用 VueCrack 的完整检测逻辑
        const res = await execInTabMain(tab.id, executeVueDetect);
        
        const out = res && res[0] && res[0].result ? res[0].result : null;
        
        if (!out) {
          setVueStatus("检测失败");
          return;
        }
        
        // 显示检测结果
        const findings = [];
        let generatedUrls = [];
        
        if (out.vueDetected) {
          findings.push({ k: "Vue Detected", v: "Yes" });
          findings.push({ k: "Vue Version", v: out.vueVersion || "Unknown" });
          
          if (out.routerDetected) {
            findings.push({ k: "Vue Router", v: "Detected" });
            findings.push({ k: "Router Base", v: out.routerBase || "(none)" });
            
            if (out.pageAnalysis.detectedBasePath) {
              findings.push({ k: "Detected Base Path", v: out.pageAnalysis.detectedBasePath });
            }
            
            findings.push({ k: "Total Routes", v: out.allRoutes.length.toString() });
            findings.push({ k: "Modified Auth Routes", v: out.modifiedRoutes.length.toString() });
            
            // 生成 URL 列表
            const tabInfo = await getActiveTab();
            const origin = (() => {
              try {
                const u = new URL(tabInfo.url || "");
                if (u.origin && u.origin !== "null") return u.origin;
                return `${u.protocol}//${u.host}`;
              } catch (_) {
                return "";
              }
            })();
            
            // 判断 router mode
            const routerModeRes = await execInTabMain(tab.id, () => {
              try {
                const vueRoot = document.querySelector('[__vue_app__]') || document.querySelector('[data-v-app]');
                if (!vueRoot) return 'history';
                if (vueRoot.__vue_app__) {
                  const app = vueRoot.__vue_app__;
                  const router = app.config?.globalProperties?.$router;
                  if (router) return router.mode || 'history';
                }
                if (vueRoot.__vue__) {
                  const vue = vueRoot.__vue__;
                  const router = vue.$router;
                  if (router) return router.mode || 'history';
                }
                return 'history';
              } catch (e) {
                return 'history';
              }
            });
            const mode = (routerModeRes && routerModeRes[0] && routerModeRes[0].result) ? routerModeRes[0].result : 'history';
            
            // 从所有路由生成 URL
            const paths = out.allRoutes
              .map(r => r.path)
              .filter(p => p && p.trim() && p.trim() !== '*' && !p.includes('*'))
              .map(p => {
                // 移除动态参数 :param
                return p.replace(/:\w+/g, 'PARAM').replace(/\/+/g, '/');
              });
            
            const uniquePaths = [...new Set(paths)];
            generatedUrls = buildAbsoluteUrls(origin, mode, uniquePaths);
            
            // 添加路由列表信息
            findings.push({ k: "Router Mode", v: mode });
            findings.push({ k: "Generated URLs", v: generatedUrls.length.toString() });
          } else {
            findings.push({ k: "Vue Router", v: "Not Detected" });
          }
        } else {
          findings.push({ k: "Vue", v: "Not Detected" });
        }
        
        if (out.error) {
          findings.push({ k: "Error", v: out.error });
        }
        
        renderVueFindings(findings);
        
        // 显示生成的 URL 列表
        if (generatedUrls.length > 0) {
          // 在 textarea 中显示 URL 列表
          setVueUrls(generatedUrls);
          
          // 在检测结果区域显示 URL 列表（带复制和打开按钮）
          setTimeout(() => renderVueUrlsList(generatedUrls), 100);
          
          setVueStatus(out.vueDetected ? "检测成功" : "未检测到 Vue");
        } else {
          setVueStatus(out.vueDetected ? "检测成功" : "未检测到 Vue");
        }
        
      } catch (e) {
        renderVueFindings([]);
        setVueStatus(`失败：${e.message || "unknown"}`);
      }
    });
  }

  if (vueDumpRoutesBtn) {
    vueDumpRoutesBtn.addEventListener("click", async () => {
      try {
        setVueStatus("导出中...");
        const tab = await getActiveTab();
        const origin = (() => {
          try {
            const u = new URL(tab.url || "");
            if (u.origin && u.origin !== "null") return u.origin;
            return `${u.protocol}//${u.host}`;
          } catch (_) {
            return "";
          }
        })();
        const res = await execInTabMain(tab.id, () => {
          const out = { ok: false, mode: "", base: "", paths: [], routes: [], error: "" };
          const isRouter = (r) => r && typeof r === "object" && typeof r.getRoutes === "function" && (typeof r.push === "function" || typeof r.replace === "function");
          const pickFromApp = (app) => {
            try {
              if (app && app.config && app.config.globalProperties && app.config.globalProperties.$router && isRouter(app.config.globalProperties.$router)) return app.config.globalProperties.$router;
            } catch (_) {}
            try {
              if (app && app._instance && app._instance.proxy && app._instance.proxy.$router && isRouter(app._instance.proxy.$router)) return app._instance.proxy.$router;
            } catch (_) {}
            try {
              const prov = app && app._context && app._context.provides ? app._context.provides : null;
              if (prov && typeof prov === "object") {
                for (const k of Object.keys(prov)) {
                  const v = prov[k];
                  if (isRouter(v)) return v;
                }
              }
            } catch (_) {}
            return null;
          };
          const pickFromVm = (vm) => {
            try {
              if (vm && vm.$router && isRouter(vm.$router)) return vm.$router;
            } catch (_) {}
            return null;
          };
          const getMode = (router) => {
            try {
              if (router && typeof router.mode === "string") return router.mode;
              if (router && router.options && typeof router.options.mode === "string") return router.options.mode;
              const h = router && router.options && router.options.history ? router.options.history : null;
              if (h && typeof h.createHref === "function") {
                const href = h.createHref("/");
                if (typeof href === "string" && href.includes("#")) return "hash";
              }
              return "";
            } catch (_) {
              return "";
            }
          };
          let router = null;
          try {
            const hook = window.__VUE_DEVTOOLS_GLOBAL_HOOK__;
            const apps = [];
            if (hook) {
              if (Array.isArray(hook.apps)) apps.push(...hook.apps);
              else if (hook.apps && typeof hook.apps.forEach === "function") hook.apps.forEach((a) => apps.push(a));
              if (Array.isArray(hook.appRecords)) hook.appRecords.forEach((r) => r && r.app && apps.push(r.app));
            }
            for (const app of apps) {
              router = pickFromApp(app);
              if (router) break;
            }
          } catch (_) {}
          if (!router) {
            try {
              const cand = [];
              const addEl = (el) => { if (el) cand.push(el); };
              addEl(document.querySelector("[data-v-app]"));
              addEl(document.getElementById("app"));
              addEl(document.body);
              addEl(document.documentElement);
              for (const el of cand) {
                if (!el) continue;
                const app = el.__vue_app__;
                if (app) { router = pickFromApp(app); if (router) break; }
                const vm = el.__vue__;
                if (vm) { router = pickFromVm(vm); if (router) break; }
              }
            } catch (_) {}
          }
          if (!router) {
            out.error = "未找到 router 实例";
            return out;
          }
          out.ok = true;
          out.mode = getMode(router);
          if (!out.mode) {
            const h = String(location.hash || "");
            if (h.startsWith("#/") || h.startsWith("#!/")) out.mode = "hash";
          }
          try {
            const routes = router.getRoutes();
            const arr = Array.isArray(routes) ? routes : [];
            const simplified = [];
            const paths = [];
            arr.forEach((r) => {
              const path = (r && r.path) ? String(r.path) : "";
              if (!path) return;
              const meta = (r && r.meta && typeof r.meta === "object") ? r.meta : null;
              const metaKeys = meta ? Object.keys(meta) : [];
              simplified.push({
                path,
                name: (r && r.name !== undefined && r.name !== null) ? String(r.name) : "",
                metaKeys
              });
              paths.push(path);
            });
            out.routes = simplified;
            out.paths = paths;
          } catch (e) {
            out.error = e && e.message ? e.message : "router.getRoutes 失败";
          }
          return out;
        });
        const out = res && res[0] && res[0].result ? res[0].result : null;
        if (!out || !out.ok) {
          setVueUrls("");
          setVueStatus(`失败：${out && out.error ? out.error : "unknown"}`);
          return;
        }
        const mode = out.mode === "hash" ? "hash" : "history";
        const paths = uniqueLines(out.paths || []).filter((p) => String(p || "").trim() && String(p || "").trim() !== "*");
        const absUrls = uniqueLines(buildAbsoluteUrls(origin, mode, paths));
        setVueUrls(absUrls);
        
        // 在检测结果区域显示 URL 列表（带复制和打开按钮）
        renderVueUrlsList(absUrls);
        
        setVueStatus(`完成：${absUrls.length} 条 URL（mode=${mode}）`);
      } catch (e) {
        setVueUrls("");
        setVueStatus(`失败：${e && e.message ? e.message : "unknown"}`);
      }
    });
  }

  if (vueBypassBtn) {
    vueBypassBtn.addEventListener("click", async () => {
      try {
        setVueStatus("执行绕过...");
        const tab = await getActiveTab();
        const res = await execInTabMain(tab.id, () => {
          try {
            const temp_push = Array.prototype.push;
            Array.prototype.push = function () {
              if (arguments.length === 0) return temp_push.call(this, ...arguments);
              if (typeof arguments[0] !== "function") return temp_push.call(this, ...arguments);
              let stack = new Error().stack;
              if (stack && (stack.includes("beforeEach") || stack.includes("beforeResolve"))) {
                const temp_array = String(stack).split("\n");
                if (temp_array.length < 4) return temp_push.call(this, ...arguments);
                if ((temp_array[3] && temp_array[3].includes("beforeEach")) || (temp_array[2] && temp_array[2].includes("beforeEach"))) {
                  return temp_push.call(this);
                }
                if ((temp_array[3] && temp_array[3].includes("beforeResolve")) || (temp_array[2] && temp_array[2].includes("beforeResolve"))) {
                  return temp_push.call(this);
                }
              }
              return temp_push.call(this, ...arguments);
            };
            return { ok: true };
          } catch (e) {
            return { ok: false, error: e.message || "unknown" };
          }
        });
        const out = res && res[0] && res[0].result ? res[0].result : { ok: false };
        setVueStatus(out.ok ? "完成" : `失败：${out.error || "unknown"}`);
      } catch (e) {
        setVueStatus(`Error: ${e.message}`);
      }
    });
  }

  if (vueCopyUrlsBtn) {
    vueCopyUrlsBtn.addEventListener("click", async () => {
      try {
        const text = vueUrlsEl ? (vueUrlsEl.value || "") : (state.vueUrls || "");
        const ok = await copyText(text);
        setVueStatus(ok ? "已复制" : "复制失败");
      } catch (e) {
        setVueStatus(`复制失败：${e && e.message ? e.message : "unknown"}`);
      }
    });
  }

  if (vueOpenAllBtn) {
    vueOpenAllBtn.addEventListener("click", async () => {
      try {
        const text = vueUrlsEl ? (vueUrlsEl.value || "") : (state.vueUrls || "");
        const lines = uniqueLines(String(text || "").split(/\r?\n/));
        if (!lines.length) {
          setVueStatus("无 URL 可打开");
          return;
        }
        const max = 50;
        const toOpen = lines.slice(0, max);
        for (let i = 0; i < toOpen.length; i++) {
          const url = toOpen[i];
          await new Promise((resolve) => chrome.tabs.create({ url, active: i === 0 }, () => resolve(true)));
        }
        setVueStatus(toOpen.length === lines.length ? `已打开：${toOpen.length}` : `已打开：${toOpen.length}（已截断，原始 ${lines.length}）`);
      } catch (e) {
        setVueStatus(`打开失败：${e && e.message ? e.message : "unknown"}`);
      }
    });
  }

  if (fuzzJsOpenAllBtn) {
    fuzzJsOpenAllBtn.addEventListener("click", async () => {
      try {
        const arr = state.fuzzOut && state.fuzzOut.js ? state.fuzzOut.js : [];
        const urls = arr.map(x => x.url).filter(u => u && /^https?:\/\//i.test(u));
        const uniqueUrls = [...new Set(urls)];
        if (!uniqueUrls.length) {
          fuzzJsStatus.textContent = "无 URL 可打开";
          return;
        }
        const max = 50;
        const toOpen = uniqueUrls.slice(0, max);
        for (let i = 0; i < toOpen.length; i++) {
          await new Promise(resolve => chrome.tabs.create({ url: toOpen[i], active: i === 0 }, () => resolve(true)));
        }
        const msg = toOpen.length === uniqueUrls.length ? `已打开：${toOpen.length}` : `已打开：${toOpen.length}（已截断，原始 ${uniqueUrls.length}）`;
        fuzzJsStatus.textContent = msg;
      } catch (e) {
        fuzzJsStatus.textContent = `打开失败：${e && e.message ? e.message : "unknown"}`;
      }
    });
  }

  sniffBtn.addEventListener("click", runSniff);
  fpBtn.addEventListener("click", async () => {
    try {
      const tab = await getActiveTab();
      state.tabId = tab.id;
      const [res, rules, headers, content] = await Promise.all([
        fingerprintAllFrames(state.tabId),
        loadFingerRules(),
        getHeaders(state.tabId),
        getPageContent(state.tabId)
      ]);
      const list = [];
      for (const r of res || []) {
        const arr = r.result || [];
        arr.forEach((x) => list.push(x));
      }
      const rawHeaderStr = headers.map(h => `${h.name}: ${h.value}`).join("\n");
      
      // Extract server info from headers
      headers.forEach(h => {
        const n = h.name.toLowerCase();
        const v = h.value || "";
        if (n === "server") {
          list.push({ name: "Server", version: v, source: "header" });
        } else if (n === "x-powered-by") {
          list.push({ name: "X-Powered-By", version: v, source: "header" });
        } else if (n === "via") {
          list.push({ name: "Via", version: v, source: "header" });
        } else if (n === "set-cookie") {
            if (v.includes("PHPSESSID")) list.push({ name: "PHP", version: "", source: "cookie" });
            if (v.includes("JSESSIONID")) list.push({ name: "Java", version: "", source: "cookie" });
            if (v.includes("ASP.NET_SessionId")) list.push({ name: "ASP.NET", version: "", source: "cookie" });
        }
      });

      const htmlStr = content.html;
      const titleStr = content.title;
      rules.forEach(rule => {
        let matched = false;
        const kw = rule.keyword || [];
        const keywords = Array.isArray(kw) ? kw : [kw];
        if (rule.location === "header") {
          matched = keywords.every(k => rawHeaderStr.includes(k));
        } else if (rule.location === "body") {
          matched = keywords.every(k => htmlStr.includes(k));
        } else if (rule.location === "title") {
          matched = keywords.every(k => titleStr.includes(k));
        }
        if (matched) {
          list.push({
            name: rule.cms,
            version: "",
            source: ""
          });
        }
      });
      const uniqueList = [];
      const seen = new Set();
      list.forEach(item => {
        const k = `${item.name}|${item.version}|${item.source}`;
        if (!seen.has(k)) {
          seen.add(k);
          uniqueList.push(item);
        }
      });
      renderFP(uniqueList);
    } catch (_) {
      renderFP([]);
    }
  });
  const buildRows = (out) => {
    if (!out) return [];
    const order = ["site_ip","ip","domain","url","absolute_path","relative_path","email","phone","jwt","key","crypto","sensitive"];
    const rows = [];
    order.forEach((k) => {
      const arr = Array.isArray(out[k]) ? out[k] : [];
      arr.forEach((v) => {
        const val = (v && typeof v === "object" && v.value !== undefined) ? v.value : v;
        rows.push({ type: k, value: String(val === undefined || val === null ? "" : val) });
      });
    });
    return rows;
  };
  const downloadText = (name, mime, text) => {
    try {
      const blob = new Blob([text], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        URL.revokeObjectURL(url);
        a.remove();
      }, 0);
    } catch (_) {}
  };
  exportJsonBtn.addEventListener("click", () => {
    const out = state.sniffOut || {};
    downloadText("sniff.json", "application/json;charset=utf-8", JSON.stringify(out, null, 2));
  });
  exportTxtBtn.addEventListener("click", () => {
    const out = state.sniffOut || {};
    const labels = {
      site_ip: "站点 IP",
      ip: "IP:端口",
      domain: "域名",
      url: "URL",
      absolute_path: "绝对路径",
      relative_path: "相对路径",
      email: "邮箱",
      phone: "手机号",
      jwt: "JWT",
      key: "可能的密钥",
      crypto: "加密关键词",
      sensitive: "敏感信息"
    };
    const order = ["site_ip","ip","domain","url","absolute_path","relative_path","email","phone","jwt","key","crypto","sensitive"];
    let txt = "";
    order.forEach((k) => {
      const arr = Array.isArray(out[k]) ? out[k] : [];
      txt += `== ${labels[k] || k} ==\n`;
      arr.forEach((v) => {
        const val = (v && typeof v === "object" && v.value !== undefined) ? v.value : v;
        txt += `${String(val === undefined || val === null ? "" : val)}\n`;
      });
      txt += `\n`;
    });
    downloadText("sniff.txt", "text/plain;charset=utf-8", txt);
  });
  exportCsvBtn.addEventListener("click", () => {
    const rows = buildRows(state.sniffOut || {});
    const esc = (s) => `"${String(s).replace(/"/g, '""')}"`;
    let csv = "type,value\n";
    rows.forEach((r) => { csv += `${esc(r.type)},${esc(r.value)}\n`; });
    downloadText("sniff.csv", "text/csv;charset=utf-8", csv);
  });
  exportXlsxBtn.addEventListener("click", () => {
    // 修复：使用 HTML Table 格式伪装成 .xls，解决直接将 CSV 保存为 .xlsx 导致无法打开的问题
    const rows = buildRows(state.sniffOut || {});
    
    // 构建 HTML Table
    let html = '<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel" xmlns="http://www.w3.org/TR/REC-html40">';
    html += '<head><meta charset="UTF-8"><!--[if gte mso 9]><xml><x:ExcelWorkbook><x:ExcelWorksheets><x:ExcelWorksheet><x:Name>SniffResults</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet></x:ExcelWorksheets></x:ExcelWorkbook></xml><![endif]--></head>';
    html += '<body><table>';
    html += '<tr><td>type</td><td>value</td></tr>';
    
    const escapeHtml = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    
    rows.forEach((r) => {
      html += `<tr><td>${escapeHtml(r.type)}</td><td>${escapeHtml(r.value)}</td></tr>`;
    });
    html += '</table></body></html>';

    downloadText("sniff.xls", "application/vnd.ms-excel;charset=utf-8", html);
  });

  const parseUrlBtn = q("#parseUrl");
  const queryListEl = q("#query-list");
  const hashListEl = q("#hash-list");
  const pathListEl = q("#path-list");
  const renderSimpleList = (el, items) => {
    el.textContent = "";
    const arr = Array.isArray(items) ? items : [];
    if (!arr.length) {
      const li = document.createElement("li");
      li.className = "pf-empty";
      li.textContent = "空";
      el.appendChild(li);
      return;
    }
    arr.forEach((it) => {
      const li = document.createElement("li");
      li.className = "pf-item";
      const p = document.createElement("div");
      p.className = "pf-item-primary";
      p.textContent = it.k ? `${it.k} = ${it.v}` : String(it);
      li.appendChild(p);
      el.appendChild(li);
    });
  };
  if (parseUrlBtn) {
    parseUrlBtn.addEventListener("click", async () => {
      try {
        const tab = await getActiveTab();
        state.tabId = tab.id;
        const pageUrl = await getPageUrl(state.tabId);
        const rawUrl = pageUrl || tab.url || "";
        const u = new URL(rawUrl);
        const queryItems = [];
        u.searchParams.forEach((v, k) => queryItems.push({ k, v }));
        const hash = u.hash ? u.hash.slice(1) : "";
        const hashItems = [];
        if (hash) {
          const usp = new URLSearchParams(hash);
          if ([...usp.keys()].length > 0) {
            usp.forEach((v, k) => hashItems.push({ k, v }));
          } else {
            hashItems.push({ k: "_", v: hash });
          }
        }
        const pathSegs = u.pathname.split("/").filter(Boolean);
        renderSimpleList(queryListEl, queryItems);
        renderSimpleList(hashListEl, hashItems);
        renderSimpleList(pathListEl, pathSegs);
      } catch (_) {
        renderSimpleList(queryListEl, []);
        renderSimpleList(hashListEl, []);
        renderSimpleList(pathListEl, []);
      }
    });
  }

  const encHtml = (s) => String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
    
  const decHtml = (s) => {
    const str = String(s)
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
    
    // 处理数字实体（十进制）
    return str.replace(/&#(\d+);/g, (match, dec) => {
      return String.fromCharCode(parseInt(dec, 10));
    }).replace(/&#x([0-9A-Fa-f]+);/g, (match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  };
  
  const encUrl = (s) => encodeURIComponent(String(s));
  
  const encHex = (s) => {
    const t = String(s);
    let out = "";
    for (let i = 0; i < t.length; i++) {
      const code = t.charCodeAt(i);
      if (code <= 0xFF) out += "\\x" + code.toString(16).padStart(2, "0");
      else out += "\\u" + code.toString(16).padStart(4, "0");
    }
    return out;
  };
  
  const decHex = (s) => {
    const str = String(s).replace(/\s/g, '');
    // 处理 \xHH 格式
    const decoded = str.replace(/\\x([0-9A-Fa-f]{2})/g, (match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    }).replace(/\\u([0-9A-Fa-f]{4})/g, (match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
    return decoded;
  };
  const renderEncResults = (obj) => {
    encoderListEl.textContent = "";
    const entries = Object.entries(obj || {});
    if (!entries.length) {
      const li = document.createElement("li");
      li.className = "pf-empty";
      li.textContent = "无结果";
      encoderListEl.appendChild(li);
      return;
    }
    entries.forEach(([k, v]) => {
      const li = document.createElement("li");
      li.className = "pf-item";
      const p = document.createElement("div");
      p.className = "pf-item-primary";
      p.textContent = k;
      const s = document.createElement("div");
      s.className = "pf-item-secondary";
      s.textContent = String(v);
      li.appendChild(p);
      li.appendChild(s);
      encoderListEl.appendChild(li);
    });
  };

  const runEncSingle = (mode) => {
    const t = encoderInputEl.value || "";
    let name = "", value = "";
    if (mode === "html") { name = "HTML 实体"; value = encHtml(t); }
    else if (mode === "url") { name = "URL 编码"; value = encUrl(t); }
    else if (mode === "hex") { name = "十六进制转义"; value = encHex(t); }
    renderEncResults({ [name]: value });
  };
  
  const runDecSingle = (mode) => {
    const t = encoderInputEl.value || "";
    let name = "", value = "";
    if (mode === "html") { name = "HTML 解码"; value = decHtml(t); }
    else if (mode === "hex") { name = "HEX 解码"; value = decHex(t); }
    renderEncResults({ [name]: value });
  };
  
  encHtmlBtn.addEventListener("click", () => runEncSingle("html"));
  decHtmlBtn.addEventListener("click", () => runDecSingle("html"));
  encUrlBtn.addEventListener("click", () => runEncSingle("url"));
  encHexBtn.addEventListener("click", () => runEncSingle("hex"));
  decHexBtn.addEventListener("click", () => runDecSingle("hex"));

  // Auto-select inputs
  document.querySelectorAll(".auto-select").forEach(el => {
    el.addEventListener("click", () => el.select());
  });

  // VulnRadar Functionality
  const initVulnRadar = () => {
    // Load saved states and initialize UI
    chrome.storage.local.get(['vulnradarAutoScan', 'vulnradarMasterSwitch'], (result) => {
      const states = result.vulnradarAutoScan || {};
      const masterEnabled = result.vulnradarMasterSwitch !== false; // Default true
      
      // Set master switch
      const masterSwitch = document.getElementById('vulnradar-master-switch');
      if (masterSwitch && masterEnabled) masterSwitch.classList.add('on');
      
      // Set individual switches
      document.querySelectorAll('.switch:not(.master-switch)').forEach(sw => {
        const module = sw.dataset.module;
        if (states[module]) sw.classList.add('on');
        // Disable if master is off
        if (!masterEnabled) sw.style.opacity = '0.5';
      });
    });

    // Master switch control
    const masterSwitch = document.getElementById('vulnradar-master-switch');
    if (masterSwitch) {
      masterSwitch.addEventListener('click', function() {
        this.classList.toggle('on');
        const enabled = this.classList.contains('on');
        
        // Save master switch state
        chrome.storage.local.set({ vulnradarMasterSwitch: enabled });
        
        // Enable/disable all module switches
        document.querySelectorAll('.switch:not(.master-switch)').forEach(sw => {
          sw.style.opacity = enabled ? '1' : '0.5';
          if (!enabled) {
            sw.classList.remove('on');
            const module = sw.dataset.module;
            chrome.storage.local.get(['vulnradarAutoScan'], (result) => {
              const states = result.vulnradarAutoScan || {};
              states[module] = false;
              chrome.storage.local.set({ vulnradarAutoScan: states });
            });
          }
        });
        
        console.log(`[VulnRadar 总开关] ${enabled ? '已开启' : '已关闭'}`);
      });
    }

    // Collapse functionality for results summary
    const summaryHeader = document.getElementById('vulnradar-summary-header');
    const summaryContent = document.getElementById('vulnradar-summary-content');
    if (summaryHeader && summaryContent) {
      summaryHeader.addEventListener('click', () => {
        summaryHeader.classList.toggle('collapsed');
        summaryContent.classList.toggle('collapsed');
      });
    }

    // Listen for results from content scripts
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'vulnradarScanResult') {
        const summaryContent = document.getElementById('vulnradar-summary-content');
        if (!summaryContent) return;
        
        const item = document.createElement('div');
        item.className = `summary-item ${message.severity}`;
        item.innerHTML = `
          <span>${message.module}</span>
          <span>${message.summary}</span>
        `;
        
        summaryContent.appendChild(item);
      }
    });

    // Handle "Test Now" buttons
    document.querySelectorAll('button[data-module]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const module = btn.dataset.module;
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        
        // Inject results panel first
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ['content_scripts/results-panel.js']
        }).catch(() => {});
        
        // Then inject the module
        chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: [`content_scripts/${module}.js`]
        });
      });
    });

    // Handle "Auto-Scan" toggles
    document.querySelectorAll('.switch:not(.master-switch)').forEach(sw => {
      sw.addEventListener('click', () => {
        // Check if master switch is on
        chrome.storage.local.get(['vulnradarMasterSwitch'], (result) => {
          const masterEnabled = result.vulnradarMasterSwitch !== false;
          if (!masterEnabled) {
            alert('请先开启总开关');
            return;
          }
          
          sw.classList.toggle('on');
          const module = sw.dataset.module;
          const enabled = sw.classList.contains('on');
          
          chrome.storage.local.get(['vulnradarAutoScan'], (result) => {
            const states = result.vulnradarAutoScan || {};
            states[module] = enabled;
            chrome.storage.local.set({ vulnradarAutoScan: states });
          });
        });
      });
    });
  };

  // Initialize VulnRadar when DOM is loaded
  initVulnRadar();

  // Shodan 功能
  function renderShodanHostnames(host) {
    const $hostnames = document.createElement('ul');
    host.hostnames.forEach(hostname => {
      const li = document.createElement('li');
      const a = document.createElement('a');
      a.href = 'https://' + hostname;
      a.target = '_blank';
      a.textContent = hostname;
      li.appendChild(a);
      $hostnames.appendChild(li);
    });
    return $hostnames;
  }

  function renderShodanTable(host) {
    const $items = document.getElementById('shodan-items').querySelector('tbody');
    $items.innerHTML = '';
    
    const rows = [];
    rows.push(['IP Address', host.ip]);
    
    if (host.hostnames && host.hostnames.length) {
      rows.push(['Hostname(s)', '']);
    }
    
    if (host.country_name) rows.push(['Country', host.country_name]);
    if (host.city) rows.push(['City', host.city]);
    if (host.os) rows.push(['Operating System', host.os]);
    if (host.org) rows.push(['Organization', host.org]);
    if (host.tags && host.tags.length > 0) rows.push(['Tags', host.tags.join(', ')]);
    if (host.vulns && host.vulns.length > 0) rows.push(['Vulnerabilities', host.vulns.join(', ')]);
    
    rows.forEach(row => {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td');
      const td2 = document.createElement('td');
      
      td1.textContent = row[0];
      
      if (row[0] === 'Hostname(s)') {
        td2.appendChild(renderShodanHostnames(host));
      } else {
        td2.textContent = row[1];
      }
      
      tr.appendChild(td1);
      tr.appendChild(td2);
      $items.appendChild(tr);
    });
  }

  function renderShodanPorts(host) {
    const $ports = document.getElementById('shodan-ports');
    $ports.innerHTML = '';
    
    if (!host.ports || !host.ports.length) {
      return;
    }
    
    // 排序端口
    host.ports.sort((a, b) => parseInt(a) - parseInt(b));
    
    const http_ports = [80, 8080, 81];
    const https_ports = [443, 8443];
    
    host.ports.forEach(port => {
      const li = document.createElement('li');
      let child;
      
      if (http_ports.indexOf(parseInt(port)) !== -1) {
        // HTTP port
        child = document.createElement('a');
        child.href = 'http://' + host.ip + ':' + port;
        child.target = '_blank';
        child.textContent = port;
      } else if (https_ports.indexOf(parseInt(port)) !== -1) {
        // HTTPS port
        child = document.createElement('a');
        child.href = 'https://' + host.ip + ':' + port;
        child.target = '_blank';
        child.textContent = port;
      } else {
        child = document.createElement('span');
        child.textContent = port;
      }
      
      li.appendChild(child);
      $ports.appendChild(li);
    });
  }

  function renderShodanVulns(host) {
    const $vulns = document.getElementById('shodan-vulns');
    $vulns.innerHTML = '';
    
    if (host.vulns && host.vulns.length > 0) {
      const ul = document.createElement('ul');
      host.vulns.forEach(vuln => {
        const li = document.createElement('li');
        li.textContent = vuln;
        ul.appendChild(li);
      });
      $vulns.appendChild(ul);
    }
  }

  function renderShodanPopup(data) {
    const host = data['host'];
    const hostname = data['hostname'];
    
    document.getElementById('shodan-domain').value = hostname;
    
    // 渲染主机信息表格
    renderShodanTable(host);
    
    // 渲染开放端口
    renderShodanPorts(host);
    
    // 渲染安全漏洞
    renderShodanVulns(host);
    
    // 更新 Shodan 链接
    if (host.ip) {
      document.getElementById('shodan-btn-ip-details').href = 'https://www.shodan.io/host/' + host.ip;
      document.getElementById('shodan-btn-domain-details').href = 'https://www.shodan.io/domain/' + hostname;
    }
  }

  // 当切换到 Shodan 标签页时获取主机信息
  tabs.shodan.addEventListener('click', async () => {
    switchTab('shodan');

    try {
      const tab = await getActiveTab();
      if (tab && tab.url) {
        // 发送消息到后台获取主机信息
        chrome.runtime.sendMessage({ cmd: 'getShodanHost', url: tab.url }, (response) => {
          if (response && response.host) {
            renderShodanPopup(response);
          }
        });
      }
    } catch (e) {
      console.error('Error getting Shodan host info:', e);
    }
  });

  // ============ 信息提取模块 ============

  // 标签页切换
  const tabInfoExtract = q('#tab-info-extract');
  const modInfoExtract = q('#mod-info-extract');

  if (tabInfoExtract) {
    tabInfoExtract.addEventListener('click', () => {
      switchTab('info-extract');
      loadMapHistory();
      loadCustomRegexList();
    });
  }

  // 获取当前活动标签页
  async function getActiveTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0];
  }

  // 在标签页中执行脚本
  async function execInTab(tabId, func, args = []) {
    return new Promise((resolve, reject) => {
      chrome.scripting.executeScript(
        { target: { tabId }, func, args },
        (results) => {
          if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
          } else {
            resolve(results);
          }
        }
      );
    });
  }

  // 渲染列表
  function renderExtractList(listEl, items, options = {}) {
    listEl.innerHTML = '';
    if (!items || items.length === 0) {
      const li = document.createElement('li');
      li.className = 'pf-empty';
      li.textContent = '未收集到信息';
      listEl.appendChild(li);
      return;
    }

    items.forEach(item => {
      const li = document.createElement('li');
      li.className = 'pf-item';

      // 检查是否需要高亮
      if (options.highlightKeywords && options.highlightKeywords.length > 0) {
        const lowerItem = String(item).toLowerCase();
        const shouldHighlight = options.highlightKeywords.some(kw =>
          lowerItem.includes(kw.toLowerCase())
        );
        if (shouldHighlight) {
          li.style.backgroundColor = 'rgba(214, 158, 46, 0.2)';
          li.style.borderLeft = '3px solid #d69e2e';
        }
      }

      const p = document.createElement('div');
      p.className = 'pf-item-primary';
      p.textContent = item;
      p.style.wordBreak = 'break-all';
      li.appendChild(p);
      listEl.appendChild(li);
    });
  }

  // 复制文本到剪贴板
  async function copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      return false;
    }
  }

  // 导出JSON
  function exportJson(filename, data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(url);
      a.remove();
    }, 0);
  }

  // 域名提取 - 使用增强版模块
  const extractDomainBtn = q('#extractDomain');
  const copyDomainBtn = q('#copyDomain');
  const exportDomainBtn = q('#exportDomain');
  const domainListEl = q('#domainList');
  let domainResults = [];

  if (extractDomainBtn) {
    extractDomainBtn.addEventListener('click', async () => {
      try {
        const tab = await getActiveTab();
        // 使用 info-extractor-enhanced.js 中的提取函数
        const results = await execInTab(tab.id, () => {
          // 更精确的域名正则，减少误报
          const regex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|cn|net|com\.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|io|dev|app|cloud|ai)\b/gi;
          const source = document.documentElement.outerHTML;
          const matches = source.match(regex) || [];
          
          // 过滤误报
          const filtered = matches.filter(domain => {
            const d = domain.toLowerCase();
            // 排除看起来像路径的
            if (d.includes('/')) return false;
            // 排除文件名扩展名
            if (['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.ttf', '.pdf'].some(ext => d.endsWith(ext))) return false;
            // 排除过短的
            if (d.length < 5) return false;
            // 排除连续数字
            if (/^\d+\.\d+\.\d+$/.test(d)) return false;
            return true;
          });
          
          return [...new Set(filtered)];
        });
        domainResults = results[0]?.result || [];
        renderExtractList(domainListEl, domainResults);
        copyDomainBtn.classList.toggle('pf-hidden', domainResults.length === 0);
        exportDomainBtn.classList.toggle('pf-hidden', domainResults.length === 0);
      } catch (e) {
        renderExtractList(domainListEl, []);
      }
    });
  }

  if (copyDomainBtn) {
    copyDomainBtn.addEventListener('click', async () => {
      const text = domainResults.join('\n');
      const ok = await copyToClipboard(text);
      if (ok) {
        copyDomainBtn.textContent = '已复制';
        setTimeout(() => copyDomainBtn.textContent = '复制', 1500);
      }
    });
  }

  if (exportDomainBtn) {
    exportDomainBtn.addEventListener('click', () => {
      exportJson('domains.json', domainResults);
    });
  }

  // API提取
  const extractApiBtn = q('#extractApi');
  const copyApiBtn = q('#copyApi');
  const exportApiBtn = q('#exportApi');
  const apiListEl = q('#apiList');
  let apiResults = [];

  if (extractApiBtn) {
    extractApiBtn.addEventListener('click', async () => {
      try {
        const tab = await getActiveTab();
        const results = await execInTab(tab.id, () => {
          const source = document.documentElement.outerHTML;
          const urlRegex = /https?:\/\/[^\s"'>)]+/g;
          // 排除的静态资源扩展名
          const staticExtensions = [
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'svg',
            'css', 'scss', 'less',
            'js', 'jsx', 'ts', 'tsx',
            'woff', 'woff2', 'ttf', 'otf', 'eot',
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
            'zip', 'rar', 'tar', 'gz', '7z',
            'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'm4a'
          ];
          
          const matches = source.match(urlRegex) || [];
          
          // 增强过滤逻辑
          const filtered = matches.filter(url => {
            const u = url.toLowerCase();
            // 排除静态资源
            if (staticExtensions.some(ext => u.includes('.' + ext) || u.endsWith('.' + ext))) return false;
            // 排除常见 CDN 和资源站点
            if (u.includes('googleapis.com') || u.includes('gstatic.com') || 
                u.includes('googletagmanager.com') || u.includes('analytics.google.com')) return false;
            // 排除静态目录
            if (u.includes('/static/') || u.includes('/assets/') || u.includes('/images/') || 
                u.includes('/img/') || u.includes('/css/') || u.includes('/fonts/')) return false;
            // 保留 API 特征
            return u.includes('/api/') || u.includes('/v') || 
                   u.includes('?') || (url.match(/\//g) || []).length >= 3;
          });
          
          return [...new Set(filtered)];
        });
        apiResults = results[0]?.result || [];
        renderExtractList(apiListEl, apiResults);
        copyApiBtn.classList.toggle('pf-hidden', apiResults.length === 0);
        exportApiBtn.classList.toggle('pf-hidden', apiResults.length === 0);
      } catch (e) {
        renderExtractList(apiListEl, []);
      }
    });
  }

  if (copyApiBtn) {
    copyApiBtn.addEventListener('click', async () => {
      const text = apiResults.join('\n');
      const ok = await copyToClipboard(text);
      if (ok) {
        copyApiBtn.textContent = '已复制';
        setTimeout(() => copyApiBtn.textContent = '复制', 1500);
      }
    });
  }

  if (exportApiBtn) {
    exportApiBtn.addEventListener('click', () => {
      exportJson('apis.json', apiResults);
    });
  }

  // JS文件提取
  const extractJsBtn = q('#extractJs');
  const copyJsBtn = q('#copyJs');
  const exportJsBtn = q('#exportJs');
  const jsListEl = q('#jsList');
  const highlightKeywordsEl = q('#highlightKeywords');
  let jsResults = [];

  if (extractJsBtn) {
    extractJsBtn.addEventListener('click', async () => {
      try {
        const tab = await getActiveTab();
        const results = await execInTab(tab.id, () => {
          const jsFiles = [];
          const seen = new Set();
          const scripts = document.getElementsByTagName('script');
          
          for (const script of scripts) {
            const src = script.getAttribute('src');
            if (src && src.endsWith('.js') && !src.endsWith('.map')) {
              let fullPath;
              if (src.startsWith('http')) {
                fullPath = src;
              } else if (src.startsWith('//')) {
                fullPath = window.location.protocol + src;
              } else if (src.startsWith('/')) {
                fullPath = window.location.protocol + '//' + window.location.host + src;
              } else {
                const base = window.location.href.substring(0, window.location.href.lastIndexOf('/') + 1);
                fullPath = base + src;
              }
              
              // 过滤掉 webpack 运行时和明显不是业务代码的 JS
              if (!fullPath.includes('webpack/bootstrap') && 
                  !fullPath.includes('webpack/runtime') &&
                  !fullPath.includes('hot-update.js')) {
                if (!seen.has(fullPath)) {
                  seen.add(fullPath);
                  jsFiles.push(fullPath);
                }
              }
            }
          }
          
          return [...new Set(jsFiles)];
        });
        jsResults = results[0]?.result || [];
        const keywords = highlightKeywordsEl?.value?.split(',').map(k => k.trim()).filter(k => k) || [];
        renderExtractList(jsListEl, jsResults, { highlightKeywords: keywords });
        copyJsBtn.classList.toggle('pf-hidden', jsResults.length === 0);
        exportJsBtn.classList.toggle('pf-hidden', jsResults.length === 0);
      } catch (e) {
        renderExtractList(jsListEl, []);
      }
    });
  }

  if (copyJsBtn) {
    copyJsBtn.addEventListener('click', async () => {
      const text = jsResults.join('\n');
      const ok = await copyToClipboard(text);
      if (ok) {
        copyJsBtn.textContent = '已复制';
        setTimeout(() => copyJsBtn.textContent = '复制', 1500);
      }
    });
  }

  if (exportJsBtn) {
    exportJsBtn.addEventListener('click', () => {
      exportJson('js_files.json', jsResults);
    });
  }

  // 路径提取
  const extractPathBtn = q('#extractPath');
  const copyPathBtn = q('#copyPath');
  const exportPathBtn = q('#exportPath');
  const pathExtractListEl = q('#pathExtractList');
  let pathResults = [];

  if (extractPathBtn) {
    extractPathBtn.addEventListener('click', async () => {
      try {
        const tab = await getActiveTab();
        const results = await execInTab(tab.id, () => {
          const source = document.documentElement.outerHTML;
          const pathRegex = /(?:\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]+)+/g;
          const matches = source.match(pathRegex) || [];
          
          // 排除静态资源和无效路径
          const staticExtensions = [
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'svg',
            'css', 'scss', 'less', 'js', 'jsx', 'ts', 'tsx',
            'woff', 'woff2', 'ttf', 'otf', 'eot',
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar',
            'mp3', 'mp4', 'avi', 'mov', 'flv', 'webm'
          ];
          
          const filtered = matches.filter(path => {
            const p = path.toLowerCase();
            // 排除过短的路径
            if (p.length < 3) return false;
            // 排除静态资源
            if (staticExtensions.some(ext => p.includes('.' + ext) || p.endsWith('.' + ext))) return false;
            // 排除看起来像域名的
            if (p.startsWith('//') || p.includes('://')) return false;
            // 排除包含连续数字的路径（可能是乱码）
            if (/\/\d{8,}\//.test(p)) return false;
            return true;
          });
          
          return [...new Set(filtered)];
        });
        pathResults = results[0]?.result || [];
        renderExtractList(pathExtractListEl, pathResults);
        copyPathBtn.classList.toggle('pf-hidden', pathResults.length === 0);
        exportPathBtn.classList.toggle('pf-hidden', pathResults.length === 0);
      } catch (e) {
        renderExtractList(pathExtractListEl, []);
      }
    });
  }

  if (copyPathBtn) {
    copyPathBtn.addEventListener('click', async () => {
      const text = pathResults.join('\n');
      const ok = await copyToClipboard(text);
      if (ok) {
        copyPathBtn.textContent = '已复制';
        setTimeout(() => copyPathBtn.textContent = '复制', 1500);
      }
    });
  }

  if (exportPathBtn) {
    exportPathBtn.addEventListener('click', () => {
      exportJson('paths.json', pathResults);
    });
  }

  // Cookie提取
  const extractCookieBtn = q('#extractCookie');
  const copyCookieBtn = q('#copyCookie');
  const cookieExtractListEl = q('#cookieExtractList');
  let cookieResults = [];

  if (extractCookieBtn) {
    extractCookieBtn.addEventListener('click', async () => {
      try {
        const tab = await getActiveTab();
        chrome.runtime.sendMessage({ action: 'getCookies', url: tab.url }, (response) => {
          cookieResults = response?.cookies || [];
          cookieExtractListEl.innerHTML = '';
          if (cookieResults.length === 0) {
            const li = document.createElement('li');
            li.className = 'pf-empty';
            li.textContent = '未获取到Cookie';
            cookieExtractListEl.appendChild(li);
          } else {
            cookieResults.forEach(cookie => {
              const li = document.createElement('li');
              li.className = 'pf-item';
              const p = document.createElement('div');
              p.className = 'pf-item-primary';
              p.textContent = `${cookie.name}=${cookie.value}`;
              p.style.wordBreak = 'break-all';
              li.appendChild(p);
              cookieExtractListEl.appendChild(li);
            });
          }
          copyCookieBtn.classList.toggle('pf-hidden', cookieResults.length === 0);
        });
      } catch (e) {
        cookieExtractListEl.innerHTML = '';
        const li = document.createElement('li');
        li.className = 'pf-empty';
        li.textContent = '获取失败';
        cookieExtractListEl.appendChild(li);
      }
    });
  }

  if (copyCookieBtn) {
    copyCookieBtn.addEventListener('click', async () => {
      const text = cookieResults.map(c => `${c.name}=${c.value}`).join('; ');
      const ok = await copyToClipboard(text);
      if (ok) {
        copyCookieBtn.textContent = '已复制';
        setTimeout(() => copyCookieBtn.textContent = '复制全部', 1500);
      }
    });
  }

  // Map文件提取
  const detectMapBtn = q('#detectMap');
  const clearMapHistoryBtn = q('#clearMapHistory');
  const mapResultEl = q('#mapResult');
  const mapHistoryListEl = q('#mapHistoryList');

  async function loadMapHistory() {
    chrome.storage.local.get(['mapHistory'], (result) => {
      const history = result.mapHistory || [];
      mapHistoryListEl.innerHTML = '';
      if (history.length === 0) {
        const li = document.createElement('li');
        li.className = 'pf-empty';
        li.textContent = '暂无下载记录';
        mapHistoryListEl.appendChild(li);
      } else {
        history.forEach(item => {
          const li = document.createElement('li');
          li.className = 'pf-item';
          const p = document.createElement('div');
          p.className = 'pf-item-primary';
          p.textContent = item.url.split('/').pop();
          p.style.wordBreak = 'break-all';
          const s = document.createElement('div');
          s.className = 'pf-item-secondary';
          s.textContent = new Date(item.timestamp).toLocaleString();
          li.appendChild(p);
          li.appendChild(s);
          mapHistoryListEl.appendChild(li);
        });
      }
    });
  }

  if (detectMapBtn) {
    detectMapBtn.addEventListener('click', async () => {
      try {
        mapResultEl.textContent = '检测中...';
        const tab = await getActiveTab();

        const results = await execInTab(tab.id, () => {
          const potentialUrls = [];
          const scripts = document.getElementsByTagName('script');
          for (const script of scripts) {
            const src = script.getAttribute('src');
            if (src && src.endsWith('.js')) {
              let fullUrl;
              if (src.startsWith('http')) {
                fullUrl = src;
              } else if (src.startsWith('//')) {
                fullUrl = window.location.protocol + src;
              } else if (src.startsWith('/')) {
                fullUrl = window.location.protocol + '//' + window.location.host + src;
              } else {
                const base = window.location.href.substring(0, window.location.href.lastIndexOf('/') + 1);
                fullUrl = base + src;
              }
              potentialUrls.push(fullUrl + '.map');
            }
          }
          return [...new Set(potentialUrls)];
        });

        const urls = results[0]?.result || [];
        if (urls.length === 0) {
          mapResultEl.textContent = '未找到JS文件';
          return;
        }

        const verifiedUrls = [];
        for (const url of urls) {
          try {
            const response = await fetch(url, { method: 'HEAD' });
            if (response.ok) {
              verifiedUrls.push(url);
            }
          } catch (e) {}
        }

        if (verifiedUrls.length === 0) {
          mapResultEl.textContent = '该网站暂无泄露Map文件';
        } else {
          mapResultEl.innerHTML = '';
          verifiedUrls.forEach(url => {
            const div = document.createElement('div');
            div.className = 'pf-item';
            div.style.marginBottom = '8px';

            const urlSpan = document.createElement('span');
            urlSpan.textContent = url.split('/').pop();
            urlSpan.style.wordBreak = 'break-all';
            urlSpan.style.display = 'block';
            urlSpan.style.marginBottom = '4px';

            const downloadBtn = document.createElement('button');
            downloadBtn.className = 'pf-btn';
            downloadBtn.textContent = '下载';
            downloadBtn.style.fontSize = '12px';
            downloadBtn.style.padding = '4px 8px';
            downloadBtn.addEventListener('click', () => {
              chrome.runtime.sendMessage({ action: 'downloadFile', url }, () => {
                loadMapHistory();
              });
            });

            div.appendChild(urlSpan);
            div.appendChild(downloadBtn);
            mapResultEl.appendChild(div);
          });
        }
      } catch (e) {
        mapResultEl.textContent = '检测失败';
      }
    });
  }

  if (clearMapHistoryBtn) {
    clearMapHistoryBtn.addEventListener('click', () => {
      chrome.storage.local.set({ mapHistory: [] }, () => {
        loadMapHistory();
      });
    });
  }

  // 编码解码工具
  const encodeInputEl = q('#encodeInput');
  const encodeOutputEl = q('#encodeOutput');
  const copyEncodeResultBtn = q('#copyEncodeResult');
  const clearEncodeBtn = q('#clearEncode');

  document.querySelectorAll('.encode-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.dataset.type;
      const action = btn.dataset.action;
      const input = encodeInputEl?.value || '';

      if (!input) {
        if (encodeOutputEl) encodeOutputEl.value = '请输入内容';
        return;
      }

      try {
        let result = '';
        switch (type) {
          case 'url':
            result = action === 'encode' ? encodeURIComponent(input) : decodeURIComponent(input);
            break;
          case 'base64':
            result = action === 'encode'
              ? btoa(unescape(encodeURIComponent(input)))
              : decodeURIComponent(escape(atob(input)));
            break;
          case 'hex':
            if (action === 'encode') {
              result = input.split('').map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join('');
            } else {
              result = input.match(/.{1,2}/g)?.map(byte => String.fromCharCode(parseInt(byte, 16))).join('') || '';
            }
            break;
          case 'html':
            if (action === 'encode') {
              const htmlEntities = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;'
              };
              result = input.replace(/[&<>"']/g, char => htmlEntities[char]);
            } else {
              const htmlEntities = {
                '&amp;': '&',
                '&lt;': '<',
                '&gt;': '>',
                '&quot;': '"',
                '&#39;': "'",
                '&apos;': "'"
              };
              result = input.replace(/&amp;|&lt;|&gt;|&quot;|&#39;|&apos;/g, match => htmlEntities[match]);
            }
            break;
          case 'unicode':
            if (action === 'encode') {
              result = input.split('').map(char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0')).join('');
            } else {
              result = input.replace(/\\u([\dA-Fa-f]{4})/g, (_, code) => String.fromCharCode(parseInt(code, 16)));
            }
            break;
        }
        if (encodeOutputEl) encodeOutputEl.value = result;
      } catch (e) {
        if (encodeOutputEl) encodeOutputEl.value = '操作失败: ' + e.message;
      }
    });
  });

  if (copyEncodeResultBtn) {
    copyEncodeResultBtn.addEventListener('click', async () => {
      const text = encodeOutputEl?.value || '';
      if (!text) return;
      const ok = await copyToClipboard(text);
      if (ok) {
        copyEncodeResultBtn.textContent = '已复制';
        setTimeout(() => copyEncodeResultBtn.textContent = '复制结果', 1500);
      }
    });
  }

  if (clearEncodeBtn) {
    clearEncodeBtn.addEventListener('click', () => {
      if (encodeInputEl) encodeInputEl.value = '';
      if (encodeOutputEl) encodeOutputEl.value = '';
    });
  }

  // 自定义正则提取
  const customRegexLabelEl = q('#customRegexLabel');
  const customRegexPatternEl = q('#customRegexPattern');
  const addCustomRegexBtn = q('#addCustomRegex');
  const customRegexListEl = q('#customRegexList');

  async function loadCustomRegexList() {
    chrome.storage.local.get(['customRegexPatterns'], (result) => {
      const patterns = result.customRegexPatterns || [];
      customRegexListEl.innerHTML = '';

      if (patterns.length === 0) {
        const div = document.createElement('div');
        div.className = 'pf-empty';
        div.textContent = '暂无自定义规则';
        customRegexListEl.appendChild(div);
        return;
      }

      patterns.forEach(pattern => {
        const div = document.createElement('div');
        div.className = 'pf-card';
        div.style.marginBottom = '10px';
        div.style.padding = '10px';

        const header = document.createElement('div');
        header.style.display = 'flex';
        header.style.justifyContent = 'space-between';
        header.style.alignItems = 'center';
        header.style.marginBottom = '8px';

        const label = document.createElement('strong');
        label.textContent = pattern.label;

        const btnGroup = document.createElement('div');

        const extractBtn = document.createElement('button');
        extractBtn.className = 'pf-btn';
        extractBtn.textContent = '提取';
        extractBtn.style.fontSize = '12px';
        extractBtn.style.padding = '4px 8px';
        extractBtn.style.marginRight = '5px';

        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'pf-btn';
        deleteBtn.textContent = '删除';
        deleteBtn.style.fontSize = '12px';
        deleteBtn.style.padding = '4px 8px';

        extractBtn.addEventListener('click', async () => {
          try {
            const tab = await getActiveTab();
            const results = await execInTab(tab.id, (regexPattern) => {
              try {
                const regex = new RegExp(regexPattern, 'g');
                const source = document.documentElement.outerHTML;
                const matches = source.match(regex) || [];
                return [...new Set(matches)];
              } catch (e) {
                return [];
              }
            }, [pattern.pattern]);

            const items = results[0]?.result || [];
            const resultDiv = div.querySelector('.custom-regex-result');
            if (resultDiv) {
              resultDiv.innerHTML = '';
              if (items.length === 0) {
                resultDiv.textContent = '未匹配到结果';
              } else {
                const ul = document.createElement('ul');
                ul.className = 'pf-list';
                items.forEach(item => {
                  const li = document.createElement('li');
                  li.className = 'pf-item';
                  li.textContent = item;
                  li.style.wordBreak = 'break-all';
                  ul.appendChild(li);
                });
                resultDiv.appendChild(ul);
              }
            }
          } catch (e) {
            const resultDiv = div.querySelector('.custom-regex-result');
            if (resultDiv) resultDiv.textContent = '提取失败';
          }
        });

        deleteBtn.addEventListener('click', () => {
          const filtered = patterns.filter(p => p.label !== pattern.label);
          chrome.storage.local.set({ customRegexPatterns: filtered }, () => {
            loadCustomRegexList();
          });
        });

        btnGroup.appendChild(extractBtn);
        btnGroup.appendChild(deleteBtn);
        header.appendChild(label);
        header.appendChild(btnGroup);

        const patternDiv = document.createElement('div');
        patternDiv.className = 'pf-item-secondary';
        patternDiv.textContent = pattern.pattern;
        patternDiv.style.marginBottom = '8px';
        patternDiv.style.fontFamily = 'monospace';

        const resultDiv = document.createElement('div');
        resultDiv.className = 'custom-regex-result';
        resultDiv.style.marginTop = '8px';
        resultDiv.style.maxHeight = '150px';
        resultDiv.style.overflowY = 'auto';

        div.appendChild(header);
        div.appendChild(patternDiv);
        div.appendChild(resultDiv);
        customRegexListEl.appendChild(div);
      });
    });
  }

  if (addCustomRegexBtn) {
    addCustomRegexBtn.addEventListener('click', () => {
      const label = customRegexLabelEl?.value?.trim();
      const pattern = customRegexPatternEl?.value?.trim();

      if (!label || !pattern) {
        alert('请输入规则名称和正则表达式');
        return;
      }

      try {
        new RegExp(pattern);
      } catch (e) {
        alert('无效的正则表达式');
        return;
      }

      chrome.storage.local.get(['customRegexPatterns'], (result) => {
        const patterns = result.customRegexPatterns || [];
        const existingIndex = patterns.findIndex(p => p.label === label);
        if (existingIndex >= 0) {
          patterns[existingIndex].pattern = pattern;
        } else {
          patterns.push({ label, pattern });
        }
        chrome.storage.local.set({ customRegexPatterns: patterns }, () => {
          customRegexLabelEl.value = '';
          customRegexPatternEl.value = '';
          loadCustomRegexList();
        });
      });
    });
  }

  // ============ 信息提取模块结束 ============
});
