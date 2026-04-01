const store = {};

// 用于User-Agent头设置的规则管理
let currentUserAgentRuleId = 1;
const userAgentRules = new Map();

// Shodan 功能集成
const CACHE_HOST = {}
const HOSTNAME_REGEX = /^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/

function getHostname(url) {
  try {
    return HOSTNAME_REGEX.exec(url)[4]
  } catch(error) {
    return ""
  }
}

// Save host info to cache, and only store what is needed
function saveCache(hostname, host) {
  const keys = ['ip', 'hostnames', 'ports', 'tags', 'vulns']

  let smallerHost = {}
  keys.forEach(key => {
    if (host.hasOwnProperty(key) && host[key]) {
      // Ignore empty array
      if (Array.isArray(host[key]) && !host[key].length) {
        return
      }

      smallerHost[key] = host[key]
    }
  })

  CACHE_HOST[hostname] = smallerHost

  return smallerHost
}

function deleteCache(hostname) {
  delete CACHE_HOST[hostname]
}

function dnsLookup(hostname, callback) {
  CACHE_HOST[hostname] = 'fetching'
  
  fetch('https://geonet.shodan.io/api/dns/' + hostname)
    .then(response => response.json())
    .then(data => {
      if (data['answers']) {
        callback(data['answers'][0]['value'])
      } else {
        deleteCache(hostname)
      }
    })
    .catch(error => deleteCache(hostname))
}

function hostLookup(hostname, ip, callback) {
  fetch('https://internetdb.shodan.io/' + ip)
    .then(response => response.json())
    .then(data => {
      if (!data.error) {
        callback(data)
      } else {
        deleteCache(hostname)
      }
    })
    .catch(error => deleteCache(hostname))
}

function getShodanHostInfo(hostname, callback) {
  // Check cache first
  let cached = CACHE_HOST[hostname]
  if (cached && cached !== 'fetching') {
    callback({ hostname, host: cached })
    return
  }

  // Resolve the hostname to its IP address, which then gets passed to the actual Shodan host lookup
  dnsLookup(hostname, ip => {
    hostLookup(hostname, ip, host => {
      // Make sure we got a response back for the right IP
      if (host.ip === ip) {
        // Update the hostname cache
        host = saveCache(hostname, host)
        callback({ hostname, host })
      } else {
        // Delete "fetching" status
        deleteCache(hostname)
        callback(null)
      }
    })
  })
}

// 添加右键菜单功能
chrome.contextMenus.removeAll(() => {
  // Add the ability to search Shodan using the right-click/ context menu
  chrome.contextMenus.create({
    'id': 'search_for_link',
    'title': 'Search Shodan for link',
    'contexts': ['link']
  })

  chrome.contextMenus.create({
    'id': 'search_for_site',
    'title': 'Search Shodan for current website',
    'contexts': ['page']
  })

  chrome.contextMenus.create({
    'id': 'search_for_selection',
    'title': 'Search Shodan for "%s"',
    'contexts': ['selection']
  })

  chrome.contextMenus.onClicked.addListener((info, tab) => {
    const menuItemId = info['menuItemId']
	let query = ''

    // The user has selected some text
    if (menuItemId == 'search_for_selection') {
      query = info.selectionText
    } else {
      let checkUrl = info.linkUrl || info.pageUrl || info.frameUrl || null
      if (checkUrl) {
        let hostname = getHostname(checkUrl)

        // Strip any prepending 'www.' if present
        if (hostname.toLowerCase().indexOf('www.') === 0) {
          hostname = hostname.substring(4)
        }

        query = 'hostname:' + hostname
      }
    }

    if (query) {
      let shodanUrl = 'https://www.shodan.io/search?query=' + encodeURIComponent(query)
      chrome.tabs.create({
        'url': shodanUrl,
      })
    }
  })
});

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const tabId = details.tabId;
    if (tabId < 0) return;
    const headers = details.responseHeaders || [];
    let csp = null;
    for (const h of headers) {
      const n = (h.name || "").toLowerCase();
      if (n === "content-security-policy") {
        csp = h.value || "";
        break;
      }
    }
    store[tabId] = { 
      csp, 
      headers: headers, 
      url: details.url || "", 
      time: Date.now() 
    };
  },
  { urls: ["<all_urls>"], types: ["main_frame", "sub_frame"] },
  ["responseHeaders"]
);
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type && !message.cmd && !message.action) return;

  // 信息提取模块 - 获取Cookie
  if (message.action === 'getCookies') {
    chrome.cookies.getAll({ url: message.url }, (cookies) => {
      if (chrome.runtime.lastError) {
        console.error('Error getting cookies:', chrome.runtime.lastError);
        sendResponse({ cookies: [] });
      } else {
        sendResponse({ cookies: cookies });
      }
    });
    return true;
  }

  // 信息提取模块 - 检查URL是否存在
  if (message.action === 'checkUrl') {
    fetch(message.url, { method: 'HEAD' })
      .then(response => {
        sendResponse({ exists: response.ok });
      })
      .catch(error => {
        console.error('Error checking URL:', error);
        sendResponse({ exists: false });
      });
    return true;
  }

  // 信息提取模块 - 获取内容
  if (message.action === 'fetchContent') {
    fetch(message.url)
      .then(response => response.text())
      .then(content => {
        sendResponse({ content: content });
      })
      .catch(error => {
        console.error('Error fetching content:', error);
        sendResponse({ content: '' });
      });
    return true;
  }

  // 信息提取模块 - 下载文件
  if (message.action === 'downloadFile') {
    chrome.downloads.download({
      url: message.url,
      filename: message.url.split('/').pop(),
      conflictAction: 'uniquify'
    }, (downloadId) => {
      if (chrome.runtime.lastError) {
        console.error('Error downloading file:', chrome.runtime.lastError);
        sendResponse({ success: false });
      } else {
        sendResponse({ success: true });
      }
    });
    return true;
  }

  // Shodan 相关消息处理
  if (message.cmd === 'getShodanHost') {
    const url = message.url;
    if (url) {
      const hostname = getHostname(url);
      if (hostname) {
        getShodanHostInfo(hostname, (response) => {
          sendResponse(response);
        });
      } else {
        sendResponse(null);
      }
    } else {
      sendResponse(null);
    }
    return true;
  }
  
  if (message.type === "GET_HEADERS") {
    const tabId = message.tabId;
    const v = store[tabId] || null;
    sendResponse({ ok: !!v, data: v });
    return true;
  }
  if (message.type === "GET_CSP") {
    const tabId = message.tabId;
    const v = store[tabId] || null;
    sendResponse({ ok: !!v, data: v });
    return true;
  }
  if (message.type === "SQL_FETCH") {
    (async () => {
      try {
        const url = String(message.url || "");
        const method = String(message.method || "GET").toUpperCase();
        const headersIn = message.headers && typeof message.headers === "object" ? message.headers : {};
        const body = message.body === undefined ? undefined : String(message.body);
        const headers = {};
        let userAgent = null;
        
        Object.keys(headersIn).forEach((k) => {
          const v = headersIn[k];
          if (v === undefined || v === null) return;
          const headerName = String(k).toLowerCase();
          if (headerName === 'user-agent') {
            userAgent = String(v);
          } else {
            headers[String(k)] = String(v);
          }
        });

        // 如果有User-Agent头，设置declarativeNetRequest规则
        if (userAgent) {
          await setUserAgentRule(url, userAgent);
        }

        const start = Date.now();
        const resp = await fetch(url, {
          method,
          headers,
          body
        });
        const ms = Date.now() - start;
        const h = [];
        resp.headers.forEach((v, k) => h.push(`${k}: ${v}`));
        const text = await resp.text();
        const limit = 220000;
        const bodyOut = text.length > limit ? (text.slice(0, limit) + `\n\n...[TRUNCATED ${text.length - limit} chars]`) : text;
        
        // 清除User-Agent规则
        if (userAgent) {
          await clearUserAgentRule(url);
        }
        
        sendResponse({
          ok: true,
          meta: `${resp.status} ${resp.statusText}  |  ${ms}ms`,
          headers: h.join("\n"),
          body: bodyOut
        });
      } catch (e) {
        sendResponse({ ok: false, error: String(e && e.message ? e.message : e) });
      }
    })();
    return true;
  }
  if (message.type === "DEEP_SNIFF") {
    (async () => {
      try {
        const urls = Array.isArray(message.urls) ? message.urls : [];
        const html = typeof message.html === "string" ? message.html : "";
        const regs = {
          ip: /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b/g,
          url: /\bhttps?:\/\/[^\s"'<>]+/gi,
          domain: /\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]+\.(?:com|cn)\b/gi,
          jwt: /\beyJ[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\.[0-9A-Za-z_-]+\b/g,
          key: /\b(?:api[_-]?key|access[_-]?key|secret|token)\b\s*[:=]\s*["']?([A-Za-z0-9-_]{16,})["']?/gi,
          email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
          phone: /\b\d{11}\b/g,
          crypto: /\b(AES|RSA|MD5|SHA256|SHA-256|bcrypt)\b/gi,
          sensitive: /\b(password|passwd|pwd|username|user_name|token|access_token|id_token|auth_token)\b/gi
        };
        const out = { ip: [], url: [], absolute_path: [], relative_path: [], domain: [], jwt: [], key: [], email: [], phone: [], crypto: [], sensitive: [] };
        const decodeEntities = (s) => {
          if (!s) return s;
          let t = s.replace(/&quot;|&#x22;|&#34;/gi, '"').replace(/&apos;|&#x27;|&#39;/gi, "'").replace(/&amp;/gi, "&").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">");
          t = t.replace(/\s+/g, (m) => m);
          return t;
        };
        const cleanUrl = (raw) => {
          if (!raw) return null;
          let u = String(raw).trim();
          u = decodeEntities(u);
          u = u.replace(/^url\(\s*(['"]?)([^'")]+)\1\s*\)\s*;?$/i, "$2");
          u = u.replace(/^['"]+|['")]+$/g, "");
          const mFull = u.match(/^(https?:\/\/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)/);
          if (mFull && mFull[1]) u = mFull[1];
          u = u.replace(/[)"'`;:，。、）\]\}\>]+$/g, "");
          u = u.replace(/^([^)\s"'`,;，。、）\]\}\>]+).*$/, "$1");
          const noQuery = u.split(/[?#]/)[0];
          const extBoundary = noQuery.match(/\.(png|jpg|jpeg|gif|svg|webp|ico|css|map|woff2?|ttf|otf|eot|pdf|mp3|mp4|webm|m4a|aac|wav)\b/i);
          if (extBoundary) {
            const idx = noQuery.toLowerCase().indexOf("." + extBoundary[1].toLowerCase());
            if (idx >= 0) {
              const cut = idx + 1 + extBoundary[1].length;
              u = noQuery.slice(0, cut);
            }
          }
          const staticExt = /\.(?:png|jpg|jpeg|gif|svg|webp|ico|css|map|woff2?|ttf|otf|eot|pdf|mp3|mp4|webm|m4a|aac|wav)$/i;
          if (staticExt.test(noQuery)) return null;
          if (/^https?:\/\//i.test(u) || u.startsWith("/") || u.startsWith("./") || u.startsWith("../")) return u;
          return null;
        };

        const analyze = (text, sourceName) => {
          if (!text) return;
          const newlines = [];
          let idx = -1;
          while ((idx = text.indexOf('\n', idx + 1)) !== -1) {
            newlines.push(idx);
          }
          const findLine = (charIndex) => {
            let l = 0, r = newlines.length - 1, res = 0;
            while (l <= r) {
              const m = (l + r) >>> 1;
              if (newlines[m] < charIndex) {
                res = m + 1;
                l = m + 1;
              } else {
                r = m - 1;
              }
            }
            return res + 1;
          };
          const add = (k, val, line) => {
            out[k].push({ value: val, source: sourceName, line });
          };

          for (const k of Object.keys(regs)) {
            const matches = text.matchAll(regs[k]);
            for (const m of matches) {
              const val = m[0];
              const line = findLine(m.index);
              if (k === "domain") {
                add(k, String(val).toLowerCase(), line);
              } else if (k === "url") {
                const c = cleanUrl(val);
                if (c) add(k, c, line);
              } else {
                add(k, String(val).slice(0, 500), line);
              }
            }
          }

          const kv = /\b(password|passwd|pwd|username|user_name|token|access_token|id_token|auth_token)\b\s*[:=]\s*["']?([A-Za-z0-9._-]{4,})["']?/gi;
          for (const m of text.matchAll(kv)) {
            add("sensitive", m[0].slice(0, 500), findLine(m.index));
          }

          const processApiMatch = (matches, groupIdx) => {
            for (const m of matches) {
              if (m[groupIdx]) {
                const v = cleanUrl(m[groupIdx]);
                if (v) {
                  const line = findLine(m.index);
                  if (v.startsWith("/")) add("absolute_path", v, line);
                  else if (v.startsWith("./") || v.startsWith("../")) add("relative_path", v, line);
                  else add("url", v, line);
                }
              }
            }
          };

          processApiMatch(text.matchAll(/fetch\s*\(\s*(['"])([^'"]+)\1/gi), 2);
          processApiMatch(text.matchAll(/axios(?:\.\w+)?\s*\(\s*(['"])([^'"]+)\1/gi), 2);
          processApiMatch(text.matchAll(/xhr\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"]([^'"]+)['"]/gi), 1);
          processApiMatch(text.matchAll(/\$\.\s*ajax\s*\(\s*\{[\s\S]*?url\s*:\s*['"]([^'"]+)['"]/gi), 1);
          processApiMatch(text.matchAll(/\$\.\s*(?:get|post|put|delete)\s*\(\s*['"]([^'"]+)['"]/gi), 2);
          processApiMatch(text.matchAll(/graphql\s*['"]?endpoint['"]?\s*[:=]\s*['"]([^'"]+)['"]/gi), 1);
          processApiMatch(text.matchAll(/['"]((?:\/|\.\.?\/)[A-Za-z0-9/_\-\.]+(?:\?[^\s"'<>]*)?)['"]/g), 1);
        };

        analyze(html, "Current Page");

        for (const u of urls) {
          try {
            const resp = await fetch(u, { mode: "cors" });
            const t = await resp.text();
            analyze(t, u);
          } catch (e) {}
        }

        for (const k of Object.keys(out)) {
          const seen = new Set();
          const unique = [];
          for (const item of out[k]) {
            const key = item.value + "|" + item.source + "|" + item.line;
            if (!seen.has(key)) {
              seen.add(key);
              unique.push(item);
            }
          }
          out[k] = unique;
        }
        sendResponse({ ok: true, result: out });
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
    })();
    return true;
  }
});

// 生成唯一的规则ID
function generateRuleId() {
  return currentUserAgentRuleId++;
}

// 设置User-Agent规则
async function setUserAgentRule(url, userAgent) {
  try {
    const ruleId = generateRuleId();
    const rules = [{
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
        urlFilter: url,
        resourceTypes: ['main_frame', 'sub_frame', 'xmlhttprequest', 'fetch']
      }
    }];
    
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [],
      addRules: rules
    });
    
    userAgentRules.set(url, ruleId);
    return ruleId;
  } catch (error) {
    console.error('设置User-Agent规则失败:', error);
    return null;
  }
}

// 清除User-Agent规则
async function clearUserAgentRule(url) {
  try {
    const ruleId = userAgentRules.get(url);
    if (ruleId) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: [ruleId],
        addRules: []
      });
      userAgentRules.delete(url);
    }
  } catch (error) {
    console.error('清除User-Agent规则失败:', error);
  }
}

// VulnRadar Auto Scan Functionality
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    chrome.storage.local.get(['vulnradarAutoScan', 'vulnradarMasterSwitch'], async (result) => {
      const masterEnabled = result.vulnradarMasterSwitch !== false; // Default true
      
      // Check master switch
      if (!masterEnabled) {
        console.log('[VulnRadar] 总开关已关闭，跳过自动扫描');
        return;
      }
      
      const states = result.vulnradarAutoScan || {};
      const enabledModules = Object.entries(states).filter(([_, enabled]) => enabled);
      
      if (enabledModules.length > 0) {
        // Inject results panel first
        await chrome.scripting.executeScript({
          target: { tabId },
          files: ['src/content_scripts/results-panel.js']
        }).catch(() => {});
        
        // Then inject enabled modules
        enabledModules.forEach(([module]) => {
          chrome.scripting.executeScript({
            target: { tabId },
            files: [`src/content_scripts/${module}.js`]
          }).catch(() => {});
        });
      }
    });
  }
});
