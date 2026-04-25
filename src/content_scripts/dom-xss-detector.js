(() => {
  console.log('[DOM XSS 检测] 开始扫描...');
  
  const results = [];
  const observedElements = new Set(); // 避免重复检测
  
  // Dangerous sinks to monitor
  const sinks = {
    'innerHTML': { obj: Element.prototype, prop: 'innerHTML' },
    'outerHTML': { obj: Element.prototype, prop: 'outerHTML' },
    'insertAdjacentHTML': { obj: Element.prototype, prop: 'insertAdjacentHTML' },
    'document.write': { obj: document, prop: 'write' },
    'document.writeln': { obj: document, prop: 'writeln' },
    'eval': { obj: window, prop: 'eval' },
    'setTimeout': { obj: window, prop: 'setTimeout' },
    'setInterval': { obj: window, prop: 'setInterval' },
    'Function': { obj: window, prop: 'Function' }
  };
  
  // Dangerous sources
  const sources = [
    'location.href',
    'location.hash',
    'location.search',
    'document.URL',
    'document.documentURI',
    'document.referrer',
    'window.name'
  ];
  
  // 辅助函数：安全地获取 source 值（避免使用 eval）
  const getSourceValue = (src) => {
    try {
      switch(src) {
        case 'location.href': return location.href;
        case 'location.hash': return location.hash;
        case 'location.search': return location.search;
        case 'document.URL': return document.URL;
        case 'document.documentURI': return document.documentURI;
        case 'document.referrer': return document.referrer;
        case 'window.name': return window.name;
        default: return '';
      }
    } catch {
      return '';
    }
  };
  
  // 检查数据是否被污染
  const isTainted = (data) => {
    if (!data) return false;
    const dataStr = data.toString();
    return sources.some(src => {
      try {
        const value = getSourceValue(src);
        return value && dataStr.includes(value);
      } catch { return false; }
    });
  };
  
  // 记录 XSSFound
  const recordXSS = (sinkName, data, stack) => {
    const result = {
      sink: sinkName,
      data: data.slice(0, 100),
      tainted: '[是]',
      location: stack.split('\n')[2]?.trim() || '未知'
    };
    
    // 避免重复记录
    const key = JSON.stringify(result);
    if (!observedElements.has(key)) {
      observedElements.add(key);
      results.push(result);
      console.warn(`[DOM XSS] 在 ${sinkName} 中发现污染数据:`, data.slice(0, 100));
    }
  };
  
  // Hook dangerous sinks - 使用 Function 替代 eval
  Object.entries(sinks).forEach(([name, { obj, prop }]) => {
    const original = obj[prop];
    if (typeof original === 'function') {
      obj[prop] = new Proxy(original, {
        apply: function(target, thisArg, args) {
          const data = args[0]?.toString() || '';
          
          if (isTainted(data)) {
            const stack = new Error().stack;
            recordXSS(name, data, stack);
          }
          
          return target.apply(thisArg, args);
        }
      });
    } else {
      // For properties like innerHTML
      const descriptor = Object.getOwnPropertyDescriptor(obj, prop);
      if (descriptor?.set) {
        Object.defineProperty(obj, prop, {
          set: function(value) {
            const data = value?.toString() || '';
            
            if (isTainted(data)) {
              const stack = new Error().stack;
              recordXSS(name, data, stack);
            }
            
            return descriptor.set.call(this, value);
          },
          get: descriptor.get,
          configurable: true
        });
      }
    }
  });
  
  // 使用 MutationObserver 监听动态 DOM 变化
  const setupMutationObserver = () => {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // 检查新添加的元素是否包含潜在危险属性
              const dangerousAttrs = ['onclick', 'onerror', 'onload', 'onmouseover', 'onfocus'];
              dangerousAttrs.forEach(attr => {
                if (node.hasAttribute && node.hasAttribute(attr)) {
                  const value = node.getAttribute(attr);
                  if (isTainted(value)) {
                    recordXSS(`DOM Attribute: ${attr}`, value, new Error().stack);
                  }
                }
              });
              
              // 检查 script 标签
              if (node.tagName === 'SCRIPT' && node.textContent) {
                const xssPatterns = [
                  /<script/i, /javascript:/i, /onerror=/i, /onload=/i
                ];
                const hasXSS = xssPatterns.some(p => p.test(node.textContent));
                if (hasXSS && isTainted(node.textContent)) {
                  recordXSS('Dynamic Script', node.textContent, new Error().stack);
                }
              }
            }
          });
        }
      });
    });
    
    // 开始监听
    observer.observe(document.documentElement || document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['onclick', 'onerror', 'onload', 'onmouseover', 'onfocus', 'src', 'href']
    });
    
    console.log('[DOM XSS] MutationObserver 已启动');
  };
  
  // 启动 MutationObserver
  if (document.documentElement || document.body) {
    setupMutationObserver();
  } else {
    // 如果 DOM 还未准备好，等待加载
    window.addEventListener('DOMContentLoaded', setupMutationObserver);
  }
  
  // Check URL parameters for XSS patterns
  const urlParams = new URLSearchParams(window.location.search);
  const xssPatterns = [
    /<script/i,
    /javascript:/i,
    /onerror=/i,
    /onload=/i,
    /onclick=/i,
    /<img/i,
    /<iframe/i,
    /alert\(/i,
    /eval\(/i
  ];
  
  urlParams.forEach((value, key) => {
    const hasXSS = xssPatterns.some(pattern => pattern.test(value));
    if (hasXSS) {
      results.push({
        sink: 'URL 参数',
        data: `${key}=${value.slice(0, 80)}`,
        tainted: '[XSS 模式]',
        location: window.location.href
      });
    }
  });
  
  // Check hash for XSS patterns
  if (window.location.hash) {
    const hash = decodeURIComponent(window.location.hash);
    const hasXSS = xssPatterns.some(pattern => pattern.test(hash));
    if (hasXSS) {
      results.push({
        sink: 'URL Hash',
        data: hash.slice(0, 100),
        tainted: '[XSS 模式]',
        location: window.location.href
      });
    }
  }
  
  // 显示结果 - 延长等待时间以捕获动态内容
  setTimeout(() => {
    if (results.length > 0) {
      console.warn(`[DOM XSS] 发现 ${results.length} 个潜在 XSS 问题！`);
      console.table(results);
      
      // Alert for vulnerabilities
      const details = results.map(r => `${r.sink}: ${r.data.slice(0, 50)}...`).join('\n');
      alert(`[安全警告] 发现 ${results.length} 个 DOM XSS 漏洞！\n\n${details}\n\n详细信息请查看控制台。`);
      
      if (window.bmscanAddResult) {
        window.bmscanAddResult('DOM XSS 检测', results, {
          count: `${results.length} 个问题`,
          badgeType: 'danger'
        });
      }
      
      // Send to popup
      if (window.sendVulnRadarResult) {
        window.sendVulnRadarResult('DOM XSS 检测', `发现 ${results.length} 个漏洞`, 'danger');
      }
    } else {
      console.log('[DOM XSS] 未检测到 XSS 漏洞');
      
      if (window.bmscanAddResult) {
        window.bmscanAddResult('DOM XSS 检测', '未检测到 XSS 漏洞', {
          count: '安全',
          badgeType: 'success'
        });
      }
      
      // Send to popup
      if (window.sendVulnRadarResult) {
        window.sendVulnRadarResult('DOM XSS 检测', '未发现漏洞', 'success');
      }
    }
  }, 5000); // 延长到 5 秒以捕获更多动态内容
  
  console.log('[DOM XSS] 监控已激活，已安装钩子:', Object.keys(sinks).join(', '));
  console.log('[DOM XSS] MutationObserver 已启动，监听动态 DOM 变化');
})();
