(() => {
  console.log('[DOM XSS 检测] 开始扫描...');
  
  const results = [];
  
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
  
  // Hook dangerous sinks
  Object.entries(sinks).forEach(([name, { obj, prop }]) => {
    const original = obj[prop];
    if (typeof original === 'function') {
      obj[prop] = new Proxy(original, {
        apply: function(target, thisArg, args) {
          const data = args[0]?.toString() || '';
          const tainted = sources.some(src => {
            try {
              const value = eval(src);
              return value && data.includes(value);
            } catch { return false; }
          });
          
          if (tainted) {
            const stack = new Error().stack;
            results.push({
              危险点: name,
              数据: data.slice(0, 100),
              污染: '[是]',
              位置: stack.split('\n')[2]?.trim() || '未知'
            });
            console.warn(`[DOM XSS] 在 ${name} 中发现污染数据:`, data.slice(0, 100));
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
            const tainted = sources.some(src => {
              try {
                const srcValue = eval(src);
                return srcValue && data.includes(srcValue);
              } catch { return false; }
            });
            
            if (tainted) {
              const stack = new Error().stack;
              results.push({
                危险点: name,
                数据: data.slice(0, 100),
                污染: '[是]',
                位置: stack.split('\n')[2]?.trim() || '未知'
              });
              console.warn(`[DOM XSS] 在 ${name} 中发现污染数据:`, data.slice(0, 100));
            }
            
            return descriptor.set.call(this, value);
          },
          get: descriptor.get,
          configurable: true
        });
      }
    }
  });
  
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
        危险点: 'URL 参数',
        数据: `${key}=${value.slice(0, 80)}`,
        污染: '[XSS 模式]',
        位置: window.location.href
      });
    }
  });
  
  // Check hash for XSS patterns
  if (window.location.hash) {
    const hash = decodeURIComponent(window.location.hash);
    const hasXSS = xssPatterns.some(pattern => pattern.test(hash));
    if (hasXSS) {
      results.push({
        危险点: 'URL Hash',
        数据: hash.slice(0, 100),
        污染: '[XSS 模式]',
        位置: window.location.href
      });
    }
  }
  
  // Display results after 3 seconds
  setTimeout(() => {
    if (results.length > 0) {
      console.warn(`[DOM XSS] 发现 ${results.length} 个潜在 XSS 问题！`);
      console.table(results);
      
      // Alert for vulnerabilities
      const details = results.map(r => `${r.危险点}: ${r.数据.slice(0, 50)}...`).join('\n');
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
  }, 3000);
  
  console.log('[DOM XSS] 监控已激活，已安装钩子:', Object.keys(sinks).join(', '));
})();
