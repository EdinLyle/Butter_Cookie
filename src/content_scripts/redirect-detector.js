(() => {
  console.log('[重定向检测] 开始扫描...');
  
  const results = [];
  
  // Common redirect parameter names
  const redirectParams = [
    'redirect', 'url', 'return', 'returnUrl', 'next', 'goto', 'target',
    'callback', 'continue', 'dest', 'destination', 'redir', 'redirect_uri',
    'jump', 'link', 'to', 'from', 'ref', 'out', 'view', 'logout'
  ];
  
  // Decode URL value (handle multiple encoding)
  function decodeValue(value) {
    let decoded = value;
    try {
      decoded = decodeURIComponent(value);
      // Try double decode
      const doubleDecoded = decodeURIComponent(decoded);
      if (doubleDecoded !== decoded) {
        return { value: doubleDecoded, encoding: '双重编码' };
      }
      if (decoded !== value) {
        return { value: decoded, encoding: 'URL编码' };
      }
    } catch {}
    return { value, encoding: '无' };
  }
  
  // Check if value looks like a URL
  function isURLLike(value) {
    const patterns = [
      { pattern: /^https?:\/\//i, type: '完整URL' },
      { pattern: /^\/\//, type: '协议相对URL' },
      { pattern: /^\/[a-z0-9_\-]/i, type: '路径' },
      { pattern: /^[a-z0-9.-]+\.[a-z]{2,}/i, type: '域名' },
      { pattern: /javascript:/i, type: 'JavaScript协议' },
      { pattern: /data:/i, type: 'Data协议' }
    ];
    
    for (const { pattern, type } of patterns) {
      if (pattern.test(value)) return type;
    }
    return null;
  }
  
  // Generate test payloads
  function generatePayloads() {
    return [
      { payload: 'https://baidu.com', desc: '完整URL' },
      { payload: '//baidu.com', desc: '协议相对' },
      { payload: '/\\baidu.com', desc: '反斜杠绕过' },
      { payload: 'http%3A%2F%2Fbaidu.com', desc: 'URL编码' },
      { payload: '%2F%2Fbaidu.com', desc: '编码协议相对' }
    ];
  }
  
  // Parse URL parameters
  const urlParams = new URLSearchParams(window.location.search);
  
  urlParams.forEach((value, key) => {
    const { value: decodedValue, encoding } = decodeValue(value);
    const urlType = isURLLike(decodedValue);
    
    const nameMatch = redirectParams.includes(key.toLowerCase());
    const valueMatch = urlType !== null;
    
    if (nameMatch || valueMatch) {
      let level = '低';
      let reason = [];
      
      if (nameMatch) reason.push('参数名匹配');
      if (valueMatch) reason.push(`参数值: ${urlType}`);
      
      if (nameMatch && valueMatch) level = '高';
      else if (valueMatch) level = '中';
      
      const payloads = generatePayloads();
      
      results.push({
        参数: key,
        原始值: value.slice(0, 50),
        解码值: decodedValue.slice(0, 50),
        编码: encoding,
        匹配原因: reason.join(' + '),
        危险等级: level,
        测试Payload: payloads[0].payload
      });
    }
  });
  
  // Hook redirect functions
  const redirects = [];
  
  const originalLocationSetter = Object.getOwnPropertyDescriptor(window, 'location').set;
  Object.defineProperty(window, 'location', {
    set: function(value) {
      redirects.push({ type: 'location', target: value });
      console.warn('[重定向检测] 检测到跳转:', value);
      return originalLocationSetter.call(window, value);
    },
    get: function() {
      return window.location;
    }
  });
  
  const originalHrefDescriptor = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
  Object.defineProperty(Location.prototype, 'href', {
    set: function(value) {
      redirects.push({ type: 'location.href', target: value });
      console.warn('[重定向检测] 检测到跳转:', value);
      return originalHrefDescriptor.set.call(this, value);
    },
    get: originalHrefDescriptor.get,
    configurable: true
  });
  
  ['replace', 'assign'].forEach(method => {
    const original = Location.prototype[method];
    Location.prototype[method] = new Proxy(original, {
      apply: function(target, thisArg, args) {
        redirects.push({ type: `location.${method}`, target: args[0] });
        console.warn(`[重定向检测] 检测到跳转 (${method}):`, args[0]);
        return target.apply(thisArg, args);
      }
    });
  });
  
  // Display results after 2 seconds
  setTimeout(() => {
    if (results.length > 0) {
      console.warn(`[重定向检测] 发现 ${results.length} 个可疑重定向参数！`);
      console.table(results);
      
      const highRisk = results.filter(r => r.危险等级 === '高');
      if (highRisk.length > 0) {
        const details = highRisk.map(r => `${r.参数}=${r.解码值.slice(0, 30)}...`).join('\n');
        alert(`[安全警告] 发现 ${highRisk.length} 个高危重定向漏洞！\n\n${details}\n\n详细信息请查看控制台。`);
      }
      
      if (window.bmscanAddResult) {
        window.bmscanAddResult('重定向漏洞检测', results, {
          count: `发现 ${results.length} 个`,
          badgeType: highRisk.length > 0 ? 'danger' : 'warning'
        });
      }
      
      if (window.sendVulnRadarResult) {
        window.sendVulnRadarResult('重定向漏洞检测', highRisk.length > 0 ? `发现 ${highRisk.length} 个高危` : `发现 ${results.length} 个可疑`, highRisk.length > 0 ? 'danger' : 'warning');
      }
    } else {
      console.log('[重定向检测] 未发现可疑重定向参数');
      
      if (window.bmscanAddResult) {
        window.bmscanAddResult('重定向漏洞检测', '未发现可疑重定向参数', {
          count: '安全',
          badgeType: 'success'
        });
      }
      
      if (window.sendVulnRadarResult) {
        window.sendVulnRadarResult('重定向漏洞检测', '未发现漏洞', 'success');
      }
    }
    
    if (redirects.length > 0) {
      console.log(`[重定向检测] 监控到 ${redirects.length} 次跳转行为`);
      console.table(redirects);
    }
  }, 2000);
  
  console.log('[重定向检测] 监控已激活，正在分析 URL 参数...');
})();
