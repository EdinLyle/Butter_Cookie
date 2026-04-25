(async () => {
  console.log('[端点发现] 开始扫描...');
  
  const apis = new Set();
  
  // 智能路径标准化函数
  const normalizePath = (path) => {
    if (!path) return '';
    return path
      .replace(/\/+/g, '/')      // 双斜杠转单斜杠
      .replace(/\/$/, '')        // 移除尾部斜杠
      .replace(/[{}]/g, '')      // 移除模板变量
      .split('?')[0]             // 移除查询参数
      .toLowerCase();            // 转小写
  };
  
  // 危险路径过滤
  const isDangerousPath = (path) => {
    const dangerous = ['delete', 'remove', 'destroy', 'drop', 'truncate'];
    return dangerous.some(word => path.toLowerCase().includes(word));
  };
  
  // Extract API endpoints from scripts - 改进提取逻辑
  document.querySelectorAll('script').forEach(s => {
    const text = s.src || s.textContent || '';
    
    // Pattern 1: Quoted paths - 使用更精确的正则
    const quotedMatches = text.matchAll(/["'`](\/[a-zA-Z0-9_\-\/{}:.]+)["'`]/g);
    for (const match of quotedMatches) {
      const path = match[1];
      if (!path.includes('{') && !isDangerousPath(path)) {
        apis.add(normalizePath(path));
      }
    }
    
    // Pattern 2: API paths
    const apiMatches = text.matchAll(/\/api\/[a-zA-Z0-9_\-\/]*/g);
    for (const match of apiMatches) {
      const path = match[0];
      if (!path.includes('{') && !isDangerousPath(path)) {
        apis.add(normalizePath(path));
      }
    }
    
    // Pattern 3: Version paths
    const versionMatches = text.matchAll(/\/v\d+\/[a-zA-Z0-9_\-\/]*/g);
    for (const match of versionMatches) {
      const path = match[0];
      if (!path.includes('{') && !isDangerousPath(path)) {
        apis.add(normalizePath(path));
      }
    }
    
    // Pattern 4: Common endpoints
    const commonMatches = text.matchAll(/\/(user|admin|login|logout|register|profile|settings|config|data|list|info|detail|update|delete|create|add|edit|remove|search|query|get|post|put|patch)[a-zA-Z0-9_\-\/]*/gi);
    for (const match of commonMatches) {
      const path = match[0];
      if (!path.includes('{') && !isDangerousPath(path)) {
        apis.add(normalizePath(path));
      }
    }
  });
  
  // 转换为数组（已经在提取时过滤过了）
  const filtered = [...apis];
  
  if (filtered.length === 0) {
    console.log('[端点发现] 未发现 API');
    
    // Send empty result to panel
    if (window.bmscanAddResult) {
      window.bmscanAddResult('JS 端点发现', '未发现 API 端点', {
        count: '0 个接口',
        badgeType: 'info'
      });
    }
    
    // Send to popup
    if (window.sendVulnRadarResult) {
      window.sendVulnRadarResult('JS 端点发现', '未发现端点', 'success');
    }
    
    return;
  }
  
  // Sensitive data patterns
  const patterns = {
    '地图密钥': /webapi\.amap\.com|apis\.map\.qq\.com|api\.map\.baidu\.com|map\.qq\.com|restapi\.amap\.com/g,
    '身份证': /[^0-9]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3})|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))[^0-9]/g,
    '密码': /((|'|")(|[\w]{1,10})([p](ass|wd|asswd|assword))(|[\w]{1,10})(|'|")(:|=)( |)('|")(.*?)('|")(|,))/gi,
    '认证': /((basic [a-z0-9=:_\+\/-]{5,100})|(bearer [a-z0-9_.=:_\+\/-]{5,100}))/gi,
    'AK泄露': /((access_key|access_token|admin_pass|api_key|api_secret|aws_access|aws_secret|password|token|secret)[a-z0-9_ .\-,]{0,25})(=|>|:=|:).{0,5}['"]([0-9a-zA-Z\-_=]{8,64})['"]/gi,
    'Key泄露': /(GOOG[\w\W]{10,30}|AZ[A-Za-z0-9]{34,40}|AKID[A-Za-z0-9]{13,20}|AKIA[A-Za-z0-9]{16}|LTAI[A-Za-z0-9]{12,20})/g
  };
  
  console.log(`[端点发现] 正在测试 ${filtered.length} 个 API...`);
  
  const results = [];
  let done = 0;
  
  // 403 bypass techniques - 新增更多绕过方法
  const bypassMethods = [
    { name: '原始', modify: url => url },
    { name: '尾部斜杠', modify: url => url + '/' },
    { name: '双斜杠', modify: url => url.replace(/\/([^\/])/, '//$1') },
    { name: '大小写', modify: url => url.replace(/\/([a-z])/g, (m, c) => '/' + c.toUpperCase()) },
    { name: '点斜杠', modify: url => url + '/.' },
    { name: '分号', modify: url => url + ';' },
    { name: 'URL 编码', modify: url => url.replace(/\//g, '%2f') },
    { name: '请求头', modify: url => url, headers: { 'X-Original-URL': '', 'X-Rewrite-URL': '' } },
    // 新增绕过技术
    { name: 'X-Custom-IP', modify: url => url, headers: { 'X-Custom-IP-Authorization': '127.0.0.1' } },
    { name: 'X-Forwarded-Host', modify: url => url, headers: { 'X-Forwarded-Host': 'localhost' } },
    { name: 'Mid-0xff', modify: url => url.replace(/\/([^\/])/, '/%2e%2f%2f$1') },
    { name: '参数污染', modify: url => url + '?url=' + encodeURIComponent(url) },
    { name: 'FTP 覆盖', modify: url => url.replace(/^https?:/, 'ftp:') },
    { name: 'Unicode 编码', modify: url => url.replace(/\//g, '/%u002f') },
    { name: '双重 URL 编码', modify: url => url.replace(/\//g, '%252f') },
    { name: '反向代理绕过', modify: url => url + '/..;/;st0' }
  ];
  
  // Test API with 403 bypass
  async function testAPI(url) {
    const testUrl = url.startsWith('http') ? url : window.location.origin + url;
    
    try {
      const res = await Promise.race([
        fetch(testUrl, { credentials: 'omit' }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout')), 5000))
      ]);
      
      // If 403, try bypass methods
      if (res.status === 403) {
        console.log(`[端点发现] 检测到 403: ${url}，尝试绕过...`);
        
        for (const method of bypassMethods.slice(1)) { // Skip original
          try {
            const bypassUrl = method.modify(testUrl);
            const bypassRes = await fetch(bypassUrl, { 
              credentials: 'omit',
              headers: method.headers || {}
            });
            
            if (bypassRes.status !== 403) {
              console.log(`[端点发现] 绕过成功: ${method.name}`);
              return await processResponse(bypassRes, url, method.name);
            }
          } catch {}
        }
      }
      
      return await processResponse(res, url, '-');
    } catch (e) {
      return {
        接口: url,
        状态: e.message.includes('Timeout') ? '超时' :
                e.message.includes('CORS') ? 'CORS' : 
                e.message.includes('Failed') ? '网络错误' : '错误',
        类型: '-',
        大小: 0,
        敏感数据: '-',
        绕过: '-'
      };
    }
  }
  
  // Process response and check for sensitive data
  async function processResponse(res, url, bypassMethod) {
    const ct = res.headers.get('content-type') || '';
    const data = await res.text();
    const found = [];
    
    Object.keys(patterns).forEach(k => {
      const m = data.match(patterns[k]);
      if (m) found.push(`${k}: ${m.slice(0, 2).join('; ')}`);
    });
    
    return {
      接口: url,
      状态: res.status,
      类型: ct.includes('json') ? 'JSON' : ct.includes('html') ? 'HTML' : '文本',
      大小: data.length,
      敏感数据: found.join(' | ') || '-',
      绕过: bypassMethod !== '-' ? `[成功] ${bypassMethod}` : '-'
    };
  }
  
  // Test all APIs in parallel with timeout
  await Promise.all(filtered.map(p => 
    testAPI(p).then(r => {
      results.push(r);
      console.log(`[端点发现] 进度: ${++done}/${filtered.length}`);
      return r;
    })
  ));
  
  // Sort by sensitive data first
  results.sort((a, b) => 
    (b.敏感数据 !== '-' ? 1 : 0) - (a.敏感数据 !== '-' ? 1 : 0)
  );
  
  console.table(results);
  
  const sensitiveCount = results.filter(r => r.敏感数据 !== '-').length;
  const bypassCount = results.filter(r => r.绕过 !== '-').length;
  
  if (sensitiveCount > 0) {
    console.warn(`[端点发现] 发现 ${sensitiveCount} 个接口包含敏感数据！`);
    alert(`[安全警告] 发现 ${sensitiveCount} 个接口包含敏感数据！\n\n详细信息请查看控制台。`);
  }
  
  if (bypassCount > 0) {
    console.warn(`[端点发现] 成功绕过 ${bypassCount} 个 403 限制！`);
    console.log(`绕过详情：\n${results.filter(r => r.绕过 !== '-').map(r => `${r.接口}: ${r.绕过}`).join('\n')}`);
  }
  
  console.log(`[端点发现] 扫描完成: 共测试 ${results.length} 个接口`);
  
  // Send to panel
  if (window.bmscanAddResult) {
    window.bmscanAddResult('JS 端点发现', results, {
      count: `${results.length} 个接口`,
      badgeType: sensitiveCount > 0 ? 'danger' : 'success'
    });
  }
  
  // Send to popup
  if (window.sendVulnRadarResult) {
    window.sendVulnRadarResult('JS 端点发现', sensitiveCount > 0 ? `发现 ${sensitiveCount} 个敏感数据` : `${results.length} 个接口`, sensitiveCount > 0 ? 'danger' : 'success');
  }
})();
