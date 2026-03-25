(() => {
  console.log('[原型污染检测] 开始检查...');
  
  const url = new URL(window.location.href);
  const params = Array.from(url.searchParams.keys());
  
  if (params.length === 0) {
    console.log('[原型污染检测] 没有 URL 参数可测试');
    return;
  }
  
  const payloads = [
    '__proto__[polluted]',
    'constructor[prototype][polluted]',
    '__proto__.polluted'
  ];
  
  const results = [];
  
  params.forEach(param => {
    payloads.forEach(payload => {
      // Generate test URL
      const testUrl = new URL(window.location.href);
      testUrl.searchParams.set(payload, 'true');
      
      // Check if pollution occurred
      const polluted = Object.prototype.polluted !== undefined ||
                      ({}).polluted !== undefined;
      
      if (polluted) {
        results.push({
          参数: param,
          载荷: payload,
          是否脆弱: '是'
        });
        delete Object.prototype.polluted;
      } else {
        results.push({
          参数: param,
          载荷: payload,
          是否脆弱: '否'
        });
      }
    });
  });
  
  console.log(`[原型污染检测] 测试了 ${results.length} 种组合`);
  console.table(results);
  
  const vulnerable = results.filter(r => r.是否脆弱 === '是');
  if (vulnerable.length > 0) {
    console.warn(`[原型污染检测] 发现 ${vulnerable.length} 个脆弱参数`);
    alert(`[安全警告] 发现 ${vulnerable.length} 个原型污染漏洞！\n\n详细信息请查看控制台。`);
  }
  
  if (window.bmscanAddResult) {
    window.bmscanAddResult('原型污染检测', results, {
      count: vulnerable.length > 0 ? `${vulnerable.length} 个脆弱` : '无问题',
      badgeType: vulnerable.length > 0 ? 'danger' : 'success'
    });
  }
  
  // Send to popup
  if (window.sendVulnRadarResult) {
    window.sendVulnRadarResult('原型污染检测', vulnerable.length > 0 ? `发现 ${vulnerable.length} 个漏洞` : '未发现漏洞', vulnerable.length > 0 ? 'danger' : 'success');
  }
})();
