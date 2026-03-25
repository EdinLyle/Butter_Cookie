(async () => {
  console.log('[敏感目录发现] 开始扫描...');
  
  const rules = [
    { name: 'Swagger UI', method: 'GET', path: '/swagger-ui.html', check: (body, status) => status === 200 && (body.includes('swagger-ui.css') || body.includes('swagger-ui.js') || body.includes('Swagger UI')) },
    { name: 'Swagger UI', method: 'GET', path: '/swagger-ui/index.html', check: (body, status) => status === 200 && (body.includes('swagger-ui.css') || body.includes('swagger-ui.js') || body.includes('Swagger UI')) },
    { name: 'Swagger UI', method: 'GET', path: '/swagger/index.html', check: (body, status) => status === 200 && (body.includes('swagger-ui.css') || body.includes('swagger-ui.js') || body.includes('Swagger UI')) },
    { name: 'Swagger Resources', method: 'GET', path: '/swagger-resources', check: (body, status) => status === 200 && (body.includes('"swaggerVersion"') || body.includes('"location"')) },
    { name: 'Swagger Resources', method: 'GET', path: '/api/swagger-resources', check: (body, status) => status === 200 && (body.includes('"swaggerVersion"') || body.includes('"location"')) },
    { name: 'Swagger JSON', method: 'GET', path: '/v1/swagger.json', check: (body, status) => status === 200 && (body.includes('"swagger":') || body.includes('"swaggerVersion"')) },
    { name: 'Swagger JSON', method: 'GET', path: '/v2/swagger.json', check: (body, status) => status === 200 && (body.includes('"swagger":') || body.includes('"swaggerVersion"')) },
    { name: 'Swagger JSON', method: 'GET', path: '/swagger.json', check: (body, status) => status === 200 && (body.includes('"swagger":') || body.includes('"swaggerVersion"')) },
    { name: 'Swagger API Doc', method: 'GET', path: '/v2/api-docs', check: (body, status) => status === 200 && (body.includes('"swagger":') || body.includes('"openapi":')) },
    { name: 'Swagger API Doc', method: 'GET', path: '/v3/api-docs', check: (body, status) => status === 200 && (body.includes('"swagger":') || body.includes('"openapi":')) },
    { name: 'Swagger API Doc', method: 'GET', path: '/api/v2/api-docs', check: (body, status) => status === 200 && (body.includes('"swagger":') || body.includes('"openapi":')) },
    { name: 'Spring Actuator Env', method: 'GET', path: '/env', check: (body, status) => status === 200 && (body.includes('java.version') || body.includes('os.arch')) },
    { name: 'Spring Actuator Env', method: 'GET', path: '/actuator/env', check: (body, status) => status === 200 && (body.includes('java.version') || body.includes('os.arch')) },
    { name: 'Spring Actuator', method: 'GET', path: '/actuator', check: (body, status) => status === 200 && (body.includes('"health"') || body.includes('"self":{') || body.includes('"_links":')) },
    { name: 'Spring Actuator', method: 'GET', path: '/api/actuator', check: (body, status) => status === 200 && (body.includes('"health"') || body.includes('"self":{') || body.includes('"_links":')) },
    { name: 'Spring Jolokia', method: 'GET', path: '/jolokia/list', check: (body, status) => status === 200 && (body.includes('springframework') || body.includes('reloadByURL')) },
    { name: 'Spring Jolokia', method: 'GET', path: '/actuator/jolokia/list', check: (body, status) => status === 200 && (body.includes('springframework') || body.includes('reloadByURL')) },
    { name: 'Tomcat Session', method: 'GET', path: '/examples/servlets/servlet/SessionExample', check: (body, status) => body.includes('Sessions Example') || (body.includes('../sessions.html') && body.includes('SessionExample')) },
    { name: 'Tomcat Manager', method: 'GET', path: '/manager/html', check: (body, status) => body.includes('401 Unauthorized') || body.includes('403 Access Denied') || body.includes('manager-gui') },
    { name: 'Git 泄露', method: 'GET', path: '/.git/config', check: (body, status) => status === 200 && body.includes('repositoryformatversion') },
    { name: 'SVN 泄露', method: 'GET', path: '/.svn/entries', check: (body, status) => status === 200 && ((body.includes('\ndir\n') && body.includes('\nfile\n')) || body.includes('12\n')) },
    { name: 'DS_Store 泄露', method: 'GET', path: '/.DS_Store', check: (body, status) => status === 200 && body.includes('Bud1') },
    { name: 'Nacos', method: 'GET', path: '/nacos/v1/console/server/state', check: (body, status) => status === 200 && body.includes('"auth_enabled":"false"') },
    { name: 'Alibaba Druid', method: 'GET', path: '/druid/index.html', check: (body, status) => status === 200 && body.includes('Druid Stat Index') },
    { name: 'Metrics', method: 'GET', path: '/metrics', check: (body, status) => status === 200 && body.includes('# HELP node_uname_info') && body.includes('# TYPE') },
    { name: 'XXL-Job', method: 'GET', path: '/xxl-job-admin', check: (body, status) => status === 200 && body.includes('xxl-job') },
    { name: 'WWW 压缩包', method: 'GET', path: '/www.zip', check: (body, status) => status === 200 && body.length > 100 },
    { name: 'WWW 压缩包', method: 'GET', path: '/web.zip', check: (body, status) => status === 200 && body.length > 100 },
    { name: 'Bin 压缩包', method: 'GET', path: '/bin.zip', check: (body, status) => status === 200 && body.length > 100 },
    { name: 'Backup 压缩包', method: 'GET', path: '/backup.zip', check: (body, status) => status === 200 && body.length > 100 },
    { name: 'Backup 压缩包', method: 'GET', path: '/backup.tar.gz', check: (body, status) => status === 200 && body.length > 100 }
  ];
  
  console.log(`[敏感目录发现] 正在测试 ${rules.length} 个路径...`);
  
  const results = [];
  let done = 0;
  
  await Promise.all(rules.map(rule => 
    Promise.race([
      fetch(window.location.origin + rule.path, { credentials: 'omit' }).then(async res => {
        const body = await res.text();
        const matched = rule.check(body, res.status);
        
        if (matched) {
          return {
            规则: rule.name,
            路径: rule.path,
            状态: res.status,
            大小: body.length,
            结果: '[发现]'
          };
        }
        return null;
      }),
      new Promise(res => setTimeout(() => res(null), 5000))
    ]).catch(() => null).then(r => {
      done++;
      console.log(`[敏感目录发现] 进度: ${done}/${rules.length}`);
      if (r) results.push(r);
      return r;
    })
  ));
  
  console.log(`[敏感目录发现] 扫描完成: 发现 ${results.length} 个敏感路径`);
  
  if (results.length > 0) {
    console.table(results);
    // 不弹窗，只在控制台输出
  } else {
    console.log('[敏感目录发现] 未发现敏感路径');
  }
  
  // Send to panel
  if (window.bmscanAddResult) {
    window.bmscanAddResult('敏感目录发现', results.length > 0 ? results : '未发现敏感路径', {
      count: results.length > 0 ? `发现 ${results.length} 个` : '未发现',
      badgeType: results.length > 0 ? 'danger' : 'success'
    });
  }
  
  // Send to popup
  if (window.sendVulnRadarResult) {
    window.sendVulnRadarResult('敏感目录发现', results.length > 0 ? `发现 ${results.length} 个` : '未发现', results.length > 0 ? 'danger' : 'success');
  }
})();
