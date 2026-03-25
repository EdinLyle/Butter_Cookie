// Security Scanner Results Panel
(() => {
  // Create floating panel
  const panel = document.createElement('div');
  panel.id = 'bmscan-panel';
  panel.innerHTML = `
    <div class="bmscan-header">
      <div class="bmscan-traffic-lights">
        <span class="bmscan-light bmscan-close" title="关闭"></span>
        <span class="bmscan-light bmscan-minimize" title="最小化"></span>
        <span class="bmscan-light bmscan-maximize" title="最大化"></span>
      </div>
      <span class="bmscan-title">安全扫描结果</span>
      <div class="bmscan-spacer"></div>
    </div>
    <div class="bmscan-content" id="bmscan-content">
      <div class="bmscan-empty">等待扫描结果...</div>
    </div>
  `;
  
  // Inject styles
  const style = document.createElement('style');
  style.textContent = `
    #bmscan-panel {
      position: fixed;
      top: 20px;
      right: 20px;
      width: 600px;
      max-height: 80vh;
      background: white;
      border-radius: 10px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.15), 0 0 0 0.5px rgba(0,0,0,0.1);
      z-index: 2147483647;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      resize: both;
      min-width: 400px;
      min-height: 200px;
    }
    #bmscan-panel.minimized {
      max-height: 38px;
    }
    #bmscan-panel.minimized .bmscan-content {
      display: none;
    }
    .bmscan-header {
      background: #f6f6f6;
      border-bottom: 1px solid #d1d1d1;
      padding: 10px 16px;
      display: flex;
      align-items: center;
      cursor: move;
      user-select: none;
      height: 38px;
      box-sizing: border-box;
    }
    .bmscan-traffic-lights {
      display: flex;
      gap: 8px;
      margin-right: 12px;
    }
    .bmscan-light {
      width: 12px;
      height: 12px;
      border-radius: 50%;
      cursor: pointer;
      transition: all 0.2s;
    }
    .bmscan-light.bmscan-close {
      background: #ff5f57;
      border: 0.5px solid #e0443e;
    }
    .bmscan-light.bmscan-close:hover {
      background: #ff3b30;
    }
    .bmscan-light.bmscan-minimize {
      background: #ffbd2e;
      border: 0.5px solid #dea123;
    }
    .bmscan-light.bmscan-minimize:hover {
      background: #ffaa00;
    }
    .bmscan-light.bmscan-maximize {
      background: #28c840;
      border: 0.5px solid #1aab29;
    }
    .bmscan-light.bmscan-maximize:hover {
      background: #20c035;
    }
    .bmscan-title {
      font-weight: 500;
      font-size: 13px;
      color: #333;
      flex: 1;
      text-align: center;
    }
    .bmscan-spacer {
      width: 44px;
    }
    .bmscan-content {
      padding: 16px;
      overflow-y: auto;
      max-height: calc(80vh - 38px);
      font-size: 13px;
      background: white;
    }
    .bmscan-empty {
      text-align: center;
      color: #999;
      padding: 40px 20px;
    }
    .bmscan-module {
      margin-bottom: 16px;
      border: 1px solid #e5e5e5;
      border-radius: 6px;
      overflow: hidden;
    }
    .bmscan-module-header {
      background: #fafafa;
      padding: 10px 12px;
      font-weight: 500;
      font-size: 13px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #e5e5e5;
      cursor: pointer;
      user-select: none;
    }
    .bmscan-module-header:hover {
      background: #f0f0f0;
    }
    .bmscan-module-header::after {
      content: '▼';
      font-size: 10px;
      color: #999;
      transition: transform 0.2s;
    }
    .bmscan-module-header.collapsed::after {
      transform: rotate(-90deg);
    }
    .bmscan-module-body {
      padding: 12px;
      background: white;
      max-height: 400px;
      overflow-y: auto;
      transition: max-height 0.3s;
    }
    .bmscan-module-body.collapsed {
      max-height: 0;
      padding: 0;
      overflow: hidden;
    }
    .bmscan-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    .bmscan-table th {
      background: #f9f9f9;
      padding: 8px;
      text-align: left;
      font-weight: 500;
      border-bottom: 1px solid #e5e5e5;
      color: #666;
    }
    .bmscan-table td {
      padding: 8px;
      border-bottom: 1px solid #f0f0f0;
      word-break: break-all;
    }
    .bmscan-table tr:last-child td {
      border-bottom: none;
    }
    .bmscan-table tr:hover {
      background: #f9f9f9;
    }
    .bmscan-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 500;
    }
    .bmscan-badge-danger {
      background: #ffebee;
      color: #d32f2f;
    }
    .bmscan-badge-warning {
      background: #fff3e0;
      color: #f57c00;
    }
    .bmscan-badge-success {
      background: #e8f5e9;
      color: #388e3c;
    }
    .bmscan-badge-info {
      background: #e3f2fd;
      color: #1976d2;
    }
    .bmscan-test-btn {
      background: #007aff;
      color: white;
      border: none;
      padding: 4px 12px;
      border-radius: 4px;
      font-size: 11px;
      cursor: pointer;
      transition: background 0.2s;
    }
    .bmscan-test-btn:hover {
      background: #0051d5;
    }
    .bmscan-test-btn:active {
      transform: scale(0.95);
    }
  `;
  
  document.head.appendChild(style);
  document.body.appendChild(panel);
  
  // Make draggable
  let isDragging = false;
  let currentX, currentY, initialX, initialY;
  
  panel.querySelector('.bmscan-header').addEventListener('mousedown', (e) => {
    isDragging = true;
    initialX = e.clientX - panel.offsetLeft;
    initialY = e.clientY - panel.offsetTop;
  });
  
  document.addEventListener('mousemove', (e) => {
    if (isDragging) {
      e.preventDefault();
      currentX = e.clientX - initialX;
      currentY = e.clientY - initialY;
      panel.style.left = currentX + 'px';
      panel.style.top = currentY + 'px';
      panel.style.right = 'auto';
    }
  });
  
  document.addEventListener('mouseup', () => {
    isDragging = false;
  });
  
  // Controls
  panel.querySelector('.bmscan-light.bmscan-minimize').addEventListener('click', () => {
    panel.classList.toggle('minimized');
  });
  
  panel.querySelector('.bmscan-light.bmscan-close').addEventListener('click', () => {
    panel.remove();
  });
  
  panel.querySelector('.bmscan-light.bmscan-maximize').addEventListener('click', () => {
    if (panel.style.width === '90vw') {
      panel.style.width = '600px';
      panel.style.maxHeight = '80vh';
    } else {
      panel.style.width = '90vw';
      panel.style.maxHeight = '90vh';
    }
  });
  
  // Export global function to add results
  window.bmscanAddResult = (moduleName, data, options = {}) => {
    const content = document.getElementById('bmscan-content');
    const empty = content.querySelector('.bmscan-empty');
    if (empty) empty.remove();
    
    const moduleDiv = document.createElement('div');
    moduleDiv.className = 'bmscan-module';
    
    const badge = options.count ? 
      `<span class="bmscan-badge bmscan-badge-${options.badgeType || 'info'}">${options.count}</span>` : '';
    
    moduleDiv.innerHTML = `
      <div class="bmscan-module-header">
        <span>${moduleName}</span>
        ${badge}
      </div>
      <div class="bmscan-module-body" id="bmscan-${moduleName.replace(/\s/g, '-')}"></div>
    `;
    
    content.appendChild(moduleDiv);
    
    const body = moduleDiv.querySelector('.bmscan-module-body');
    const header = moduleDiv.querySelector('.bmscan-module-header');
    
    // Add collapse functionality
    header.addEventListener('click', () => {
      header.classList.toggle('collapsed');
      body.classList.toggle('collapsed');
    });
    
    if (Array.isArray(data) && data.length > 0) {
      const table = document.createElement('table');
      table.className = 'bmscan-table';
      
      const headers = Object.keys(data[0]);
      const needsTestButton = (moduleName.includes('端点发现') || moduleName.includes('敏感目录')) && (headers.includes('接口') || headers.includes('路径'));
      
      table.innerHTML = `
        <thead>
          <tr>${headers.map(h => `<th>${h}</th>`).join('')}${needsTestButton ? '<th>操作</th>' : ''}</tr>
        </thead>
        <tbody>
          ${data.map((row, idx) => `
            <tr>
              ${headers.map(h => `<td>${formatCell(row[h])}</td>`).join('')}
              ${needsTestButton ? `<td><button class="bmscan-test-btn" data-url="${row['接口'] || row['路径']}" data-idx="${idx}">测试</button></td>` : ''}
            </tr>
          `).join('')}
        </tbody>
      `;
      
      body.appendChild(table);
      
      // Add click handlers for test buttons
      if (needsTestButton) {
        table.querySelectorAll('.bmscan-test-btn').forEach(btn => {
          btn.addEventListener('click', (e) => {
            e.stopPropagation();
            let url = btn.dataset.url;
            if (!url.startsWith('http')) {
              url = window.location.origin + url;
            }
            window.open(url, '_blank');
          });
        });
      }
    } else if (typeof data === 'string') {
      body.textContent = data;
    } else {
      body.textContent = 'No data';
    }
  };
  
  // Export function to send scan results to popup
  window.sendVulnRadarResult = (module, summary, severity) => {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'vulnradarScanResult',
        module: module,
        summary: summary,
        severity: severity
      });
    }
  };
  
  function formatCell(value) {
    if (typeof value === 'string') {
      if (value.includes('⚠️')) {
        return `<span class="bmscan-badge bmscan-badge-danger">${value}</span>`;
      }
      if (value.includes('✅')) {
        return `<span class="bmscan-badge bmscan-badge-success">${value}</span>`;
      }
      if (value.length > 80) {
        return value.slice(0, 80) + '...';
      }
    }
    return value;
  }
  
  console.log('[VulnRadar] Results panel initialized');
})();
