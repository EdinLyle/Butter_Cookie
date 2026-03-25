(() => {
  console.log('[跨域消息追踪] 开始监控...');
  
  const events = [];
  
  // Override addEventListener to capture message listeners
  const originalAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, listener, options) {
    if (type === 'message') {
      console.log('[跨域消息追踪] 消息监听器已注册');
    }
    return originalAddEventListener.call(this, type, listener, options);
  };
  
  // Capture postMessage events
  window.addEventListener('message', (event) => {
    // Filter out wappalyzer messages
    if (event.data && typeof event.data === 'object') {
      const dataStr = JSON.stringify(event.data);
      if (dataStr.includes('wappalyzer') || dataStr.includes('Wappalyzer')) {
        return; // Skip wappalyzer messages
      }
    }
    
    const record = {
      时间戳: new Date().toISOString(),
      来源: event.origin,
      数据: typeof event.data === 'object' ? JSON.stringify(event.data) : event.data,
      源: event.source === window ? '自身' : '外部'
    };
    
    events.push(record);
    console.log('[跨域消息追踪] 捕获事件:', record);
  });
  
  // Display captured events after 5 seconds
  setTimeout(() => {
    if (events.length > 0) {
      console.log(`[跨域消息追踪] 捕获 ${events.length} 个事件`);
      console.table(events);
      
      if (window.bmscanAddResult) {
        window.bmscanAddResult('跨域消息追踪', events, {
          count: `${events.length} 个事件`,
          badgeType: 'info'
        });
      }
      
      // Send to popup
      if (window.sendVulnRadarResult) {
        window.sendVulnRadarResult('跨域消息追踪', `${events.length} 个事件`, 'success');
      }
    } else {
      console.log('[跨域消息追踪] 未捕获到事件');
      
      if (window.bmscanAddResult) {
        window.bmscanAddResult('跨域消息追踪', '未检测到 postMessage 事件', {
          count: '0 个事件',
          badgeType: 'info'
        });
      }
      
      // Send to popup
      if (window.sendVulnRadarResult) {
        window.sendVulnRadarResult('跨域消息追踪', '无事件', 'success');
      }
    }
  }, 5000);
  
  console.log('[跨域消息追踪] 监控已激活');
})();
