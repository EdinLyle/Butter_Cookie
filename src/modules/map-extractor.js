// Map文件提取模块 - 检测和下载Source Map文件

// 提取潜在的Map文件URL
function extractPotentialMapUrls() {
  const potentialUrls = new Set();
  const mapFileExtensions = ['.js.map'];

  if (typeof document === 'undefined') return [];

  // 提取<script>和<link>标签中的URL
  const scripts = document.getElementsByTagName('script');
  const links = document.getElementsByTagName('link');

  // 处理<script>标签
  for (const script of scripts) {
    const src = script.getAttribute('src');
    if (src && (src.endsWith('.js') || src.endsWith('.ts') || src.endsWith('.css'))) {
      mapFileExtensions.forEach(ext => {
        const mapUrl = src.replace(/\.(js|ts|css)$/, ext);
        potentialUrls.add(resolveUrl(mapUrl));
      });
    }

    // 提取内联脚本中的sourceMappingURL
    const scriptContent = script.textContent;
    if (scriptContent) {
      const sourceMappingRegex = /\/\/\#\s*sourceMappingURL=([^\s]+)/g;
      let match;
      while ((match = sourceMappingRegex.exec(scriptContent)) !== null) {
        const mapUrl = match[1];
        potentialUrls.add(resolveUrl(mapUrl));
      }
    }
  }

  // 处理<link>标签
  for (const link of links) {
    const href = link.getAttribute('href');
    if (href && (href.endsWith('.css') || href.endsWith('.js') || href.endsWith('.ts'))) {
      mapFileExtensions.forEach(ext => {
        const mapUrl = href.replace(/\.(js|ts|css)$/, ext);
        potentialUrls.add(resolveUrl(mapUrl));
      });
    }
  }

  // 提取页面源码中的sourceMappingURL
  const source = document.documentElement.outerHTML;
  const sourceMappingRegex = /\/\/\#\s*sourceMappingURL=([^\s]+)/g;
  let match;
  while ((match = sourceMappingRegex.exec(source)) !== null) {
    const mapUrl = match[1];
    potentialUrls.add(resolveUrl(mapUrl));
  }

  return Array.from(potentialUrls);
}

// 解析相对URL为绝对URL
function resolveUrl(url) {
  if (typeof window === 'undefined') return url;
  try {
    return new URL(url, window.location.href).href;
  } catch (error) {
    console.error('Error resolving URL:', url, error);
    return url;
  }
}

// 验证Map文件是否存在（限制并发请求）
function verifyMapFiles(urls, callback) {
  const verifiedUrls = [];
  const maxConcurrent = 5;
  let currentIndex = 0;
  let activeRequests = 0;

  function processNext() {
    while (currentIndex < urls.length && activeRequests < maxConcurrent) {
      const url = urls[currentIndex];
      activeRequests++;
      currentIndex++;

      chrome.runtime.sendMessage({ action: 'checkUrl', url: url }, (response) => {
        if (response && response.exists) {
          verifiedUrls.push(url);
        }
        activeRequests--;
        if (currentIndex === urls.length && activeRequests === 0) {
          callback(verifiedUrls);
        } else {
          processNext();
        }
      });
    }
  }

  if (urls.length === 0) {
    callback(verifiedUrls);
    return;
  }

  processNext();
}

// 保存Map文件下载历史
function saveMapHistory(url, source) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['mapHistory'], (result) => {
      let history = result.mapHistory || [];
      const timestamp = new Date().toISOString();
      
      if (!history.some(item => item.url === url)) {
        history.unshift({ url, source, timestamp });
        if (history.length > 10) {
          history = history.slice(0, 10);
        }
        chrome.storage.local.set({ mapHistory: history }, () => {
          resolve(history);
        });
      } else {
        resolve(history);
      }
    });
  });
}

// 获取Map文件下载历史
function getMapHistory() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['mapHistory'], (result) => {
      resolve(result.mapHistory || []);
    });
  });
}

// 清空Map文件下载历史
function clearMapHistory() {
  return new Promise((resolve) => {
    chrome.storage.local.set({ mapHistory: [] }, () => {
      resolve();
    });
  });
}

// 下载Map文件
function downloadMapFile(url) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: 'downloadFile', url: url }, (response) => {
      if (response && response.success) {
        const source = typeof window !== 'undefined' ? window.location.href : '';
        saveMapHistory(url, source).then(() => {
          resolve({ success: true });
        });
      } else {
        resolve({ success: false, error: '下载失败' });
      }
    });
  });
}

// 导出函数
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    extractPotentialMapUrls,
    resolveUrl,
    verifyMapFiles,
    saveMapHistory,
    getMapHistory,
    clearMapHistory,
    downloadMapFile
  };
}
