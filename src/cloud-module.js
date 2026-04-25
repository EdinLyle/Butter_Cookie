// ============ 云存储检测模块 ============

// DOM 元素引用
let cloudScanBtn, cloudRefreshBtn, cloudExportBtn;
let cloudStatUrls, cloudStatVulns, cloudStatVendors;
let cloudLoading, cloudResultList, cloudNoResult;
let cloudHistoryList, cloudHistoryEmpty, cloudHistoryPrev, cloudHistoryNext, cloudHistoryClear;
let cloudFilterVendor, cloudFilterLevel;
let cloudWhitelistInput, cloudWhitelistAdd, cloudWhitelist;
let cloudBlacklistInput, cloudBlacklistAdd, cloudBlacklist;
let cloudListsContainer, cloudSettingsToggle, cloudSettingsContainer;
let cloudSafetyMode, cloudDetectAcl, cloudDetectPolicy, cloudBacktrack, cloudPageScan;
let cloudScanDepth, cloudExternalJsLimit, cloudInlineJsLimit, cloudFileMaxSize, cloudUrlMaxCount;
let cloudResetSettings, cloudResetPerformance;

// 状态
let cloudHistoryPage = 1;
const cloudHistoryPageSize = 20;
let cloudCurrentResults = [];

// 默认配置
const DEFAULT_CLOUD_CONFIG = {
  // 检测策略
  safetyMode: false,
  detectAcl: true,
  detectPolicy: true,
  backtrack: false,
  pageScan: false,
  // 高级性能设置
  scanDepth: 40,
  externalJsLimit: 20,
  inlineJsLimit: 10,
  fileMaxSize: 1024,
  urlMaxCount: 60
};

let cloudConfig = { ...DEFAULT_CLOUD_CONFIG };

async function initCloudStorageModule() {
  // 获取 DOM 元素
  cloudScanBtn = document.getElementById('cloud-scan-now');
  cloudRefreshBtn = document.getElementById('cloud-refresh');
  cloudExportBtn = document.getElementById('cloud-export');
  cloudStatUrls = document.getElementById('cloud-stat-urls');
  cloudStatVulns = document.getElementById('cloud-stat-vulns');
  cloudStatVendors = document.getElementById('cloud-stat-vendors');
  cloudLoading = document.getElementById('cloud-loading');
  cloudResultList = document.getElementById('cloud-result-list');
  cloudNoResult = document.getElementById('cloud-no-result');
  cloudHistoryList = document.getElementById('cloud-history-list');
  cloudHistoryEmpty = document.getElementById('cloud-history-empty');
  cloudHistoryPrev = document.getElementById('cloud-history-prev');
  cloudHistoryNext = document.getElementById('cloud-history-next');
  cloudHistoryClear = document.getElementById('cloud-history-clear');
  cloudFilterVendor = document.getElementById('cloud-filter-vendor');
  cloudFilterLevel = document.getElementById('cloud-filter-level');
  cloudWhitelistInput = document.getElementById('cloud-whitelist-input');
  cloudWhitelistAdd = document.getElementById('cloud-whitelist-add');
  cloudWhitelist = document.getElementById('cloud-whitelist');
  cloudBlacklistInput = document.getElementById('cloud-blacklist-input');
  cloudBlacklistAdd = document.getElementById('cloud-blacklist-add');
  cloudBlacklist = document.getElementById('cloud-blacklist');
  cloudListsContainer = document.getElementById('cloud-lists-container');
  cloudSettingsToggle = document.getElementById('cloud-settings-toggle');
  cloudSettingsContainer = document.getElementById('cloud-settings-container');
  
  // 检测策略元素
  cloudSafetyMode = document.getElementById('cloud-safety-mode');
  cloudDetectAcl = document.getElementById('cloud-detect-acl');
  cloudDetectPolicy = document.getElementById('cloud-detect-policy');
  cloudBacktrack = document.getElementById('cloud-backtrack');
  cloudPageScan = document.getElementById('cloud-page-scan');
  
  // 高级性能设置元素
  cloudScanDepth = document.getElementById('cloud-scan-depth');
  cloudExternalJsLimit = document.getElementById('cloud-external-js-limit');
  cloudInlineJsLimit = document.getElementById('cloud-inline-js-limit');
  cloudFileMaxSize = document.getElementById('cloud-file-max-size');
  cloudUrlMaxCount = document.getElementById('cloud-url-max-count');
  
  // 重置按钮
  cloudResetSettings = document.getElementById('cloud-reset-settings');
  cloudResetPerformance = document.getElementById('cloud-reset-performance');

  // 绑定事件
  if (cloudScanBtn) {
    cloudScanBtn.addEventListener('click', () => performCloudScan());
  }
  if (cloudRefreshBtn) {
    cloudRefreshBtn.addEventListener('click', () => loadCloudResults());
  }
  if (cloudExportBtn) {
    cloudExportBtn.addEventListener('click', () => exportCloudResults());
  }

  if (cloudHistoryPrev) {
    cloudHistoryPrev.addEventListener('click', () => loadCloudHistory(cloudHistoryPage - 1));
  }
  if (cloudHistoryNext) {
    cloudHistoryNext.addEventListener('click', () => loadCloudHistory(cloudHistoryPage + 1));
  }
  if (cloudHistoryClear) {
    cloudHistoryClear.addEventListener('click', () => clearCloudHistory());
  }
  if (cloudFilterVendor || cloudFilterLevel) {
    [cloudFilterVendor, cloudFilterLevel].forEach(el => {
      if (el) el.addEventListener('change', () => loadCloudHistory(1));
    });
  }

  if (cloudWhitelistAdd) {
    cloudWhitelistAdd.addEventListener('click', () => addToCloudWhitelist());
  }
  if (cloudBlacklistAdd) {
    cloudBlacklistAdd.addEventListener('click', () => addToCloudBlacklist());
  }
  if (cloudSettingsToggle) {
    cloudSettingsToggle.addEventListener('click', () => toggleCloudSettings());
  }
  if (cloudResetSettings) {
    cloudResetSettings.addEventListener('click', () => resetCloudSettings());
  }
  if (cloudResetPerformance) {
    cloudResetPerformance.addEventListener('click', () => resetCloudPerformance());
  }
  
  // 绑定开关切换事件
  bindSwitchEvent(cloudSafetyMode, 'safetyMode');
  bindSwitchEvent(cloudDetectAcl, 'detectAcl');
  bindSwitchEvent(cloudDetectPolicy, 'detectPolicy');
  bindSwitchEvent(cloudBacktrack, 'backtrack');
  bindSwitchEvent(cloudPageScan, 'pageScan');
  
  // 绑定输入框事件
  bindInputEvent(cloudScanDepth, 'scanDepth', 10, 100);
  bindInputEvent(cloudExternalJsLimit, 'externalJsLimit', 10, 100);
  bindInputEvent(cloudInlineJsLimit, 'inlineJsLimit', 5, 50);
  bindInputEvent(cloudFileMaxSize, 'fileMaxSize', 100, 5000);
  bindInputEvent(cloudUrlMaxCount, 'urlMaxCount', 20, 200);

  // 加载初始数据
  await loadCloudConfig();
  loadCloudResults();
  loadCloudHistory(1);
  loadCloudLists(true); // 初始加载时自动展开如果有数据

  // 监听消息
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'CLOUD_STORAGE_VULNERABILITY_DETECTED') {
      loadCloudResults();
    }
  });
}

// 绑定开关事件
function bindSwitchEvent(switchEl, configKey) {
  if (!switchEl) return;
  const initialState = cloudConfig[configKey];
  if (initialState) {
    switchEl.classList.add('switch-active');
  }
  switchEl.addEventListener('click', () => {
    const isActive = switchEl.classList.toggle('switch-active');
    cloudConfig[configKey] = isActive;
    saveCloudConfig();
  });
}

// 绑定输入框事件
function bindInputEvent(inputEl, configKey, min, max) {
  if (!inputEl) return;
  
  let defaultValue = cloudConfig[configKey];
  inputEl.value = defaultValue || '';
  inputEl.placeholder = `Default: ${defaultValue}`;
  
  inputEl.addEventListener('change', () => {
    let value = parseInt(inputEl.value, 10);
    if (isNaN(value)) {
      value = defaultValue;
    } else {
      value = Math.max(min, Math.min(max, value));
    }
    inputEl.value = value;
    cloudConfig[configKey] = value;
    saveCloudConfig();
  });
}

// 加载配置
async function loadCloudConfig() {
  try {
    const result = await new Promise(resolve => {
      chrome.storage.local.get(['cloud_storage_config'], resolve);
    });
    
    if (result.cloud_storage_config) {
      cloudConfig = { ...DEFAULT_CLOUD_CONFIG, ...result.cloud_storage_config };
    }
    
    // 更新 UI
    updateCloudConfigUI();
  } catch (error) {
    console.error('[云存储] 加载配置失败:', error);
  }
}

// 更新配置 UI
function updateCloudConfigUI() {
  // 更新开关
  const switches = {
    safetyMode: cloudSafetyMode,
    detectAcl: cloudDetectAcl,
    detectPolicy: cloudDetectPolicy,
    backtrack: cloudBacktrack,
    pageScan: cloudPageScan
  };
  
  Object.keys(switches).forEach(key => {
    if (switches[key]) {
      if (cloudConfig[key]) {
        switches[key].classList.add('switch-active');
      } else {
        switches[key].classList.remove('switch-active');
      }
    }
  });
  
  // 更新输入框
  const inputs = {
    scanDepth: cloudScanDepth,
    externalJsLimit: cloudExternalJsLimit,
    inlineJsLimit: cloudInlineJsLimit,
    fileMaxSize: cloudFileMaxSize,
    urlMaxCount: cloudUrlMaxCount
  };
  
  Object.keys(inputs).forEach(key => {
    if (inputs[key]) {
      let defaultVal = DEFAULT_CLOUD_CONFIG[key];
      let currentVal = cloudConfig[key];
      inputs[key].value = currentVal !== undefined ? currentVal : '';
      inputs[key].placeholder = `Default: ${defaultVal}`;
    }
  });
}

// 保存配置
async function saveCloudConfig() {
  try {
    await new Promise(resolve => {
      chrome.storage.local.set({ cloud_storage_config: cloudConfig }, resolve);
    });
  } catch (error) {
    console.error('[云存储] 保存配置失败:', error);
  }
}

// 重置设置
async function resetCloudSettings() {
  if (!confirm('确定要重置检测策略设置吗？')) return;
  
  cloudConfig.safetyMode = DEFAULT_CLOUD_CONFIG.safetyMode;
  cloudConfig.detectAcl = DEFAULT_CLOUD_CONFIG.detectAcl;
  cloudConfig.detectPolicy = DEFAULT_CLOUD_CONFIG.detectPolicy;
  cloudConfig.backtrack = DEFAULT_CLOUD_CONFIG.backtrack;
  cloudConfig.pageScan = DEFAULT_CLOUD_CONFIG.pageScan;
  
  await saveCloudConfig();
  updateCloudConfigUI();
  alert('检测策略设置已恢复默认！');
}

// 重置性能设置
async function resetCloudPerformance() {
  if (!confirm('确定要重置性能设置吗？')) return;
  
  cloudConfig.scanDepth = DEFAULT_CLOUD_CONFIG.scanDepth;
  cloudConfig.externalJsLimit = DEFAULT_CLOUD_CONFIG.externalJsLimit;
  cloudConfig.inlineJsLimit = DEFAULT_CLOUD_CONFIG.inlineJsLimit;
  cloudConfig.fileMaxSize = DEFAULT_CLOUD_CONFIG.fileMaxSize;
  cloudConfig.urlMaxCount = DEFAULT_CLOUD_CONFIG.urlMaxCount;
  
  await saveCloudConfig();
  updateCloudConfigUI();
  alert('性能设置已恢复默认！');
}

// 执行扫描
async function performCloudScan() {
  if (!cloudLoading || !cloudResultList) return;

  cloudLoading.classList.remove('pf-hidden');
  cloudResultList.innerHTML = '';
  cloudNoResult.classList.add('pf-hidden');

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) throw new Error('无法获取当前标签页');

    // 发送扫描请求到 content script
    chrome.tabs.sendMessage(tab.id, { type: 'CLOUD_STORAGE_SCAN_REQUEST' }, (response) => {
      if (chrome.runtime.lastError) {
        showError('请刷新页面后重试');
        return;
      }

      if (response && response.success) {
        loadCloudResults();
      } else {
        showError('扫描失败：' + (response?.error || '未知错误'));
      }
    });
  } catch (error) {
    showError('扫描失败：' + error.message);
  } finally {
    setTimeout(() => {
      cloudLoading?.classList.add('pf-hidden');
    }, 500);
  }
}

// 加载检测结果
async function loadCloudResults() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    chrome.tabs.sendMessage(tab.id, { type: 'CLOUD_STORAGE_GET_URLS' }, async (response) => {
      if (response && response.success) {
        cloudCurrentResults = response.urls || [];
        updateCloudStats(cloudCurrentResults.length);

        if (cloudCurrentResults.length === 0) {
          cloudResultList.innerHTML = '';
          cloudNoResult.classList.remove('pf-hidden');
        } else {
          cloudNoResult.classList.add('pf-hidden');
          renderCloudResults(cloudCurrentResults);
        }
      }
    });
  } catch (error) {
    console.error('[云存储] 加载结果失败:', error);
  }
}

// 更新统计
function updateCloudStats(urlCount) {
  if (cloudStatUrls) {
    cloudStatUrls.textContent = urlCount;
  }
  if (cloudStatVulns) {
    cloudStatVulns.textContent = '-';
  }
  if (cloudStatVendors) {
    cloudStatVendors.textContent = '-';
  }
}

// 渲染结果
function renderCloudResults(urls) {
  if (!cloudResultList) return;

  // TODO: 从 background 获取实际漏洞数据
  // 目前仅显示 URL 列表
  cloudResultList.innerHTML = urls.map(url => {
    const vendorName = getVendorFromUrl(url);
    return `
      <li class="pf-cloud-item">
        <div class="pf-cloud-header">
          <span class="pf-cloud-url">${escapeHtml(url)}</span>
          <span class="pf-cloud-vendor">${vendorName}</span>
        </div>
        <div class="pf-cloud-type">等待检测...</div>
        <div class="pf-cloud-actions">
          <button class="pf-btn pf-btn-sm copy-url-btn" data-url="${escapeHtml(url)}">📋 复制</button>
          <button class="pf-btn pf-btn-sm open-url-btn" data-url="${escapeHtml(url)}">🔗 打开</button>
        </div>
      </li>
    `;
  }).join('');

  // 绑定按钮事件
  cloudResultList.querySelectorAll('.copy-url-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.dataset.url);
      btn.textContent = '✅ 已复制';
      setTimeout(() => {
        btn.textContent = '📋 复制';
      }, 2000);
    });
  });

  cloudResultList.querySelectorAll('.open-url-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      window.open(btn.dataset.url, '_blank');
      btn.textContent = '✅ 已打开';
      setTimeout(() => {
        btn.textContent = '🔗 打开';
      }, 2000);
    });
  });
}

// 从 URL 识别云厂商
function getVendorFromUrl(url) {
  const vendorMap = {
    'aliyuncs.com': '阿里云',
    'myqcloud.com': '腾讯云',
    'myhuaweicloud.com': '华为云',
    'amazonaws.com': 'AWS',
    'qiniucs.com': '七牛云',
    'clouddn.com': '七牛云',
    'qingstor.com': '青云',
    'upaiyun.com': '又拍云',
    'upyun.com': '又拍云',
    'jcloudcs.com': '京东云',
    'ksyuncs.com': '金山云',
    'ctyun.cn': '天翼云',
    'ctyunapi.cn': '天翼云'
  };

  for (const [domain, name] of Object.entries(vendorMap)) {
    if (url.includes(domain)) return name;
  }
  return '未知';
}

// 加载历史记录
async function loadCloudHistory(page) {
  try {
    const vendor = cloudFilterVendor?.value || '';
    const level = cloudFilterLevel?.value || '';

    const options = {
      page,
      pageSize: cloudHistoryPageSize
    };
    if (vendor) options.vendor = vendor;
    if (level) options.riskLevel = level;

    const response = await new Promise(resolve => {
      chrome.runtime.sendMessage({
        type: 'CLOUD_STORAGE_GET_HISTORY',
        options
      }, resolve);
    });

    if (response && response.success) {
      cloudHistoryPage = page;
      const history = response.history || [];

      if (history.length === 0) {
        cloudHistoryList.innerHTML = '';
        cloudHistoryEmpty.classList.remove('pf-hidden');
      } else {
        cloudHistoryEmpty.classList.add('pf-hidden');
        renderCloudHistory(history);
      }
    }
  } catch (error) {
    console.error('[云存储] 加载历史失败:', error);
  }
}

// 渲染历史记录
function renderCloudHistory(history) {
  if (!cloudHistoryList) return;

  cloudHistoryList.innerHTML = history.map(item => `
    <li class="pf-cloud-item">
      <div class="pf-cloud-header">
        <span class="pf-cloud-url">${escapeHtml(item.url)}</span>
        <span class="pf-cloud-vendor">${item.vendorName || item.vendor}</span>
      </div>
      ${item.riskType ? `<div class="pf-cloud-type">${getRiskTypeLabel(item.riskType)}</div>` : ''}
      ${item.riskLevel ? `<span class="pf-cloud-level pf-cloud-level-${item.riskLevel.toLowerCase()}">${getRiskLevelLabel(item.riskLevel)}</span>` : ''}
      <div class="pf-cloud-actions">
        <button class="pf-btn pf-btn-sm delete-history-btn" data-id="${item.id}">🗑️ 删除</button>
      </div>
    </li>
  `).join('');

  cloudHistoryList.querySelectorAll('.delete-history-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      await deleteHistoryItem(btn.dataset.id);
      loadCloudHistory(cloudHistoryPage);
    });
  });
}

// 删除历史记录
async function deleteHistoryItem(id) {
  try {
    const response = await new Promise(resolve => {
      chrome.runtime.sendMessage({
        type: 'CLOUD_STORAGE_DELETE_HISTORY',
        id
      }, resolve);
    });

    if (response && response.success) {
      // 重新加载列表
      loadCloudHistory(cloudHistoryPage);
    } else {
      alert('删除失败：' + (response?.error || '未知错误'));
    }
  } catch (error) {
    console.error('[云存储] 删除失败:', error);
    alert('删除失败：' + error.message);
  }
}

// 清空历史
async function clearCloudHistory() {
  if (!confirm('确定要清空所有历史记录吗？此操作不可恢复！')) return;
  
  try {
    const response = await new Promise(resolve => {
      chrome.runtime.sendMessage({
        type: 'CLOUD_STORAGE_CLEAR_HISTORY'
      }, resolve);
    });

    if (response && response.success) {
      cloudHistoryPage = 1;
      loadCloudHistory(1);
      loadCloudResults();
    } else {
      alert('清空失败：' + (response?.error || '未知错误'));
    }
  } catch (error) {
    console.error('[云存储] 清空失败:', error);
    alert('清空失败：' + error.message);
  }
}

// 导出结果
async function exportCloudResults() {
  const data = JSON.stringify(cloudCurrentResults, null, 2);
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cloud-storage-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// 加载黑白名单
async function loadCloudLists(autoExpand = false) {
  try {
    const whitelist = await new Promise(resolve => {
      chrome.storage.local.get(['cloud_storage_whitelist'], r => resolve(r.cloud_storage_whitelist || []));
    });
    const blacklist = await new Promise(resolve => {
      chrome.storage.local.get(['cloud_storage_blacklist'], r => resolve(r.cloud_storage_blacklist || []));
    });

    // 显示或隐藏列表容器
    const hasWhitelist = whitelist.length > 0;
    const hasBlacklist = blacklist.length > 0;
    
    if (cloudListsContainer) {
      // 如果有数据或者自动展开，显示容器
      if (hasWhitelist || hasBlacklist || autoExpand) {
        cloudListsContainer.classList.remove('pf-hidden');
      } else {
        cloudListsContainer.classList.add('pf-hidden');
      }
    }

    if (cloudWhitelist) {
      if (hasWhitelist) {
        cloudWhitelist.innerHTML = whitelist.map(item => `
          <li class="pf-list-item-with-btn">
            <span class="pf-list-item-text">${escapeHtml(item)}</span>
            <button class="pf-btn pf-btn-sm remove-wl-btn" data-item="${escapeHtml(item)}" title="从白名单移除">✕</button>
          </li>
        `).join('');
      } else {
        cloudWhitelist.innerHTML = '';
      }
    }
    if (cloudBlacklist) {
      if (hasBlacklist) {
        cloudBlacklist.innerHTML = blacklist.map(item => `
          <li class="pf-list-item-with-btn">
            <span class="pf-list-item-text">${escapeHtml(item)}</span>
            <button class="pf-btn pf-btn-sm remove-bl-btn" data-item="${escapeHtml(item)}" title="从黑名单移除">✕</button>
          </li>
        `).join('');
      } else {
        cloudBlacklist.innerHTML = '';
      }
    }

    // 绑定删除事件
    document.querySelectorAll('.remove-wl-btn').forEach(btn => {
      btn.addEventListener('click', () => removeFromCloudWhitelist(btn.dataset.item));
    });
    document.querySelectorAll('.remove-bl-btn').forEach(btn => {
      btn.addEventListener('click', () => removeFromCloudBlacklist(btn.dataset.item));
    });
  } catch (error) {
    console.error('[云存储] 加载名单失败:', error);
  }
}

// 添加到白名单
async function addToCloudWhitelist() {
  const value = cloudWhitelistInput?.value?.trim();
  if (!value) return;

  const whitelist = await new Promise(resolve => {
    chrome.storage.local.get(['cloud_storage_whitelist'], r => resolve(r.cloud_storage_whitelist || []));
  });

  if (!whitelist.includes(value)) {
    whitelist.push(value);
    await chrome.storage.local.set({ cloud_storage_whitelist: whitelist });
    cloudWhitelistInput.value = '';
    loadCloudLists();
  }
}

// 添加到黑名单
async function addToCloudBlacklist() {
  const value = cloudBlacklistInput?.value?.trim();
  if (!value) return;

  const blacklist = await new Promise(resolve => {
    chrome.storage.local.get(['cloud_storage_blacklist'], r => resolve(r.cloud_storage_blacklist || []));
  });

  if (!blacklist.includes(value)) {
    blacklist.push(value);
    await chrome.storage.local.set({ cloud_storage_blacklist: blacklist });
    cloudBlacklistInput.value = '';
    loadCloudLists();
  }
}

// 从白名单移除
async function removeFromCloudWhitelist(item) {
  const whitelist = await new Promise(resolve => {
    chrome.storage.local.get(['cloud_storage_whitelist'], r => resolve(r.cloud_storage_whitelist || []));
  });

  const filtered = whitelist.filter(x => x !== item);
  await chrome.storage.local.set({ cloud_storage_whitelist: filtered });
  loadCloudLists();
}

// 从黑名单移除
async function removeFromCloudBlacklist(item) {
  const blacklist = await new Promise(resolve => {
    chrome.storage.local.get(['cloud_storage_blacklist'], r => resolve(r.cloud_storage_blacklist || []));
  });

  const filtered = blacklist.filter(x => x !== item);
  await chrome.storage.local.set({ cloud_storage_blacklist: filtered });
  loadCloudLists();
}

// 切换设置显示
function toggleCloudSettings() {
  if (cloudSettingsContainer) {
    cloudSettingsContainer.classList.toggle('pf-hidden');
  }
}

// 辅助函数
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function getRiskTypeLabel(type) {
  const labels = {
    'TRAVERSABLE': '存储桶可遍历',
    'UPLOAD': 'PUT 上传',
    'DELETE': 'DELETE 删除',
    'ACL_READ': 'ACL 可读',
    'ACL_WRITE': 'ACL 可写',
    'POLICY_READ': 'Policy 可读',
    'POLICY_WRITE': 'Policy 可写',
    'BUCKET_TAKEOVER': '桶接管'
  };
  return labels[type] || type;
}

function getRiskLevelLabel(level) {
  const labels = {
    'CRITICAL': '严重',
    'HIGH': '高危',
    'MEDIUM': '中危',
    'LOW': '低危'
  };
  return labels[level] || level;
}

function showError(msg) {
  if (cloudResultList) {
    cloudResultList.innerHTML = `<li class="pf-empty">${escapeHtml(msg)}</li>`;
  }
}

// 初始化
initCloudStorageModule();

// ============ 云存储检测模块结束 ============
