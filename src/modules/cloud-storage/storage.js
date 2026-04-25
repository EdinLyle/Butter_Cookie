/**
 * 云存储检测数据管理模块
 * 
 * 功能：
 * 1. 历史记录管理（增删改查、分页、导出）
 * 2. 黑白名单管理
 * 3. 配置管理
 * 
 * 使用 Chrome Storage API 持久化存储
 */

const STORAGE_KEYS = {
  HISTORY: 'cloud_storage_history',
  WHITELIST: 'cloud_storage_whitelist',
  BLACKLIST: 'cloud_storage_blacklist',
  CONFIG: 'cloud_storage_config'
};

// 默认配置
const DEFAULT_CONFIG = {
  // 检测策略
  safeMode: true,
  checkACL: true,
  checkPolicy: true,
  traverseBacktrack: false,
  
  // 页面扫描
  scanPageContent: false,
  scanMaxExternalJS: 40,
  scanMaxInlineJS: 20,
  scanMaxFileSize: 1024,
  scanMaxCandidates: 60,
  
  // 性能
  throttleMs: 6000,
  historyLimit: 500,
  
  // 通知
  showNotification: true
};

/**
 * 添加历史记录
 * @param {object} record - 历史记录对象
 * @returns {Promise<string>} 记录 ID
 */
export async function addHistory(record) {
  const id = `record_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const newRecord = {
    id,
    ...record,
    createdAt: new Date().toISOString()
  };
  
  const history = await getHistory();
  history.unshift(newRecord);
  
  // 限制历史记录数量
  const config = await getConfig();
  const limit = config.historyLimit || 500;
  if (history.length > limit) {
    history.splice(limit);
  }
  
  await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: history });
  return id;
}

/**
 * 获取历史记录
 * @param {object} options - 查询选项
 * @returns {Promise<object[]>} 历史记录列表
 */
export async function getHistory(options = {}) {
  const result = await chrome.storage.local.get([STORAGE_KEYS.HISTORY]);
  let history = result[STORAGE_KEYS.HISTORY] || [];
  
  // 过滤
  if (options.vendor) {
    history = history.filter(h => h.vendor === options.vendor);
  }
  if (options.riskLevel) {
    history = history.filter(h => h.riskLevel === options.riskLevel);
  }
  if (options.url) {
    history = history.filter(h => h.url.includes(options.url));
  }
  if (options.startDate) {
    history = history.filter(h => h.createdAt >= options.startDate);
  }
  if (options.endDate) {
    history = history.filter(h => h.createdAt <= options.endDate);
  }
  
  // 排序
  if (options.sortBy === 'createdAt') {
    history.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  }
  
  // 分页
  if (options.page && options.pageSize) {
    const start = (options.page - 1) * options.pageSize;
    history = history.slice(start, start + options.pageSize);
  }
  
  return history;
}

/**
 * 删除历史记录
 * @param {string} id - 记录 ID
 * @returns {Promise<void>}
 */
export async function deleteHistory(id) {
  const history = await getHistory();
  const filtered = history.filter(h => h.id !== id);
  await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: filtered });
}

/**
 * 清空历史记录
 * @returns {Promise<void>}
 */
export async function clearHistory() {
  await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: [] });
}

/**
 * 导出历史记录
 * @param {string} format - 导出格式 ('json' | 'csv')
 * @returns {Promise<string>} 导出的数据
 */
export async function exportHistory(format = 'json') {
  const history = await getHistory();
  
  if (format === 'json') {
    return JSON.stringify(history, null, 2);
  }
  
  if (format === 'csv') {
    const headers = ['ID', 'URL', '云厂商', '风险类型', '风险等级', '来源页面', '检测时间'];
    const rows = history.map(h => [
      h.id,
      h.url,
      h.vendor,
      h.riskType,
      h.riskLevel,
      h.sourcePage,
      h.detectedAt
    ]);
    
    return [headers, ...rows].map(row => row.join(',')).join('\n');
  }
  
  throw new Error(`不支持的导出格式：${format}`);
}

/**
 * 添加到白名单
 * @param {string} url - URL 或域名
 * @returns {Promise<void>}
 */
export async function addToWhitelist(url) {
  const whitelist = await getWhitelist();
  if (!whitelist.includes(url)) {
    whitelist.push(url);
    await chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: whitelist });
  }
}

/**
 * 获取白名单
 * @returns {Promise<string[]>} 白名单列表
 */
export async function getWhitelist() {
  const result = await chrome.storage.local.get([STORAGE_KEYS.WHITELIST]);
  return result[STORAGE_KEYS.WHITELIST] || [];
}

/**
 * 从白名单移除
 * @param {string} url - URL 或域名
 * @returns {Promise<void>}
 */
export async function removeFromWhitelist(url) {
  const whitelist = await getWhitelist();
  const filtered = whitelist.filter(u => u !== url);
  await chrome.storage.local.set({ [STORAGE_KEYS.WHITELIST]: filtered });
}

/**
 * 添加到黑名单
 * @param {string} url - URL 或域名
 * @returns {Promise<void>}
 */
export async function addToBlacklist(url) {
  const blacklist = await getBlacklist();
  if (!blacklist.includes(url)) {
    blacklist.push(url);
    await chrome.storage.local.set({ [STORAGE_KEYS.BLACKLIST]: blacklist });
  }
}

/**
 * 获取黑名单
 * @returns {Promise<string[]>} 黑名单列表
 */
export async function getBlacklist() {
  const result = await chrome.storage.local.get([STORAGE_KEYS.BLACKLIST]);
  return result[STORAGE_KEYS.BLACKLIST] || [];
}

/**
 * 从黑名单移除
 * @param {string} url - URL 或域名
 * @returns {Promise<void>}
 */
export async function removeFromBlacklist(url) {
  const blacklist = await getBlacklist();
  const filtered = blacklist.filter(u => u !== url);
  await chrome.storage.local.set({ [STORAGE_KEYS.BLACKLIST]: filtered });
}

/**
 * 检查 URL 是否在白名单
 * @param {string} url - URL
 * @returns {Promise<boolean>} 是否在白名单
 */
export async function isInWhitelist(url) {
  const whitelist = await getWhitelist();
  return whitelist.some(pattern => url.includes(pattern));
}

/**
 * 检查 URL 是否在黑名单
 * @param {string} url - URL
 * @returns {Promise<boolean>} 是否在黑名单
 */
export async function isInBlacklist(url) {
  const blacklist = await getBlacklist();
  return blacklist.some(pattern => url.includes(pattern));
}

/**
 * 获取配置
 * @returns {Promise<object>} 配置对象
 */
export async function getConfig() {
  const result = await chrome.storage.local.get([STORAGE_KEYS.CONFIG]);
  return { ...DEFAULT_CONFIG, ...result[STORAGE_KEYS.CONFIG] };
}

/**
 * 保存配置
 * @param {object} config - 配置对象
 * @returns {Promise<void>}
 */
export async function saveConfig(config) {
  const current = await getConfig();
  const merged = { ...current, ...config };
  await chrome.storage.local.set({ [STORAGE_KEYS.CONFIG]: merged });
}

/**
 * 重置配置为默认值
 * @returns {Promise<void>}
 */
export async function resetConfig() {
  await chrome.storage.local.set({ [STORAGE_KEYS.CONFIG]: DEFAULT_CONFIG });
}

/**
 * 获取统计数据
 * @returns {Promise<object>} 统计数据
 */
export async function getStatistics() {
  const history = await getHistory();
  const whitelist = await getWhitelist();
  const blacklist = await getBlacklist();
  
  const vendorStats = {};
  const riskLevelStats = {};
  const riskTypeStats = {};
  
  history.forEach(h => {
    // 云厂商统计
    vendorStats[h.vendor] = (vendorStats[h.vendor] || 0) + 1;
    
    // 风险等级统计
    riskLevelStats[h.riskLevel] = (riskLevelStats[h.riskLevel] || 0) + 1;
    
    // 风险类型统计
    riskTypeStats[h.riskType] = (riskTypeStats[h.riskType] || 0) + 1;
  });
  
  return {
    totalRecords: history.length,
    whitelistCount: whitelist.length,
    blacklistCount: blacklist.length,
    vendorStats,
    riskLevelStats,
    riskTypeStats
  };
}
