/**
 * 云存储桶风险检测 Content Script
 * 
 * 功能：
 * 1. 页面加载时自动扫描云存储桶 URL
 * 2. 监听 DOM 变化检测新添加的云存储 URL
 * 3. 向 popup 发送检测结果
 */

import { extractUrlsFromPage, scanPage, getAllCloudUrls } from '../modules/cloud-storage/scanner.js';
import { detectVendor } from '../modules/cloud-storage/vendor-detect.js';
import { isInBlacklist, isInWhitelist } from '../modules/cloud-storage/storage.js';

// 防止重复执行
if (!window.__cloudStorageScannerInitialized) {
  window.__cloudStorageScannerInitialized = true;
} else {
  // 已初始化，跳过
  console.log('[云存储检测] Content Script 已初始化，跳过');
}

// 扫描状态
let isScanning = false;
let scanResults = [];
let scanTimestamp = 0;

/**
 * 向 popup 发送消息
 */
function sendToPopup(message) {
  chrome.runtime.sendMessage(message).catch(err => {
    // 忽略错误（popup 可能未打开）
  });
}

/**
 * 扫描页面
 */
async function scanCloudStorage() {
  if (isScanning) return;
  isScanning = true;
  
  try {
    const startTime = Date.now();
    console.log('[云存储检测] 开始扫描页面...');
    
    // 提取 URL
    const urls = await getAllCloudUrls();
    console.log(`[云存储检测] 发现 ${urls.length} 个云存储 URL`);
    
    // 识别云厂商
    const vendorStats = {};
    for (const url of urls) {
      const vendorInfo = detectVendor(url);
      if (vendorInfo) {
        vendorStats[vendorInfo.vendor] = (vendorStats[vendorInfo.vendor] || 0) + 1;
      }
    }
    
    // 发送统计信息
    sendToPopup({
      type: 'CLOUD_STORAGE_SCAN_RESULT',
      data: {
        urlCount: urls.length,
        vendors: vendorStats,
        urls: urls,
        scannedAt: new Date().toISOString()
      }
    });
    
    // 深度扫描（检测漏洞）
    const vulnerabilities = await scanPage(document, {
      safeMode: true,
      debug: true
    });
    
    console.log(`[云存储检测] 发现 ${vulnerabilities.length} 个漏洞`);
    
    // 发送漏洞信息
    if (vulnerabilities.length > 0) {
      sendToPopup({
        type: 'CLOUD_STORAGE_VULNERABILITY',
        data: {
          vulnerabilities,
          detectedAt: new Date().toISOString()
        }
      });
    }
    
    scanResults = vulnerabilities;
    scanTimestamp = Date.now();
    
    console.log(`[云存储检测] 扫描完成，耗时：${Date.now() - startTime}ms`);
    
  } catch (error) {
    console.error('[云存储检测] 扫描失败:', error);
  } finally {
    isScanning = false;
  }
}

/**
 * 节流扫描（6 秒内不重复扫描）
 */
function throttledScan() {
  const now = Date.now();
  if (now - scanTimestamp < 6000) {
    console.log('[云存储检测] 节流触发，跳过扫描');
    return;
  }
  scanCloudStorage();
}

/**
 * 监听 DOM 变化
 */
function observeDOM() {
  const observer = new MutationObserver((mutations) => {
    // 只在添加了新 script 标签或属性变化时扫描
    let shouldScan = false;
    for (const mutation of mutations) {
      if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
        for (const node of mutation.addedNodes) {
          if (node.nodeName === 'SCRIPT' || 
              (node.querySelectorAll && node.querySelectorAll('script').length > 0)) {
            shouldScan = true;
            break;
          }
        }
      }
      if (shouldScan) break;
    }
    
    if (shouldScan) {
      throttledScan();
    }
  });
  
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
  
  console.log('[云存储检测] DOM 观察器已启动');
}

/**
 * 监听来自 popup 的消息
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'CLOUD_STORAGE_SCAN_REQUEST') {
    // 立即扫描
    scanCloudStorage().then(() => {
      sendResponse({
        success: true,
        results: scanResults,
        timestamp: scanTimestamp
      });
    }).catch(err => {
      sendResponse({
        success: false,
        error: err.message
      });
    });
    return true; // 异步响应
  }
  
  if (request.type === 'CLOUD_STORAGE_GET_URLS') {
    // 获取所有 URL
    getAllCloudUrls().then(urls => {
      sendResponse({
        success: true,
        urls
      });
    });
    return true;
  }
});

// 页面加载完成后启动扫描
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    setTimeout(scanCloudStorage, 1000);
    observeDOM();
  });
} else {
  setTimeout(scanCloudStorage, 1000);
  observeDOM();
}

console.log('[云存储检测] Content Script 已加载');
