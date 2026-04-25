/**
 * 云存储桶风险被动检测模块
 * 
 * 功能：
 * 1. 监听网络请求，检测云存储桶访问
 * 2. 节流控制（6 秒规则）
 * 3. 黑白名单过滤
 * 4. 自动检测并保存漏洞
 * 
 * 集成到 background.js
 */

// 延迟导入模块
let detectVendor, detectVendorByServerHeader;
let isInBlacklist, isInWhitelist, addHistory, getConfig;

async function initModules() {
  const vendorDetect = await import('./modules/cloud-storage/vendor-detect.js');
  const storage = await import('./modules/cloud-storage/storage.js');
  
  detectVendor = vendorDetect.detectVendor;
  detectVendorByServerHeader = vendorDetect.detectVendorByServerHeader;
  isInBlacklist = storage.isInBlacklist;
  isInWhitelist = storage.isInWhitelist;
  addHistory = storage.addHistory;
  getConfig = storage.getConfig;
}

// 初始化模块
initModules().catch(err => {
  console.error('[云存储] 模块加载失败:', err);
});

// 请求节流 Map（每个 URL 最后请求时间）
const throttleMap = new Map();
const THROTTLE_MS = 6000;

// 已检测 URL 缓存
const detectedUrls = new Map();

/**
 * 检查 URL 是否应该被检测
 */
async function shouldCheckUrl(url) {
  // 确保模块已初始化
  if (!detectVendor) await initModules();
  
  // 检查云厂商域名
  const vendorInfo = detectVendor(url);
  if (!vendorInfo) return false;
  
  // 检查黑名单
  if (await isInBlacklist(url)) {
    return false;
  }
  
  // 检查白名单
  if (await isInWhitelist(url)) {
    return false;
  }
  
  // 检查节流
  const lastCheck = throttleMap.get(url);
  const now = Date.now();
  if (lastCheck && (now - lastCheck < THROTTLE_MS)) {
    return false;
  }
  
  // 检查是否已检测过
  if (detectedUrls.has(url)) {
    const cache = detectedUrls.get(url);
    // 5 分钟内不重复检测
    if (Date.now() - cache.timestamp < 300000) {
      return false;
    }
  }
  
  return true;
}

/**
 * 检测单个请求
 */
async function checkRequest(details) {
  const url = details.url;
  
  // 只检测 GET/PUT/DELETE 请求
  if (!['GET', 'PUT', 'DELETE', 'HEAD'].includes(details.method)) {
    return;
  }
  
  // 检查是否应该检测
  if (!await shouldCheckUrl(url)) {
    return;
  }
  
  // 更新节流时间
  throttleMap.set(url, Date.now());
  
  try {
    // 识别云厂商
    const vendorInfo = detectVendor(url);
    if (!vendorInfo) return;
    
    const { vendor, name } = vendorInfo;
    
    // 根据云厂商调用检测器
    let checkFunc;
    if (vendor === 'aliyun') {
      const { checkAliyun } = await import('./modules/cloud-storage/detectors/aliyun.js');
      checkFunc = checkAliyun;
    } else if (vendor === 'tencent') {
      const { checkTencent } = await import('./modules/cloud-storage/detectors/tencent.js');
      checkFunc = checkTencent;
    } else if (vendor === 'huawei') {
      const { checkHuawei } = await import('./modules/cloud-storage/detectors/huawei.js');
      checkFunc = checkHuawei;
    } else if (vendor === 'aws') {
      const { checkAWS } = await import('./modules/cloud-storage/detectors/aws.js');
      checkFunc = checkAWS;
    } else if (vendor === 'qiniu') {
      const { checkQiniu } = await import('./modules/cloud-storage/detectors/qiniu.js');
      checkFunc = checkQiniu;
    } else if (vendor === 'qing') {
      const { checkQing } = await import('./modules/cloud-storage/detectors/qing.js');
      checkFunc = checkQing;
    } else if (vendor === 'upyun') {
      const { checkUpyun } = await import('./modules/cloud-storage/detectors/upyun.js');
      checkFunc = checkUpyun;
    } else if (vendor === 'jd') {
      const { checkJD } = await import('./modules/cloud-storage/detectors/jd.js');
      checkFunc = checkJD;
    } else if (vendor === 'kingsoft') {
      const { checkKingsoft } = await import('./modules/cloud-storage/detectors/kingsoft.js');
      checkFunc = checkKingsoft;
    } else if (vendor === 'tianyi') {
      const { checkTianyi } = await import('./modules/cloud-storage/detectors/tianyi.js');
      checkFunc = checkTianyi;
    }
    
    if (!checkFunc) return;
    
    // 执行检测
    const config = await getConfig();
    const vulnerabilities = await checkFunc(url, {
      safeMode: true,
      debug: false
    });
    
    // 保存结果
    if (vulnerabilities.length > 0) {
      for (const vuln of vulnerabilities) {
        await addHistory({
          url,
          vendor,
          vendorName: name,
          riskType: vuln.riskType,
          riskLevel: vuln.riskLevel,
          sourcePage: details.originUrl || details.documentUrl || 'unknown',
          detectedAt: new Date().toISOString(),
          request: {
            method: details.method,
            url: details.url,
            statusCode: details.statusCode
          },
          response: vuln.response,
          detail: vuln.detail
        });
      }
      
      // 更新缓存
      detectedUrls.set(url, {
        timestamp: Date.now(),
        vulnerabilities
      });
      
      // 通知 popup
      chrome.runtime.sendMessage({
        type: 'CLOUD_STORAGE_VULNERABILITY_DETECTED',
        data: {
          url,
          vendor,
          vendorName: name,
          vulnerabilities,
          tabId: details.tabId
        }
      }).catch(() => {
        // 忽略错误（popup 可能未打开）
      });
    } else {
      // 无漏洞，也缓存起来避免重复检测
      detectedUrls.set(url, {
        timestamp: Date.now(),
        vulnerabilities: []
      });
    }
    
  } catch (error) {
    console.warn('[云存储检测] 被动检测失败:', error.message);
  }
}

/**
 * 监听请求完成
 */
function setupPassiveDetection() {
  // 确保模块已初始化
  initModules().then(() => {
    console.log('[云存储] 模块初始化完成');
  });
  
  chrome.webRequest.onCompleted.addListener(
    (details) => {
      checkRequest(details).catch(err => {
        console.warn('[云存储检测] 检查请求失败:', err);
      });
    },
    {
      urls: ['<all_urls>'],
      types: ['xmlhttprequest', 'script', 'image', 'object', 'media']
    },
    ['responseHeaders']
  );
  
  console.log('[云存储检测] 被动检测已启用');
}

// 导出到全局
globalThis.setupPassiveDetection = setupPassiveDetection;
