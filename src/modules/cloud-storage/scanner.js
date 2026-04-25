/**
 * 云存储桶主动扫描器
 * 
 * 功能：
 * 1. 从页面 HTML、JS 文件中提取潜在的云存储桶 URL
 * 2. 支持提取外链 JS 和内联 JS 中的 URL
 * 3. URL 规范化和去重
 * 4. 节流控制，避免过多请求
 */

import { detectVendor, detectVendorByServerHeader } from './vendor-detect.js';
import { isInBlacklist, isInWhitelist, getConfig } from './storage.js';

/**
 * URL 正则表达式
 */
const BUCKET_URL_REGEX = /https?:\/\/[^\s"'<>]*\.(aliyuncs\.com|myqcloud\.com|myhuaweicloud\.com|amazonaws\.com|qiniucs\.com|clouddn\.com|qingstor\.com|upaiyun\.com|upyun\.com|jcloudcs\.com|ksyuncs\.com|ks3-cn-[\w-]+\.ksyuncs\.com|ctyun\.cn|ctyunapi\.cn)[^\s"'<>]*/gi;

/**
 * 从文本中提取 URL
 * @param {string} text - 文本内容
 * @returns {string[]} URL 列表
 */
function extractUrlsFromText(text) {
  const matches = text.match(BUCKET_URL_REGEX) || [];
  return [...new Set(matches)];
}

/**
 * 从 HTML 中提取 URL
 * @param {string} html - HTML 内容
 * @returns {string[]} URL 列表
 */
function extractUrlsFromHtml(html) {
  const urls = new Set();
  
  // 提取 src 和 href 属性
  const attrRegex = /(src|href)=["'](https?:\/\/[^"']*)["']/gi;
  let match;
  while ((match = attrRegex.exec(html)) !== null) {
    if (match[2].match(BUCKET_URL_REGEX)) {
      urls.add(match[2]);
    }
  }
  
  // 提取 script 标签内容中的 URL
  const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
  while ((match = scriptRegex.exec(html)) !== null) {
    extractUrlsFromText(match[1]).forEach(url => urls.add(url));
  }
  
  return Array.from(urls);
}

/**
 * 从 JS 代码中提取 URL
 * @param {string} jsCode - JS 代码
 * @returns {string[]} URL 列表
 */
function extractUrlsFromJs(jsCode) {
  return extractUrlsFromText(jsCode);
}

/**
 * 规范化 URL
 * @param {string} url - URL
 * @returns {string} 规范化后的 URL
 */
function normalizeUrl(url) {
  try {
    const parsed = new URL(url);
    // 移除末尾的斜杠
    if (parsed.pathname === '/') {
      return `${parsed.protocol}//${parsed.host}`;
    }
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch (e) {
    return url;
  }
}

/**
 * 从页面提取云存储桶 URL
 * @param {Document} doc - Document 对象
 * @param {object} options - 扫描选项
 * @returns {Promise<string[]>} URL 列表
 */
export async function extractUrlsFromPage(doc = document, options = {}) {
  const config = await getConfig();
  const urls = new Set();
  
  // 从 HTML 中提取
  const htmlUrls = extractUrlsFromHtml(doc.documentElement.outerHTML);
  htmlUrls.forEach(url => urls.add(url));
  
  // 从内联 JS 中提取
  if (config.scanPageContent) {
    const scripts = Array.from(doc.getElementsByTagName('script'));
    const inlineScripts = scripts.filter(s => !s.src && s.text);
    
    // 限制数量
    const maxInline = config.scanMaxInlineJS || 20;
    for (let i = 0; i < Math.min(inlineScripts.length, maxInline); i++) {
      const scriptUrls = extractUrlsFromJs(inlineScripts[i].text);
      scriptUrls.forEach(url => urls.add(url));
    }
  }
  
  // 从外链 JS 中提取
  if (config.scanPageContent) {
    const scripts = Array.from(doc.getElementsByTagName('script'));
    const externalScripts = scripts.filter(s => s.src);
    
    // 限制数量
    const maxExternal = config.scanMaxExternalJS || 40;
    for (let i = 0; i < Math.min(externalScripts.length, maxExternal); i++) {
      try {
        const response = await fetch(externalScripts[i].src);
        if (response.ok) {
          const jsText = await response.text();
          // 限制文件大小
          const maxSize = (config.scanMaxFileSize || 1024) * 1024;
          if (jsText.length <= maxSize) {
            const jsUrls = extractUrlsFromJs(jsText);
            jsUrls.forEach(url => urls.add(url));
          }
        }
      } catch (e) {
        // 忽略跨域等错误
      }
    }
  }
  
  // 规范化 URL
  const normalizedUrls = Array.from(urls).map(normalizeUrl);
  
  // 过滤黑名单
  const filtered = await Promise.all(
    normalizedUrls.map(async url => {
      if (await isInBlacklist(url)) return null;
      if (await isInWhitelist(url)) return null;
      return url;
    })
  );
  
  // 限制最大候选数量
  const maxCandidates = config.scanMaxCandidates || 60;
  return filtered.filter(Boolean).slice(0, maxCandidates);
}

/**
 * 扫描页面中的云存储桶
 * @param {Document} doc - Document 对象
 * @param {object} options - 扫描选项
 * @returns {Promise<object[]>} 漏洞列表
 */
export async function scanPage(doc = document, options = {}) {
  const urls = await extractUrlsFromPage(doc, options);
  const vulnerabilities = [];
  
  for (const url of urls) {
    try {
      // 识别云厂商
      const vendorInfo = detectVendor(url);
      if (!vendorInfo) continue;
      
      // 根据云厂商调用对应检测器
      const { vendor } = vendorInfo;
      
      let checkFunc;
      if (vendor === 'aliyun') {
        const { checkAliyun } = await import('./detectors/aliyun.js');
        checkFunc = checkAliyun;
      } else if (vendor === 'tencent') {
        const { checkTencent } = await import('./detectors/tencent.js');
        checkFunc = checkTencent;
      } else if (vendor === 'huawei') {
        const { checkHuawei } = await import('./detectors/huawei.js');
        checkFunc = checkHuawei;
      } else if (vendor === 'aws') {
        const { checkAWS } = await import('./detectors/aws.js');
        checkFunc = checkAWS;
      } else if (vendor === 'qiniu') {
        const { checkQiniu } = await import('./detectors/qiniu.js');
        checkFunc = checkQiniu;
      } else if (vendor === 'qing') {
        const { checkQing } = await import('./detectors/qing.js');
        checkFunc = checkQing;
      } else if (vendor === 'upyun') {
        const { checkUpyun } = await import('./detectors/upyun.js');
        checkFunc = checkUpyun;
      } else if (vendor === 'jd') {
        const { checkJD } = await import('./detectors/jd.js');
        checkFunc = checkJD;
      } else if (vendor === 'kingsoft') {
        const { checkKingsoft } = await import('./detectors/kingsoft.js');
        checkFunc = checkKingsoft;
      } else if (vendor === 'tianyi') {
        const { checkTianyi } = await import('./detectors/tianyi.js');
        checkFunc = checkTianyi;
      }
      
      if (checkFunc) {
        const vuls = await checkFunc(url, { safeMode: true, debug: options.debug });
        vulnerabilities.push(...vuls);
      }
    } catch (error) {
      if (options.debug) {
        console.warn(`[扫描器] 扫描 ${url} 失败：`, error.message);
      }
    }
  }
  
  return vulnerabilities;
}

/**
 * 提取当前页面的所有云存储 URL（用于 content script）
 * @returns {Promise<string[]>}
 */
export async function getAllCloudUrls() {
  return extractUrlsFromPage(document, { scanPageContent: false });
}
