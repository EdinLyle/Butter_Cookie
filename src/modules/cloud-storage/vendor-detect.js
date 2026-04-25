// 云存储检测模块 - 云厂商识别
// 源自谛听鉴 lib/index.js

import { checkAliyun } from './detectors/aliyun.js';
import { checkTencent } from './detectors/tencent.js';
import { checkHuawei } from './detectors/huawei.js';
import { checkAWS } from './detectors/aws.js';
import { checkQiniu } from './detectors/qiniu.js';
import { checkQing } from './detectors/qing.js';
import { checkUpyun } from './detectors/upyun.js';
import { checkJD } from './detectors/jd.js';
import { checkKingsoft } from './detectors/kingsoft.js';
import { checkTianyi } from './detectors/tianyi.js';

/**
 * 检测存储桶漏洞
 * @param {string} url - 存储桶 URL
 * @param {object} options - 检测选项
 * @returns {Promise<Array>} 风险列表
 */
export async function detectBucketVul(url, options = {}) {
  // 如果指定了云厂商列表，则只检测这些厂商
  if (options && Array.isArray(options.vendors) && options.vendors.length > 0) {
    let results = [];
    for (const v of options.vendors) {
      if (v === 'aliyun') {
        results = results.concat(await checkAliyun(url, options));
      } else if (v === 'tencent') {
        results = results.concat(await checkTencent(url, options));
      } else if (v === 'huawei') {
        results = results.concat(await checkHuawei(url, options));
      } else if (v === 'AmazonS3') {
        results = results.concat(await checkAWS(url, options));
      } else if (v === 'qiniu') {
        results = results.concat(await checkQiniu(url, options));
      } else if (v === 'qingcloud') {
        results = results.concat(await checkQing(url, options));
      } else if (v === 'jdcloud') {
        results = results.concat(await checkJD(url, options));
      } else if (v === 'ctyun') {
        results = results.concat(await checkTianyi(url, options));
      }
    }
    if (!Array.isArray(results)) return [];
    return results;
  }

  // 自动识别云厂商
  let vendor = detectVendor(url);
  if (vendor === '未知') {
    vendor = await detectVendorByServer(url);
  }
  let results = [];

  if (vendor === '阿里云') {
    results = await checkAliyun(url, options);
  } else if (vendor === '腾讯云') {
    results = await checkTencent(url, options);
  } else if (vendor === '华为云') {
    results = await checkHuawei(url, options);
  } else if (vendor === 'AmazonS3') {
    results = await checkAWS(url, options);
  } else if (vendor === '七牛云') {
    results = await checkQiniu(url, options);
  } else if (vendor === '青云') {
    results = await checkQing(url, options);
  } else if (vendor === '京东云') {
    results = await checkJD(url, options);
  } else if (vendor === '天翼云') {
    results = await checkTianyi(url, options);
  }
  
  if (!Array.isArray(results)) return [];
  return results;
}

/**
 * 基于 URL 识别云厂商
 * @param {string} url - URL
 * @returns {string} 云厂商名称
 */
export function detectVendor(url) {
  try {
    const u = new URL(url);
    const host = u.hostname;
    
    if (host.includes('aliyuncs.com')) return '阿里云';
    if (host.includes('myqcloud.com')) return '腾讯云';
    if (host.includes('myhuaweicloud.com')) return '华为云';
    if (host.includes('amazonaws.com') || host.includes('s3.amazonaws.com.cn')) return 'AmazonS3';
    if (host.includes('qiniucs.com') || host.includes('clouddn.com') || host.includes('qcloudcdn.com')) return '七牛云';
    if (host.includes('qingstor.com')) return '青云';
    if (host.includes('upaiyun.com') || host.includes('upyun.com') || host.includes('upcdn.net')) return '又拍云';
    if (host.includes('jcloudcs.com')) return '京东云';
    if (host.includes('ksyuncs.com') || host.includes('ks3-cn-')) return '金山云';
    if ((host.includes('ctyun.cn') && host.includes('.obs.')) || (host.includes('ctyunapi.cn') && host.startsWith('oos-'))) return '天翼云';
    
    return '未知';
  } catch {
    return '未知';
  }
}

/**
 * 基于 Server Header 识别云厂商
 * @param {Response} resp - Fetch Response
 * @returns {string|null} 云厂商名称
 */
export function detectVendorByServerHeader(resp) {
  const server = resp.headers.get('server');
  if (!server) return null;
  
  const s = String(server).toLowerCase();
  
  if (server === 'AliyunOSS' || s.includes('aliyunoss')) return '阿里云';
  if (server === 'tencent-cos' || s.includes('tencent-cos')) return '腾讯云';
  if (server === 'OBS' || s === 'obs') return '华为云';
  if (server === 'AmazonS3' || s.includes('amazons3')) return 'AmazonS3';
  if (s.includes('qiniu')) return '七牛云';
  if (s.includes('qingstor') || s.includes('qingcloud')) return '青云';
  if (s.includes('upyun') || s.includes('upaiyun')) return '又拍云';
  if (s.includes('jdcloud') || s.includes('jcloud')) return '京东云';
  if (s.includes('ks3') || s.includes('kingsoft')) return '金山云';
  if (s.includes('ctyun')) return '天翼云';
  
  return null;
}

/**
 * 基于 Server Header 识别云厂商（异步）
 * @param {string} url - URL
 * @returns {Promise<string>} 云厂商名称
 */
export async function detectVendorByServer(url) {
  try {
    const resp = await fetch(url, { method: 'HEAD' });
    const vendor = detectVendorByServerHeader(resp);
    return vendor || '未知';
  } catch {
    return '未知';
  }
}

/**
 * 构建 BurpSuite 格式的请求
 */
export function buildBurpRequest(method, url, headers, body) {
  const u = new URL(url);
  let req = `${method} ${u.pathname}${u.search} HTTP/1.1\r\n`;
  req += `Host: ${u.host}\r\n`;
  
  for (const [k, v] of Object.entries(headers || {})) {
    if (k.toLowerCase() !== 'host') req += `${k}: ${v}\r\n`;
  }
  
  req += '\r\n';
  if (body) req += body;
  
  return req;
}

/**
 * 构建 BurpSuite 格式的响应
 */
export function buildBurpResponse(status, statusText, headers, body) {
  let resp = `HTTP/1.1 ${status} ${statusText}\r\n`;
  
  for (const [k, v] of Object.entries(headers || {})) {
    resp += `${k}: ${v}\r\n`;
  }
  
  resp += '\r\n';
  if (body) resp += body;
  
  return resp;
}
