/**
 * 云存储桶风险检测模块
 * 
 * 功能：
 * 1. 支持 10 家主流云服务商（阿里云、腾讯云、华为云、AWS、七牛云、青云、又拍云、京东云、金山云、天翼云）
 * 2. 检测 8 种风险类型（存储桶可遍历、PUT 上传、DELETE 删除、ACL 可读/写、Policy 可读/写、桶接管）
 * 3. 被动检测（监听网络请求）+ 主动检测（页面扫描）
 * 4. 黑白名单配置
 * 5. 历史记录管理
 * 
 * 源自谛听鉴 - 云存储桶风险监测 V1.1.0-By 狐狸
 */

export { detectBucketVul, detectVendor, detectVendorByServer, detectVendorByServerHeader } from './vendor-detect.js';
export { BaseDetector } from './base-detector.js';

// 云厂商检测器
export { checkAliyun } from './detectors/aliyun.js';
export { checkTencent } from './detectors/tencent.js';
export { checkHuawei } from './detectors/huawei.js';
export { checkAWS } from './detectors/aws.js';
export { checkQiniu } from './detectors/qiniu.js';
export { checkQing } from './detectors/qing.js';
export { checkUpyun } from './detectors/upyun.js';
export { checkJD } from './detectors/jd.js';
export { checkKingsoft } from './detectors/kingsoft.js';
export { checkTianyi } from './detectors/tianyi.js';

// 数据管理
export * from './storage.js';

// 扫描器
export { extractUrlsFromPage, scanPage, getAllCloudUrls } from './scanner.js';

// 配置管理
export const DEFAULT_CONFIG = {
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
  historyLimit: 500
};

// 风险等级
export const RISK_LEVELS = {
  CRITICAL: { label: '严重', color: '#dc2626' },
  HIGH: { label: '高危', color: '#ea580c' },
  MEDIUM: { label: '中危', color: '#f59e0b' },
  LOW: { label: '低危', color: '#3b82f6' }
};

// 风险类型
export const RISK_TYPES = {
  TRAVERSABLE: { label: '存储桶可遍历', level: 'HIGH' },
  UPLOAD: { label: 'PUT 文件上传', level: 'HIGH' },
  DELETE: { label: 'DELETE 文件删除', level: 'CRITICAL' },
  ACL_READ: { label: 'ACL 可读', level: 'MEDIUM' },
  ACL_WRITE: { label: 'ACL 可写', level: 'CRITICAL' },
  POLICY_READ: { label: 'Policy 可读', level: 'MEDIUM' },
  POLICY_WRITE: { label: 'Policy 可写', level: 'CRITICAL' },
  BUCKET_TAKEOVER: { label: '桶接管', level: 'CRITICAL' }
};

/**
 * 获取风险等级
 */
export function getRiskLevel(riskType) {
  const type = RISK_TYPES[riskType];
  return type ? type.level : 'MEDIUM';
}

/**
 * 获取风险颜色
 */
export function getRiskColor(riskLevel) {
  const level = RISK_LEVELS[riskLevel];
  return level ? level.color : '#6b7280';
}
