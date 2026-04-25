// 云存储检测器基类
// 提供通用检测逻辑和 HTTP 请求包装

import { buildBurpRequest, buildBurpResponse } from './vendor-detect.js';

/**
 * 移除 URL 中的所有查询参数
 */
export function removeAllParameters(url) {
  try {
    const u = new URL(url);
    u.search = '';
    u.hash = '';
    return u.toString();
  } catch {
    return url;
  }
}

/**
 * 获取存储桶基础 URL
 */
export function getBucketBase(url) {
  try {
    const u = new URL(url);
    const parts = u.pathname.split('/').filter(Boolean);
    if (parts.length > 0) {
      u.pathname = '/' + parts[0] + '/';
    }
    u.search = '';
    u.hash = '';
    return u.toString();
  } catch {
    return url;
  }
}

/**
 * 构建可遍历检测的候选 URL 列表
 */
export function buildListingCandidates(url, bucketBaseUrl, vendor, traverseBacktrack = false) {
  const candidates = [];
  const u = new URL(url);
  const basePath = u.pathname;
  
  // 标准检测 URL
  candidates.push({
    url: bucketBaseUrl,
    type: 'bucket_base'
  });
  
  // 如果启用回溯，逐层向上
  if (traverseBacktrack && basePath && basePath !== '/') {
    const parts = basePath.split('/').filter(Boolean);
    let currentPath = '';
    
    for (const part of parts) {
      currentPath += '/' + part;
      try {
        const candidate = new URL(url);
        candidate.pathname = currentPath + '/';
        candidates.push({
          url: candidate.toString(),
          type: 'path_layer'
        });
      } catch {}
    }
  }
  
  return candidates;
}

/**
 * 检测器基类
 */
export class BaseDetector {
  constructor(vendorName) {
    this.vendorName = vendorName;
    this.TYPE = {
      TRAVERSABLE: '存储桶可遍历',
      UPLOAD: 'PUT 文件上传',
      DELETE: 'DELETE 文件删除',
      ACL_READ: 'ACL 可读',
      ACL_WRITE: 'ACL 可写',
      POLICY_READ: 'Policy 可读',
      POLICY_WRITE: 'Policy 可写',
      BUCKET_TAKEOVER: '桶接管'
    };
  }

  /**
   * 检测存储桶可遍历
   */
  async checkTraversable(url, traverseBacktrack = false) {
    const results = [];
    const listUrl = removeAllParameters(url);
    const bucketBaseUrl = getBucketBase(url);

    try {
      const candidates = buildListingCandidates(url, bucketBaseUrl, this.vendorName, traverseBacktrack);
      
      for (const c of candidates) {
        try {
          const resp = await fetch(c.url, { method: 'GET' });
          const text = await resp.text();
          
          if (resp.status >= 200 && resp.status < 300 && this.isTraversableResponse(text)) {
            results.push({
              type: this.TYPE.TRAVERSABLE,
              vendor: this.vendorName,
              url: c.url,
              found: true,
              request: buildBurpRequest('GET', c.url, {}, undefined),
              response: buildBurpResponse(resp.status, resp.statusText, Object.fromEntries(resp.headers.entries()), text),
              detail: `存储桶可遍历 (${c.url})`
            });
            break;
          }
        } catch (e) {
          // 继续下一个候选
        }
      }
    } catch (e) {
      // 检测失败
    }
    
    return results;
  }

  /**
   * 判断是否为可遍历响应
   * 子类需要实现此方法
   */
  isTraversableResponse(text) {
    return false;
  }

  /**
   * 检测 PUT 上传漏洞
   */
  async checkUpload(url) {
    const results = [];
    const testObjectName = `bt_test_${Date.now()}_${Math.random().toString(16).slice(2)}.txt`;
    const testUrl = new URL(url);
    testUrl.pathname = (testUrl.pathname.endsWith('/') ? testUrl.pathname : testUrl.pathname + '/') + testObjectName;
    
    try {
      const testContent = 'ButterCookie Cloud Storage Test';
      const resp = await fetch(testUrl.toString(), {
        method: 'PUT',
        headers: {
          'Content-Type': 'text/plain'
        },
        body: testContent
      });
      
      if (resp.status >= 200 && resp.status < 300) {
        // 上传成功，立即删除
        try {
          await fetch(testUrl.toString(), { method: 'DELETE' });
        } catch {}
        
        results.push({
          type: this.TYPE.UPLOAD,
          vendor: this.vendorName,
          url: testUrl.toString(),
          found: true,
          request: buildBurpRequest('PUT', testUrl.toString(), { 'Content-Type': 'text/plain' }, testContent),
          response: buildBurpResponse(resp.status, resp.statusText, Object.fromEntries(resp.headers.entries()), await resp.text()),
          detail: '可未经授权上传文件'
        });
      }
    } catch (e) {
      // 检测失败
    }
    
    return results;
  }

  /**
   * 检测 ACL 读取漏洞
   */
  async checkACLRead(url) {
    const results = [];
    const aclUrl = new URL(url);
    aclUrl.searchParams.set('acl', '');
    
    try {
      const resp = await fetch(aclUrl.toString(), { method: 'GET' });
      const text = await resp.text();
      
      if (resp.status === 200 && this.isACLReadableResponse(text)) {
        results.push({
          type: this.TYPE.ACL_READ,
          vendor: this.vendorName,
          url: aclUrl.toString(),
          found: true,
          request: buildBurpRequest('GET', aclUrl.toString(), {}, undefined),
          response: buildBurpResponse(resp.status, resp.statusText, Object.fromEntries(resp.headers.entries()), text),
          detail: 'ACL 配置可被读取'
        });
      }
    } catch (e) {
      // 检测失败
    }
    
    return results;
  }

  /**
   * 判断 ACL 是否可读
   */
  isACLReadableResponse(text) {
    return false;
  }

  /**
   * 检测 Policy 读取漏洞
   */
  async checkPolicyRead(url) {
    const results = [];
    const policyUrl = new URL(url);
    policyUrl.searchParams.set('policy', '');
    
    try {
      const resp = await fetch(policyUrl.toString(), { method: 'GET' });
      const text = await resp.text();
      
      if (resp.status === 200 && this.isPolicyReadableResponse(text)) {
        results.push({
          type: this.TYPE.POLICY_READ,
          vendor: this.vendorName,
          url: policyUrl.toString(),
          found: true,
          request: buildBurpRequest('GET', policyUrl.toString(), {}, undefined),
          response: buildBurpResponse(resp.status, resp.statusText, Object.fromEntries(resp.headers.entries()), text),
          detail: '存储桶策略可被读取'
        });
      }
    } catch (e) {
      // 检测失败
    }
    
    return results;
  }

  /**
   * 判断 Policy 是否可读
   */
  isPolicyReadableResponse(text) {
    return false;
  }

  /**
   * 执行完整检测
   */
  async check(url, options = {}) {
    const {
      checkAcl = true,
      checkPolicy = true,
      safeMode = true,
      traverseBacktrack = false
    } = options;

    let results = [];

    // 可遍历检测
    results = results.concat(await this.checkTraversable(url, traverseBacktrack));

    // PUT 上传检测（安全模式下跳过）
    if (!safeMode) {
      results = results.concat(await this.checkUpload(url));
    }

    // ACL 检测
    if (checkAcl) {
      results = results.concat(await this.checkACLRead(url));
    }

    // Policy 检测
    if (checkPolicy && !safeMode) {
      results = results.concat(await this.checkPolicyRead(url));
    }

    return results;
  }
}
