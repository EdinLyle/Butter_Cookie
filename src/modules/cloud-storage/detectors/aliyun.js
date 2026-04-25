// 阿里云 OSS 存储桶检测器

import { BaseDetector, buildBurpRequest, buildBurpResponse, removeAllParameters, getBucketBase, buildListingCandidates } from '../base-detector.js';

const TYPE = {
  TRAVERSABLE: '存储桶可遍历',
  UPLOAD: 'PUT 文件上传',
  DELETE: 'DELETE 文件删除',
  ACL_READ: 'ACL 可读',
  ACL_WRITE: 'ACL 可写',
  POLICY_READ: 'Policy 可读',
  POLICY_WRITE: 'Policy 可写',
  BUCKET_TAKEOVER: '桶接管',
};

export async function checkAliyun(url, options = {}) {
  const detector = new AliyunDetector();
  return await detector.check(url, options);
}

class AliyunDetector extends BaseDetector {
  constructor() {
    super('阿里云');
  }

  isTraversableResponse(text) {
    return text.includes('<ListBucketResult') && text.includes('<Name>');
  }

  isACLReadableResponse(text) {
    return text.includes('<AccessControlPolicy>') && text.includes('<AccessControlList>');
  }

  isPolicyReadableResponse(text) {
    try {
      JSON.parse(text);
      return text.includes('Statement') || text.includes('Effect');
    } catch {
      return false;
    }
  }

  async checkTraversable(url, traverseBacktrack = false) {
    const results = [];
    const listUrl = removeAllParameters(url);
    const bucketBaseUrl = getBucketBase(url);

    let traversableFound = false;
    let traversableReqHeaders = {};
    let traversableResp, traversableText, traversableRespHeaders;
    let matchedTraverseUrl = '';

    try {
      const candidates = buildListingCandidates(url, bucketBaseUrl, 'oss', traverseBacktrack);
      for (const c of candidates) {
        try {
          traversableResp = await fetch(c.url, { method: 'GET' });
          traversableText = await traversableResp.text();
          traversableRespHeaders = Object.fromEntries(traversableResp.headers.entries());

          if (
            traversableResp.status >= 200 && traversableResp.status < 300 &&
            traversableText.includes('<ListBucketResult') && traversableText.includes('<Name>')
          ) {
            traversableFound = true;
            matchedTraverseUrl = c.url;
            break;
          }
        } catch (e) {}
      }
    } catch (e) {}

    if (traversableFound) {
      results.push({
        type: TYPE.TRAVERSABLE,
        vendor: '阿里云',
        url: matchedTraverseUrl || bucketBaseUrl,
        found: traversableFound,
        request: buildBurpRequest('GET', matchedTraverseUrl || bucketBaseUrl, traversableReqHeaders, undefined),
        response: traversableResp ? buildBurpResponse(traversableResp.status, traversableResp.statusText, traversableRespHeaders, traversableText) : '',
        detail: matchedTraverseUrl ? `存储桶可遍历 (${matchedTraverseUrl})` : '存储桶可遍历'
      });
    }

    return results;
  }

  async checkUpload(url, safeMode = false) {
    const results = [];
    
    if (safeMode) {
      return results;
    }

    const testObjectName = `bt_test_${Date.now()}_${Math.random().toString(16).slice(2)}.txt`;
    const testUrl = new URL(url);
    testUrl.pathname = (testUrl.pathname.endsWith('/') ? testUrl.pathname : testUrl.pathname + '/') + testObjectName;

    let uploadFound = false;
    let uploadResp, uploadText, uploadRespHeaders;

    try {
      const testContent = 'ButterCookie Cloud Storage Security Test';
      uploadResp = await fetch(testUrl.toString(), {
        method: 'PUT',
        headers: {
          'Content-Type': 'text/plain',
        },
        body: testContent,
      });
      uploadText = await uploadResp.text();
      uploadRespHeaders = Object.fromEntries(uploadResp.headers.entries());

      if (uploadResp.status >= 200 && uploadResp.status < 300 && uploadText.includes('<ETag>')) {
        uploadFound = true;

        // 删除测试文件
        try {
          await fetch(testUrl.toString(), { method: 'DELETE' });
        } catch (e) {}
      }
    } catch (e) {}

    if (uploadFound) {
      results.push({
        type: TYPE.UPLOAD,
        vendor: '阿里云',
        url: testUrl.toString(),
        found: uploadFound,
        request: buildBurpRequest('PUT', testUrl.toString(), {
          'Content-Type': 'text/plain',
        }, 'ButterCookie Cloud Storage Security Test'),
        response: uploadResp ? buildBurpResponse(uploadResp.status, uploadResp.statusText, uploadRespHeaders, uploadText) : '',
        detail: '可未经授权上传文件到存储桶'
      });
    }

    return results;
  }

  async checkACLRead(url, checkAcl = true) {
    const results = [];
    
    if (!checkAcl) {
      return results;
    }

    const aclUrl = new URL(url);
    aclUrl.searchParams.set('acl', '');

    let aclFound = false;
    let aclResp, aclText, aclRespHeaders;

    try {
      aclResp = await fetch(aclUrl.toString(), { method: 'GET' });
      aclText = await aclResp.text();
      aclRespHeaders = Object.fromEntries(aclResp.headers.entries());

      if (aclResp.status === 200 && aclText.includes('<AccessControlPolicy>') && aclText.includes('<AccessControlList>')) {
        aclFound = true;
      }
    } catch (e) {}

    if (aclFound) {
      results.push({
        type: TYPE.ACL_READ,
        vendor: '阿里云',
        url: aclUrl.toString(),
        found: aclFound,
        request: buildBurpRequest('GET', aclUrl.toString(), {}, undefined),
        response: aclResp ? buildBurpResponse(aclResp.status, aclResp.statusText, aclRespHeaders, aclText) : '',
        detail: '存储桶 ACL 配置可被读取'
      });
    }

    return results;
  }

  async checkPolicyRead(url, checkPolicy = true) {
    const results = [];
    
    if (!checkPolicy) {
      return results;
    }

    const policyUrl = new URL(url);
    policyUrl.searchParams.set('policy', '');

    let policyFound = false;
    let policyResp, policyText, policyRespHeaders;

    try {
      policyResp = await fetch(policyUrl.toString(), { method: 'GET' });
      policyText = await policyResp.text();
      policyRespHeaders = Object.fromEntries(policyResp.headers.entries());

      if (policyResp.status === 200) {
        try {
          JSON.parse(policyText);
          if (policyText.includes('Statement') || policyText.includes('Effect')) {
            policyFound = true;
          }
        } catch (e) {}
      }
    } catch (e) {}

    if (policyFound) {
      results.push({
        type: TYPE.POLICY_READ,
        vendor: '阿里云',
        url: policyUrl.toString(),
        found: policyFound,
        request: buildBurpRequest('GET', policyUrl.toString(), {}, undefined),
        response: policyResp ? buildBurpResponse(policyResp.status, policyResp.statusText, policyRespHeaders, policyText) : '',
        detail: '存储桶 Policy 策略可被读取'
      });
    }

    return results;
  }

  async check(url, options = {}) {
    const { checkAcl = true, checkPolicy = true, safeMode = true, traverseBacktrack = false } = options;

    let results = [];
    results = results.concat(await this.checkTraversable(url, traverseBacktrack));
    
    if (!safeMode) {
      results = results.concat(await this.checkUpload(url));
    }
    
    results = results.concat(await this.checkACLRead(url, checkAcl));
    
    if (checkPolicy && !safeMode) {
      results = results.concat(await this.checkPolicyRead(url, checkPolicy));
    }

    return results;
  }
}
