/**
 * 青云 QingStor 存储桶检测器
 * @module modules/cloud-storage/detectors/qing
 */

import { BaseDetector } from '../base-detector.js';
import { RISK_LEVELS, RISK_TYPES } from '../index.js';

/**
 * 青云 QingStor 检测器类
 */
class QingDetector extends BaseDetector {
  constructor() {
    super('qing', '青云 QingStor');
  }

  /**
   * 检测可遍历漏洞
   * @param {string} url - 存储桶 URL
   * @param {object} options - 检测选项
   * @returns {Promise<object|null>} 漏洞详情或 null
   */
  async checkTraversable(url, options = {}) {
    const candidates = this.buildListingCandidates(url);

    for (const targetUrl of candidates) {
      try {
        const resp = await this.sendRequest(targetUrl, {
          method: 'GET',
          headers: { 'User-Agent': this.getUserAgent() },
        });

        if (resp.status === 200 && resp.body) {
          // 青云 QingStor 列表响应特征
          const isTraversable =
            (resp.body.includes('<ListBucketResult') || resp.body.includes('<ListAllMyBucketsResult>')) &&
            (resp.body.includes('<Key>') || resp.body.includes('<Location>'));

          if (isTraversable) {
            return this.createVulnerability(
              url,
              RISK_LEVELS.CRITICAL,
              RISK_TYPES.TRAVERSABLE,
              targetUrl,
              'GET',
              resp,
              '存储桶可公开遍历，可查看桶内文件列表',
              {
                feature: '青云 QingStor 列表响应',
                indicators: ['<ListBucketResult>', '<Key>'],
              },
            );
          }
        }
      } catch (error) {
        if (options.debug) {
          console.warn(`[青云检测器] 检测可遍历漏洞失败：${error.message}`);
        }
      }
    }

    return null;
  }

  /**
   * 检测 PUT 上传漏洞
   * @param {string} url - 存储桶 URL
   * @param {object} options - 检测选项
   * @returns {Promise<object|null>} 漏洞详情或 null
   */
  async checkUpload(url, options = {}) {
    if (options.safeMode !== false) {
      try {
        const resp = await this.sendRequest(url, {
          method: 'OPTIONS',
          headers: {
            'User-Agent': this.getUserAgent(),
            'Access-Control-Request-Method': 'PUT',
            'Origin': 'https://example.com',
          },
        });

        const allowHeader = resp.headers?.['access-control-allow-methods']?.toLowerCase() || '';
        if (resp.status === 200 && allowHeader.includes('put')) {
          return this.createVulnerability(
            url,
            RISK_LEVELS.HIGH,
            RISK_TYPES.UPLOAD,
            url,
            'OPTIONS',
            resp,
            'CORS 配置允许 PUT 方法上传文件',
            {
              feature: 'CORS OPTIONS 响应允许 PUT',
              allowMethods: allowHeader,
            },
          );
        }
      } catch (error) {
        if (options.debug) {
          console.warn(`[青云检测器] OPTIONS 检测失败：${error.message}`);
        }
      }
    }

    return null;
  }

  /**
   * 检测 ACL 可读漏洞
   * @param {string} url - 存储桶 URL
   * @param {object} options - 检测选项
   * @returns {Promise<object|null>} 漏洞详情或 null
   */
  async checkACLRead(url, options = {}) {
    const aclUrl = this.appendQuery(url, '?acl');

    try {
      const resp = await this.sendRequest(aclUrl, {
        method: 'GET',
        headers: { 'User-Agent': this.getUserAgent() },
      });

      if (resp.status === 200 && resp.body) {
        const isAclReadable =
          resp.body.includes('<AccessControlPolicy>') ||
          resp.body.includes('<Grant>');

        if (isAclReadable) {
          return this.createVulnerability(
            url,
            RISK_LEVELS.HIGH,
            RISK_TYPES.ACL_READ,
            aclUrl,
            'GET',
            resp,
            '存储桶 ACL 配置可公开读取',
            {
              feature: '青云 QingStor ACL XML 响应',
              indicators: ['<AccessControlPolicy>', '<Grant>'],
            },
          );
        }
      }
    } catch (error) {
      if (options.debug) {
        console.warn(`[青云检测器] ACL 读取检测失败：${error.message}`);
      }
    }

    return null;
  }

  /**
   * 检测 ACL 可写漏洞
   * @param {string} url - 存储桶 URL
   * @param {object} options - 检测选项
   * @returns {Promise<object|null>} 漏洞详情或 null
   */
  async checkACLWrite(url, options = {}) {
    if (options.safeMode !== false) {
      try {
        const aclUrl = this.appendQuery(url, '?acl');
        const resp = await this.sendRequest(aclUrl, {
          method: 'OPTIONS',
          headers: {
            'User-Agent': this.getUserAgent(),
            'Access-Control-Request-Method': 'PUT',
            'Origin': 'https://example.com',
          },
        });

        const allowHeader = resp.headers?.['access-control-allow-methods']?.toLowerCase() || '';
        if (resp.status === 200 && allowHeader.includes('put')) {
          return this.createVulnerability(
            url,
            RISK_LEVELS.CRITICAL,
            RISK_TYPES.ACL_WRITE,
            aclUrl,
            'OPTIONS',
            resp,
            'CORS 配置允许 PUT 方法修改 ACL',
            {
              feature: 'CORS OPTIONS 响应允许 PUT ACL',
              allowMethods: allowHeader,
            },
          );
        }
      } catch (error) {
        if (options.debug) {
          console.warn(`[青云检测器] ACL 写入检测失败：${error.message}`);
        }
      }
    }

    return null;
  }

  /**
   * 检测 Policy 可读漏洞
   * @param {string} url - 存储桶 URL
   * @param {object} options - 检测选项
   * @returns {Promise<object|null>} 漏洞详情或 null
   */
  async checkPolicyRead(url, options = {}) {
    const policyUrl = this.appendQuery(url, '?policy');

    try {
      const resp = await this.sendRequest(policyUrl, {
        method: 'GET',
        headers: { 'User-Agent': this.getUserAgent() },
      });

      if (resp.status === 200 && resp.body) {
        try {
          const policy = JSON.parse(resp.body);
          const isPolicyReadable =
            policy &&
            Array.isArray(policy.Statement) &&
            policy.Statement.some(stmt => stmt.Effect);

          if (isPolicyReadable) {
            return this.createVulnerability(
              url,
              RISK_LEVELS.MEDIUM,
              RISK_TYPES.POLICY_READ,
              policyUrl,
              'GET',
              resp,
              '存储桶 Policy 策略可公开读取',
              {
                feature: '青云 QingStor Policy JSON 响应',
                statementCount: policy.Statement?.length || 0,
              },
            );
          }
        } catch (e) {
          // 不是有效 JSON，忽略
        }
      }
    } catch (error) {
      if (options.debug) {
        console.warn(`[青云检测器] Policy 读取检测失败：${error.message}`);
      }
    }

    return null;
  }

  /**
   * 检测 Policy 可写漏洞
   * @param {string} url - 存储桶 URL
   * @param {object} options - 检测选项
   * @returns {Promise<object|null>} 漏洞详情或 null
   */
  async checkPolicyWrite(url, options = {}) {
    if (options.safeMode !== false) {
      try {
        const policyUrl = this.appendQuery(url, '?policy');
        const resp = await this.sendRequest(policyUrl, {
          method: 'OPTIONS',
          headers: {
            'User-Agent': this.getUserAgent(),
            'Access-Control-Request-Method': 'PUT',
            'Origin': 'https://example.com',
          },
        });

        const allowHeader = resp.headers?.['access-control-allow-methods']?.toLowerCase() || '';
        if (resp.status === 200 && allowHeader.includes('put')) {
          return this.createVulnerability(
            url,
            RISK_LEVELS.CRITICAL,
            RISK_TYPES.POLICY_WRITE,
            policyUrl,
            'OPTIONS',
            resp,
            'CORS 配置允许 PUT 方法修改 Policy',
            {
              feature: 'CORS OPTIONS 响应允许 PUT Policy',
              allowMethods: allowHeader,
            },
          );
        }
      } catch (error) {
        if (options.debug) {
          console.warn(`[青云检测器] Policy 写入检测失败：${error.message}`);
        }
      }
    }

    return null;
  }
}

// 导出单例
const detector = new QingDetector();

/**
 * 青云 QingStor 检测入口
 * @param {string} url - 存储桶 URL
 * @param {object} options - 检测选项
 * @returns {Promise<object[]>} 漏洞列表
 */
export async function checkQing(url, options = {}) {
  return detector.check(url, options);
}

export default detector;
