// 信息提取核心模块 - 从页面源码中提取各类信息

const regexPatterns = {
  IP: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  IP_PORT: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):[0-9]{1,5}\b/g,
  Domain: /[a-zA-Z0-9\-\.]*?\.(?:xin|com|cn|net|com\.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net\.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org\.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer)/gi,
  Phone: /[^\w]((?:(?:\+|00)86)?1(?:(?:3[\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\d])|(?:9[189]))\d{8})[^\w]/g,
  Landline: /(?:0\d{2,3}[- ]?)?\d{7,8}/g,
  '400Phone': /400[- ]?\d{3,4}[- ]?\d{3,4}/g,
  Email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  JWT: /[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
  Algorithm: /(sha1|sha256|md5|aes)/gi,
  Secret: /\b(secret|key|token|password)\b/gi,
  Path: /(?:\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]+)+/g,
  JSFilePath: /(?:<script[^>]+src=["']([^"']+\.js)["']|["']([^"']+\.js)["'])/gi,
  IncompletePath: /\/[^\s?#]*$/g,
  Url: /https?:\/\/[^\s/$.?#].[^\s]*/g,
  StaticUrl: /\.(jpg|jpeg|png|gif|css|js|ico|svg)$/gi,
  // 新增敏感信息检测
  IDCard: /\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])([0-2]\d|3[01])\d{3}[\dXx]\b/g,
  AWS_Key: /\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
  AWS_Secret: /\b([A-Za-z0-9+/]{40})(?=(?:[^A-Za-z0-9+/]|$))\b/g,
  GitHub_Token: /\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b/g,
  GitHub_PAT: /\b(github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b/g,
  BaiduMapKey: /webapi\.amap\.com|apis\.map\.qq\.com|api\.map\.baidu\.com|map\.qq\.com|restapi\.amap\.com/g,
  AliyunKey: /(LTAI[A-Za-z0-9]{12,20})/g,
  TencentKey: /(AKID[A-Za-z0-9]{13,20})/g,
  CryptoPrivate: /\b([a-zA-Z0-9]{32,64})\b/g,
  AuthInfo: /((basic [a-z0-9=:_\+\/-]{5,100})|(bearer [a-z0-9_.=:_\+\/-]{5,100}))/gi,
  cryptoPrivate: /\b(private[_\-]?key|priv[_\-]?key)\b/gi,
  database: /\b(mongodb|mysql|postgresql|redis|sqlite):\/\/[^\s"'<>]+/gi,
  webhook: /https:\/\/(?:hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks)\/[^\s"'<>]+/gi,
  stripeKey: /\b(sk_live_[a-zA-Z0-9]{24}|rk_live_[a-zA-Z0-9]{24})\b/g
};

let pageSource = '';

function initPageSource() {
  if (typeof document !== 'undefined') {
    pageSource = document.documentElement.outerHTML;
  }
  return pageSource;
}

function collectInfo(pattern) {
  if (!pageSource) {
    initPageSource();
  }
  const matches = pageSource.match(pattern) || [];
  return [...new Set(matches)];
}

function dealUrl(u) {
  if (typeof window === 'undefined') return u;
  
  const protocol = window.location.protocol;
  const host = window.location.host;
  const href = window.location.href;
  
  if (u.startsWith('http')) return u;
  if (u.startsWith('//')) return protocol + u;
  if (u.startsWith('/')) return protocol + '//' + host + u;
  if (u.startsWith('./')) {
    const tmpHref = href.includes('#') ? href.slice(0, href.indexOf('#')) : href;
    return tmpHref.slice(0, tmpHref.lastIndexOf('/') + 1) + u.slice(2);
  }
  const tmpHref = href.includes('#') ? href.slice(0, href.indexOf('#')) : href;
  return tmpHref.slice(0, tmpHref.lastIndexOf('/') + 1) + u;
}

function extractDomains() {
  return collectInfo(regexPatterns.Domain);
}

function extractPhones() {
  const phones = collectInfo(regexPatterns.Phone);
  return phones.map(p => p.replace(/[^\d+]/g, ''));
}

function extractEmails() {
  return collectInfo(regexPatterns.Email);
}

function extractIPs() {
  return collectInfo(regexPatterns.IP);
}

function extractPaths() {
  return [...new Set(collectInfo(regexPatterns.Path))];
}

function extractUrls() {
  return collectInfo(regexPatterns.Url);
}

function extractApis() {
  const urls = collectInfo(regexPatterns.Url);
  return urls.filter(url => !url.match(regexPatterns.StaticUrl));
}

function extractJsFiles() {
  const rawJsPaths = collectInfo(regexPatterns.JSFilePath);
  const jsFiles = [];
  
  rawJsPaths.forEach(text => {
    const matches = text.match(/(?:src=["']([^"']+\.js)["']|["']([^"']+\.js)["'])/i);
    if (matches) {
      const jsPath = matches[1] || matches[2];
      if (jsPath) {
        const fullPath = dealUrl(jsPath);
        jsFiles.push(fullPath);
      }
    }
  });
  
  // 同时从 script 标签中提取
  if (typeof document !== 'undefined') {
    const scripts = document.getElementsByTagName('script');
    for (const script of scripts) {
      const src = script.getAttribute('src');
      if (src && src.endsWith('.js')) {
        jsFiles.push(dealUrl(src));
      }
    }
  }
  
  return [...new Set(jsFiles)].filter(path => path && path.trim());
}

function extractJWTs() {
  return collectInfo(regexPatterns.JWT).filter(jwt => jwt.split('.').length === 3);
}

function extractSecrets() {
  return collectInfo(regexPatterns.Secret);
}

// 新增敏感信息提取函数
function extractIDCards() {
  return collectInfo(regexPatterns.IDCard);
}

function extractAWSKeys() {
  return collectInfo(regexPatterns.AWS_Key);
}

function extractAWSSecrets() {
  return collectInfo(regexPatterns.AWS_Secret);
}

function extractGitHubTokens() {
  return collectInfo(regexPatterns.GitHub_Token);
}

function extractBaiduMapKeys() {
  return collectInfo(regexPatterns.BaiduMapKey);
}

function extractAliyunKeys() {
  return collectInfo(regexPatterns.AliyunKey);
}

function extractTencentKeys() {
  return collectInfo(regexPatterns.TencentKey);
}

function extractAuthTokens() {
  return collectInfo(regexPatterns.AuthInfo);
}

function extractDatabaseUrls() {
  return collectInfo(regexPatterns.database);
}

function extractWebhooks() {
  return collectInfo(regexPatterns.webhook);
}

function extractStripeKeys() {
  return collectInfo(regexPatterns.stripeKey);
}

function extractPrivateKeys() {
  return collectInfo(regexPatterns.cryptoPrivate);
}

function extractFixedPhones() {
  return collectInfo(regexPatterns.Landline);
}

function extract400Phones() {
  return collectInfo(regexPatterns['400Phone']);
}

// 使用自定义正则提取
function extractWithCustomRegex(pattern) {
  try {
    const regex = new RegExp(pattern, 'g');
    return collectInfo(regex);
  } catch (e) {
    console.error('Invalid regex pattern:', e);
    return [];
  }
}

// 刷新页面源码（当页面内容变化时调用）
function refreshPageSource() {
  pageSource = '';
  initPageSource();
}

// 导出函数
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    regexPatterns,
    initPageSource,
    collectInfo,
    dealUrl,
    extractDomains,
    extractPhones,
    extractEmails,
    extractIPs,
    extractPaths,
    extractUrls,
    extractApis,
    extractJsFiles,
    extractJWTs,
    extractSecrets,
    extractWithCustomRegex,
    refreshPageSource,
    // 新增导出函数
    extractIDCards,
    extractAWSKeys,
    extractAWSSecrets,
    extractGitHubTokens,
    extractBaiduMapKeys,
    extractAliyunKeys,
    extractTencentKeys,
    extractAuthTokens,
    extractDatabaseUrls,
    extractWebhooks,
    extractStripeKeys,
    extractPrivateKeys,
    extractFixedPhones,
    extract400Phones
  };
}
