// 信息提取核心模块 - 从页面源码中提取各类信息

const regexPatterns = {
  IP: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  IP_PORT: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):[0-9]{1,5}\b/g,
  域名: /[a-zA-Z0-9\-\.]*?\.(?:xin|com|cn|net|com\.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|net\.cn|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|org\.cn|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer)/gi,
  手机号: /[^\w]((?:(?:\+|00)86)?1(?:(?:3[\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\d])|(?:9[189]))\d{8})[^\w]/g,
  邮箱: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  JWT: /[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
  算法: /(sha1|sha256|md5|aes)/gi,
  Secret: /\b(secret|key|token|password)\b/gi,
  Path: /(?:\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]+)+/g,
  JS文件路径: /(?:<script[^>]+src=["']([^"']+\.js)["']|["']([^"']+\.js)["'])/gi,
  IncompletePath: /\/[^\s?#]*$/g,
  Url: /https?:\/\/[^\s/$.?#].[^\s]*/g,
  StaticUrl: /\.(jpg|jpeg|png|gif|css|js|ico|svg)$/gi
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
  return collectInfo(regexPatterns.域名);
}

function extractPhones() {
  const phones = collectInfo(regexPatterns.手机号);
  return phones.map(p => p.replace(/[^\d+]/g, ''));
}

function extractEmails() {
  return collectInfo(regexPatterns.邮箱);
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
  const rawJsPaths = collectInfo(regexPatterns['JS文件路径']);
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
  
  // 同时从script标签中提取
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
    refreshPageSource
  };
}
