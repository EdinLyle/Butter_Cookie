// 信息提取核心模块 - 从页面源码中提取各类信息（增强版）
// 改进：优化正则表达式、添加上下文来源、增强过滤逻辑、减少脏数据

const extractedPatterns = {
  // 基础信息
  IP: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  IP_PORT: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):[0-9]{1,5}\b/g,
  
  // 改进的域名正则 - 排除常见误报，只匹配有效域名
  Domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|cn|net|com\.cn|vip|top|cc|shop|club|wang|xyz|luxe|site|news|pub|fun|online|win|red|loan|ren|mom|org|link|biz|bid|help|tech|date|mobi|so|me|tv|co|vc|pw|video|party|pics|website|store|ltd|ink|trade|live|wiki|space|gift|lol|work|band|info|click|photo|market|tel|social|press|game|kim|games|pro|men|love|studio|rocks|asia|group|science|design|software|engineer|lawyer|fit|beer|io|dev|app|cloud|ai)\b/gi,
  
  // 改进的手机号正则 - 减少误报
  Phone: /(?<![\d])(?:(?:\+|00)?86)?1(?:[39]\d|4[5-79]|5[0-35-9]|6[2567]|7[0-8])\d{8}(?![\d])/g,
  Landline: /(?<![\d])(?:0\d{2,3}[- ]?)?\d{7,8}(?![\d])/g,
  '400Phone': /(?<![\d])400[- ]?(?:\d{3,4}[- ]?\d{4}|[0-9]{7,8})(?![\d])/g,
  
  Email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  
  // 改进的 JWT 正则 - 更精确的三段式
  JWT: /\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/g,
  
  Algorithm: /(?:sha-?(?:1|256|384|512)|md5|aes(?:-(?:128|256))?|rsa(?:-\d{3})?)\b/gi,
  Secret: /\b(?:secret|key|token|password|passwd|pwd)\b/gi,
  
  // 改进的路径正则 - 排除静态资源
  Path: /(?:\/(?:(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@])+(?:\/[a-zA-Z0-9\-._~!$&'()*+,;=:@]+)*))/g,
  JSFilePath: /(?:<script[^>]+src=["']([^"']+\.js(?:\?[^\s"']*)?)["']|import\s+(?:(?:\*\s+as|{[^}]+}|[a-zA-Z_$][\w$]*)\s+from\s+)?["']([^"']+\.js(?:\?[^\s"']*)?)["'])/gi,
  
  Url: /\bhttps?:\/\/[^\s/$.?#].[^\s"')>\]]*/gi,
  StaticUrl: /\.(?:jpg|jpeg|png|gif|css|js|ico|svg|woff2?|ttf|otf|eot|pdf|mp3|mp4|webm|m4a)(?:\?|$)/gi,
  
  // 增强的敏感信息检测
  IDCard: /(?<![0-9Xx])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:[0-2]\d|3[01])\d{3}(?:\d|X|x)(?![0-9Xx])/g,
  
  // 云服务密钥（增强版）
  AWS_Key: /\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b/g,
  AWS_Secret: /(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40})(?![A-Za-z0-9+/=])/g,
  GitHub_Token: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b/g,
  GitHub_PAT: /\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b/g,
  GitLab_Token: /\b(glpat-[A-Za-z0-9\-_]{20,})\b/g,
  BaiduMapKey: /(?:webapi\.amap\.com|apis\.map\.qq\.com|api\.map\.baidu\.com|map\.qq\.com|restapi\.amap\.com)(?:\/[^\s"'>]*)?/g,
  AliyunKey: /\b(LTAI[A-Za-z0-9]{12,20})\b/g,
  TencentKey: /\b(AKID[A-Za-z0-9]{13,20})\b/g,
  
  // 认证信息（增强版）
  AuthInfo: /(?:(?:basic\s+[A-Za-z0-9+/=]{20,})|(?:bearer\s+[A-Za-z0-9\-_.]{20,}))/gi,
  
  // 数据库连接字符串
  Database: /(?<![\w])(mongodb(?:\+srv)?|mysql(?:i)?|postgresql|postgres|redis|sqlite|mssql):\/\/[^\s"'<>]+/gi,
  MongoDB_URI: /mongodb(?:\+srv)?:\/\/[^\s"'<>]+/gi,
  
  // Webhook 和 API 密钥
  Webhook: /https:\/\/(?:hooks\.slack\.com\/services|discord(?:app)?\.com\/api\/webhooks)\/[^\s"'<>]+/gi,
  StripeKey: /\b((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,})\b/g,
  SendgridKey: /\bSG\.[A-Za-z0-9-_]{22}\.[A-Za-z0-9-_]{43}\b/g,
  TwilioKey: /\bSK[0-9a-fA-F]{32}\b/g,
  
  // 加密货币私钥
  CryptoPrivate: /(?<![A-Za-z0-9])(?:private[_-]?key|priv[_-]?key)[\s:=]+['"]?[A-Za-z0-9]{32,}['"]?(?![A-Za-z0-9])/gi,
  BitcoinPrivate: /(?:[13][a-km-zA-HJ-NP-Z1-9]{26,35}|bc1[a-z0-9]{39,59})(?![a-zA-Z0-9])/g,
  
  // 新增：内网 IP
  PrivateIP: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
  
  // 新增：端口号
  PortNumber: /(?<=:)\d{2,5}(?=\b)/g,
  
  // 新增：Base64 编码数据（长字符串）
  Base64Data: /(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){20,}(?:={0,2})?(?![A-Za-z0-9+/=])/g,
  
  // 新增：XML/JSON 密钥格式
  XmlKey: /<Key>[A-Za-z0-9+/=]{20,}<\/Key>/g,
  JsonApiKey: /["']?(?:api[_-]?key|apikey)["']?\s*[:=]\s*["']([A-Za-z0-9\-_]{20,})["']/gi
};

// 提取 API 时排除的静态资源扩展名
const STATIC_EXTENSIONS = [
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'svg',
  'css', 'scss', 'less',
  'js', 'jsx', 'ts', 'tsx',
  'woff', 'woff2', 'ttf', 'otf', 'eot',
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
  'zip', 'rar', 'tar', 'gz', '7z',
  'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm',
  'm4a', 'wav', 'ogg',
  'apk', 'exe', 'dmg',
  'swf', 'fla'
];

let enhancedPageSource = '';
let sourceMap = new Map(); // 存储匹配结果的来源位置

// 初始化页面源码（带位置信息）
function initPageSource() {
  if (typeof document !== 'undefined') {
    enhancedPageSource = document.documentElement.outerHTML;
    buildSourceMap();
  }
  return enhancedPageSource;
}

// 构建来源位置映射
function buildSourceMap() {
  sourceMap.clear();
  const lines = enhancedPageSource.split('\n');
  let currentPosition = 0;
  
  lines.forEach((line, lineIndex) => {
    const lineNumber = lineIndex + 1;
    sourceMap.set(currentPosition, { line: lineNumber, content: line.substring(0, 100) });
    currentPosition += line.length + 1; // +1 for newline
  });
}

// 查找匹配位置的上下文
function findContext(position, contextLength = 50) {
  const keys = Array.from(sourceMap.keys()).sort((a, b) => a - b);
  let bestMatch = null;
  
  for (const key of keys) {
    if (key <= position) {
      bestMatch = sourceMap.get(key);
    } else {
      break;
    }
  }
  
  if (bestMatch) {
    return {
      line: bestMatch.line,
      snippet: bestMatch.content
    };
  }
  return null;
}

// 增强的信息收集（带来源信息）
function collectInfo(pattern, includeContext = false) {
  if (!enhancedPageSource) {
    initPageSource();
  }
  
  const matches = [];
  const matchPositions = new Map(); // 用于去重
  
  for (const match of enhancedPageSource.matchAll(pattern)) {
    const value = match[0];
    const position = match.index;
    
    // 检查是否已存在相同值
    if (matchPositions.has(value)) {
      continue;
    }
    
    matchPositions.set(value, position);
    
    const result = { value };
    
    if (includeContext) {
      const context = findContext(position);
      if (context) {
        result.line = context.line;
        result.snippet = context.snippet;
      }
    }
    
    matches.push(result);
  }
  
  return matches;
}

// 简单的信息收集（保持兼容性）
function collectInfoSimple(pattern) {
  if (!enhancedPageSource) {
    initPageSource();
  }
  const matchPositions = new Map();
  const result = [];
  
  for (const match of enhancedPageSource.matchAll(pattern)) {
    const value = match[0];
    if (!matchPositions.has(value)) {
      matchPositions.set(value, match.index);
      result.push(value);
    }
  }
  
  return result;
}

// 增强的 URL 处理（带来源）
function dealUrl(u, baseUrl = null) {
  if (typeof window === 'undefined') return u;
  
  const protocol = window.location.protocol;
  const host = window.location.host;
  const href = baseUrl || window.location.href;
  
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

// 提取函数（返回带上下文的对象）
// 优化：过滤无效域名（如文件名、路径片段）
function extractDomains(includeContext = false) {
  const results = collectInfo(extractedPatterns.Domain, includeContext);
  // 过滤掉看起来像文件名或路径的假域名
  return results.filter(r => {
    const value = r.value.toLowerCase();
    // 排除常见误报
    if (value.includes('/') || value.includes('\\')) return false;
    if (['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.ttf'].some(ext => value.endsWith(ext))) return false;
    // 排除过短的域名（可能是误报）
    if (value.length < 5) return false;
    // 排除连续数字的域名（可能是版本号）
    if (/^\d+\.\d+\.\d+$/.test(value)) return false;
    return true;
  });
}

function extractPhones(includeContext = false) {
  const results = collectInfo(extractedPatterns.Phone, includeContext);
  return results.map(r => ({
    ...r,
    value: r.value.replace(/[^\d+]/g, '')
  }));
}

function extractEmails(includeContext = false) {
  return collectInfo(extractedPatterns.Email, includeContext);
}

function extractIPs(includeContext = false) {
  return collectInfo(extractedPatterns.IP, includeContext);
}

function extractPrivateIPs(includeContext = false) {
  return collectInfo(extractedPatterns.PrivateIP, includeContext);
}

// 优化：排除静态资源和明显的非路径内容
function extractPaths(includeContext = false) {
  const results = collectInfo(extractedPatterns.Path, includeContext);
  return results.filter(r => {
    const path = r.value;
    // 排除过短的路径
    if (path.length < 3) return false;
    // 排除看起来像域名或协议的部分
    if (path.startsWith('//') || path.includes('://')) return false;
    // 排除明显的静态资源
    if (STATIC_EXTENSIONS.some(ext => path.toLowerCase().includes('.' + ext))) return false;
    // 排除路径中连续的数字（可能是乱码）
    if (/\/\d{8,}\//.test(path)) return false;
    return true;
  });
}

function extractUrls(includeContext = false) {
  return collectInfo(extractedPatterns.Url, includeContext);
}

// 优化：排除静态资源、图片、文件下载等
function extractApis(includeContext = false) {
  const results = collectInfo(extractedPatterns.Url, includeContext);
  return results.filter(r => {
    const url = r.value.toLowerCase();
    // 排除静态资源扩展名
    if (STATIC_EXTENSIONS.some(ext => url.includes('.' + ext))) return false;
    // 排除明显不是 API 的 URL
    if (url.includes('/static/') || url.includes('/assets/') || url.includes('/images/')) return false;
    // 排除 CDN 资源
    if (url.includes('cdn.') || url.includes('googleapis.com') || url.includes('gstatic.com')) return false;
    // 保留看起来像 API 的 URL
    return url.includes('/api/') || 
           url.includes('/v') || 
           r.value.includes('?') ||
           (r.value.match(/\//g) || []).length >= 3;
  });
}

// 优化：过滤非 JS 文件和 CDN 资源
function extractJsFiles(includeContext = false) {
  const jsFiles = [];
  const seen = new Set();
  
  // 从 script 标签提取
  const rawPatterns = [extractedPatterns.JSFilePath];
  
  rawPatterns.forEach(pattern => {
    for (const match of enhancedPageSource.matchAll(pattern)) {
      const jsPath = match[1] || match[2];
      if (jsPath && !jsPath.endsWith('.map')) {
        const fullPath = dealUrl(jsPath);
        if (!seen.has(fullPath)) {
          seen.add(fullPath);
          const result = { value: fullPath };
          if (includeContext) {
            const context = findContext(match.index);
            if (context) {
              result.line = context.line;
              result.snippet = context.snippet;
            }
          }
          jsFiles.push(result);
        }
      }
    }
  });
  
  // 从 DOM 提取
  if (typeof document !== 'undefined') {
    const scripts = document.getElementsByTagName('script');
    for (const script of scripts) {
      const src = script.getAttribute('src');
      if (src && src.endsWith('.js') && !src.endsWith('.map')) {
        const fullPath = dealUrl(src);
        if (!seen.has(fullPath)) {
          seen.add(fullPath);
          jsFiles.push({ value: fullPath });
        }
      }
    }
  }
  
  // 过滤掉 CDN 和静态资源
  return jsFiles.filter(f => {
    if (!f.value || !f.value.trim()) return false;
    const url = f.value.toLowerCase();
    // 排除常见 CDN（可选择保留）
    // if (url.includes('cdn.') || url.includes('unpkg.com') || url.includes('jsdelivr.net')) return false;
    // 排除模板引擎相关的 JS
    if (url.includes('webpack/bootstrap') || url.includes('webpack/runtime')) return false;
    return true;
  });
}

function extractJWTs(includeContext = false) {
  const results = collectInfo(extractedPatterns.JWT, includeContext);
  return results.filter(r => {
    const parts = r.value.split('.');
    return parts.length === 3 && parts[0].startsWith('eyJ');
  });
}

function extractSecrets(includeContext = false) {
  return collectInfo(extractedPatterns.Secret, includeContext);
}

// 新增敏感信息提取函数（带上下文）
function extractIDCards(includeContext = false) {
  // 验证身份证校验位
  const validateIDCard = (id) => {
    const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const checkCodes = '10X98765432';
    let sum = 0;
    for (let i = 0; i < 17; i++) {
      sum += parseInt(id[i]) * weights[i];
    }
    return checkCodes[sum % 11] === id[17].toUpperCase();
  };
  
  const results = collectInfo(extractedPatterns.IDCard, includeContext);
  return results.filter(r => validateIDCard(r.value));
}

function extractAWSKeys(includeContext = false) {
  return collectInfo(extractedPatterns.AWS_Key, includeContext);
}

function extractAWSSecrets(includeContext = false) {
  return collectInfo(extractedPatterns.AWS_Secret, includeContext);
}

function extractGitHubTokens(includeContext = false) {
  return collectInfo(extractedPatterns.GitHub_Token, includeContext);
}

function extractGitLabTokens(includeContext = false) {
  return collectInfo(extractedPatterns.GitLab_Token, includeContext);
}

function extractBaiduMapKeys(includeContext = false) {
  return collectInfo(extractedPatterns.BaiduMapKey, includeContext);
}

function extractAliyunKeys(includeContext = false) {
  return collectInfo(extractedPatterns.AliyunKey, includeContext);
}

function extractTencentKeys(includeContext = false) {
  return collectInfo(extractedPatterns.TencentKey, includeContext);
}

function extractAuthTokens(includeContext = false) {
  return collectInfo(extractedPatterns.AuthInfo, includeContext);
}

function extractDatabaseUrls(includeContext = false) {
  return collectInfo(extractedPatterns.Database, includeContext);
}

function extractMongoDBURIs(includeContext = false) {
  return collectInfo(extractedPatterns.MongoDB_URI, includeContext);
}

function extractWebhooks(includeContext = false) {
  return collectInfo(extractedPatterns.Webhook, includeContext);
}

function extractStripeKeys(includeContext = false) {
  return collectInfo(extractedPatterns.StripeKey, includeContext);
}

function extractSendgridKeys(includeContext = false) {
  return collectInfo(extractedPatterns.SendgridKey, includeContext);
}

function extractPrivateKeys(includeContext = false) {
  return collectInfo(extractedPatterns.CryptoPrivate, includeContext);
}

function extractFixedPhones(includeContext = false) {
  return collectInfo(extractedPatterns.Landline, includeContext);
}

function extract400Phones(includeContext = false) {
  return collectInfo(extractedPatterns['400Phone'], includeContext);
}

function extractBase64Data(includeContext = false) {
  return collectInfo(extractedPatterns.Base64Data, includeContext);
}

function extractJSONAPIKeys(includeContext = false) {
  return collectInfo(extractedPatterns.JsonApiKey, includeContext);
}

// 使用自定义正则提取（增强版）
function extractWithCustomRegex(pattern, includeContext = false) {
  try {
    const regex = new RegExp(pattern, 'g');
    return collectInfo(regex, includeContext);
  } catch (e) {
    console.error('Invalid regex pattern:', e);
    return [];
  }
}

// 刷新页面源码
function refreshPageSource() {
  enhancedPageSource = '';
  sourceMap.clear();
  initPageSource();
}

// 统计信息
function getExtractionStats() {
  return {
    sourceLength: enhancedPageSource.length,
    lineCount: sourceMap.size,
    cacheSize: sourceMap.size
  };
}

// 导出函数
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    extractedPatterns,
    initPageSource,
    buildSourceMap,
    findContext,
    collectInfo,
    collectInfoSimple,
    dealUrl,
    // 提取函数
    extractDomains,
    extractPhones,
    extractEmails,
    extractIPs,
    extractPrivateIPs,
    extractPaths,
    extractUrls,
    extractApis,
    extractJsFiles,
    extractJWTs,
    extractSecrets,
    extractIDCards,
    extractAWSKeys,
    extractAWSSecrets,
    extractGitHubTokens,
    extractGitLabTokens,
    extractBaiduMapKeys,
    extractAliyunKeys,
    extractTencentKeys,
    extractAuthTokens,
    extractDatabaseUrls,
    extractMongoDBURIs,
    extractWebhooks,
    extractStripeKeys,
    extractSendgridKeys,
    extractPrivateKeys,
    extractFixedPhones,
    extract400Phones,
    extractBase64Data,
    extractJSONAPIKeys,
    // 工具函数
    extractWithCustomRegex,
    refreshPageSource,
    getExtractionStats
  };
}
