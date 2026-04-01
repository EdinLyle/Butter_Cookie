// 编码解码工具模块

// URL 编码/解码
function urlEncode(str) {
  try {
    return encodeURIComponent(str).replace(/'/g, '%27').replace(/"/g, '%22');
  } catch (e) {
    throw new Error('URL编码失败: ' + e.message);
  }
}

function urlDecode(str) {
  try {
    return decodeURIComponent(str.replace(/%27/g, "'").replace(/%22/g, '"'));
  } catch (e) {
    throw new Error('URL解码失败: 无效的编码字符串');
  }
}

// Base64 编码/解码
function base64Encode(str) {
  try {
    return btoa(unescape(encodeURIComponent(str)));
  } catch (e) {
    throw new Error('Base64编码失败: ' + e.message);
  }
}

function base64Decode(str) {
  try {
    return decodeURIComponent(escape(atob(str)));
  } catch (e) {
    throw new Error('Base64解码失败: 无效的Base64字符串');
  }
}

// Base32 编码/解码
function base32Encode(str) {
  try {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let result = '';

    // 将字符串转换为二进制
    for (let i = 0; i < str.length; i++) {
      const charCode = str.charCodeAt(i);
      bits += charCode.toString(2).padStart(8, '0');
    }

    // 补齐位数使其能被5整除
    while (bits.length % 5 !== 0) bits += '0';

    // 转换为Base32
    for (let i = 0; i < bits.length; i += 5) {
      const chunk = bits.slice(i, i + 5);
      const index = parseInt(chunk, 2);
      result += base32Chars[index];
    }

    // 补齐使其长度能被8整除
    while (result.length % 8 !== 0) result += '=';

    return result;
  } catch (e) {
    throw new Error('Base32编码失败: ' + e.message);
  }
}

function base32Decode(str) {
  try {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    str = str.replace(/=+$/, ''); // 移除填充
    let bits = '';

    // 将Base32转换为二进制
    for (let i = 0; i < str.length; i++) {
      const index = base32Chars.indexOf(str[i].toUpperCase());
      if (index === -1) throw new Error('无效的Base32字符: ' + str[i]);
      bits += index.toString(2).padStart(5, '0');
    }

    // 将二进制转换为字符串
    let result = '';
    for (let i = 0; i < bits.length - 4; i += 8) {
      const chunk = bits.slice(i, i + 8);
      const charCode = parseInt(chunk, 2);
      result += String.fromCharCode(charCode);
    }

    return result;
  } catch (e) {
    throw new Error('Base32解码失败: ' + e.message);
  }
}

// Unicode 编码/解码
function unicodeEncode(str) {
  try {
    return str.split('').map(char => {
      const code = char.charCodeAt(0);
      return '\\u' + code.toString(16).padStart(4, '0');
    }).join('');
  } catch (e) {
    throw new Error('Unicode编码失败: ' + e.message);
  }
}

function unicodeDecode(str) {
  try {
    return str.replace(/\\u([\dA-Fa-f]{4})/g, (_, code) => {
      return String.fromCharCode(parseInt(code, 16));
    });
  } catch (e) {
    throw new Error('Unicode解码失败: ' + e.message);
  }
}

// ASCII 编码/解码
function asciiEncode(str) {
  try {
    return str.split('').map(char => char.charCodeAt(0)).join(' ');
  } catch (e) {
    throw new Error('ASCII编码失败: ' + e.message);
  }
}

function asciiDecode(str) {
  try {
    return str.split(' ').map(num => {
      const code = parseInt(num);
      if (isNaN(code)) throw new Error('无效的ASCII码: ' + num);
      return String.fromCharCode(code);
    }).join('');
  } catch (e) {
    throw new Error('ASCII解码失败: ' + e.message);
  }
}

// 编码解码方法映射
const encodeDecodeMethods = {
  url: { name: 'URL', encode: urlEncode, decode: urlDecode },
  base64: { name: 'Base64', encode: base64Encode, decode: base64Decode },
  base32: { name: 'Base32', encode: base32Encode, decode: base32Decode },
  unicode: { name: 'Unicode', encode: unicodeEncode, decode: unicodeDecode },
  ascii: { name: 'ASCII', encode: asciiEncode, decode: asciiDecode }
};

// 执行编码
function encode(type, input) {
  const method = encodeDecodeMethods[type];
  if (!method) {
    throw new Error('不支持的编码类型: ' + type);
  }
  return method.encode(input);
}

// 执行解码
function decode(type, input) {
  const method = encodeDecodeMethods[type];
  if (!method) {
    throw new Error('不支持的解码类型: ' + type);
  }
  return method.decode(input);
}

// 获取所有支持的编码类型
function getSupportedMethods() {
  return Object.keys(encodeDecodeMethods).map(key => ({
    key,
    name: encodeDecodeMethods[key].name
  }));
}

// 导出函数
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    urlEncode,
    urlDecode,
    base64Encode,
    base64Decode,
    base32Encode,
    base32Decode,
    unicodeEncode,
    unicodeDecode,
    asciiEncode,
    asciiDecode,
    encode,
    decode,
    getSupportedMethods,
    encodeDecodeMethods
  };
}
