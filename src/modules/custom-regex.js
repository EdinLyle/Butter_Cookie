// 自定义正则模块 - 管理自定义正则规则和高亮设置

// 获取自定义正则规则
function getCustomRegexPatterns() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['customRegexPatterns'], (result) => {
      resolve(result.customRegexPatterns || []);
    });
  });
}

// 设置自定义正则规则
function setCustomRegexPatterns(patterns) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ customRegexPatterns: patterns }, () => {
      resolve();
    });
  });
}

// 添加单个正则规则
function addCustomRegexPattern(label, pattern) {
  return new Promise((resolve, reject) => {
    if (!label || !pattern) {
      reject(new Error('标签和正则表达式不能为空'));
      return;
    }
    
    try {
      // 验证正则表达式是否有效
      new RegExp(pattern);
      
      getCustomRegexPatterns().then(patterns => {
        // 检查是否已存在相同标签的规则
        const existingIndex = patterns.findIndex(p => p.label === label);
        if (existingIndex >= 0) {
          patterns[existingIndex].pattern = pattern;
        } else {
          patterns.push({ label, pattern });
        }
        
        setCustomRegexPatterns(patterns).then(() => {
          resolve(patterns);
        });
      });
    } catch (e) {
      reject(new Error('无效的正则表达式: ' + e.message));
    }
  });
}

// 删除正则规则
function removeCustomRegexPattern(label) {
  return new Promise((resolve) => {
    getCustomRegexPatterns().then(patterns => {
      const filtered = patterns.filter(p => p.label !== label);
      setCustomRegexPatterns(filtered).then(() => {
        resolve(filtered);
      });
    });
  });
}

// 获取高亮规则
function getHighlightRules() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['highlightRules'], (result) => {
      resolve(result.highlightRules || []);
    });
  });
}

// 设置高亮规则
function setHighlightRules(rules) {
  return new Promise((resolve) => {
    chrome.storage.local.set({ highlightRules: rules }, () => {
      resolve();
    });
  });
}

// 添加高亮关键词
function addHighlightRule(keyword) {
  return new Promise((resolve) => {
    if (!keyword || !keyword.trim()) {
      resolve([]);
      return;
    }
    
    getHighlightRules().then(rules => {
      const trimmedKeyword = keyword.trim();
      if (!rules.includes(trimmedKeyword)) {
        rules.push(trimmedKeyword);
        setHighlightRules(rules).then(() => {
          resolve(rules);
        });
      } else {
        resolve(rules);
      }
    });
  });
}

// 移除高亮关键词
function removeHighlightRule(keyword) {
  return new Promise((resolve) => {
    getHighlightRules().then(rules => {
      const filtered = rules.filter(r => r !== keyword);
      setHighlightRules(filtered).then(() => {
        resolve(filtered);
      });
    });
  });
}

// 检查值是否需要高亮
function shouldHighlight(value) {
  return new Promise((resolve) => {
    getHighlightRules().then(rules => {
      resolve(rules.some(rule => value.includes(rule)));
    });
  });
}

// 导出函数
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    getCustomRegexPatterns,
    setCustomRegexPatterns,
    addCustomRegexPattern,
    removeCustomRegexPattern,
    getHighlightRules,
    setHighlightRules,
    addHighlightRule,
    removeHighlightRule,
    shouldHighlight
  };
}
