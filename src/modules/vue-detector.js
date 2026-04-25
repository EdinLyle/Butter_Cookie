// Vue 快速检测模块 - 基于 VueCrack 功能迁移
// 功能：检测 Vue 框架、分析路由结构、清除路由守卫、修改路由 auth 字段

(function() {
  'use strict';
  
  // 存储检测结果
  let vueDetectionResult = null;
  let routerAnalysisResult = null;
  
  // ======== 工具函数 ========
  
  // 广度优先查找 Vue 根实例
  function findVueRoot(root, maxDepth = 1000) {
    const queue = [{ node: root, depth: 0 }];
    while (queue.length) {
      const { node, depth } = queue.shift();
      if (depth > maxDepth) break;
      
      if (node.__vue_app__ || node.__vue__ || node._vnode) {
        return node;
      }
      
      if (node.nodeType === 1 && node.childNodes) {
        for (let i = 0; i < node.childNodes.length; i++) {
          queue.push({ node: node.childNodes[i], depth: depth + 1 });
        }
      }
    }
    return null;
  }
  
  // 获取 Vue 版本
  function getVueVersion(vueRoot) {
    let version = vueRoot.__vue_app__?.version ||
      vueRoot.__vue__?.$root?.$options?._base?.version;
    
    if (!version || version === 'unknown') {
      if (window.Vue && window.Vue.version) {
        version = window.Vue.version;
      } else if (window.__VUE_DEVTOOLS_GLOBAL_HOOK__?.Vue?.version) {
        version = window.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue.version;
      }
    }
    
    return version || 'unknown';
  }
  
  // 查找 Vue Router 实例
  function findVueRouter(vueRoot) {
    try {
      if (vueRoot.__vue_app__) {
        // Vue 3 + Router 4
        const app = vueRoot.__vue_app__;
        if (app.config?.globalProperties?.$router) {
          return app.config.globalProperties.$router;
        }
        const instance = app._instance;
        if (instance?.appContext?.config?.globalProperties?.$router) {
          return instance.appContext.config.globalProperties.$router;
        }
        if (instance?.ctx?.$router) {
          return instance.ctx.$router;
        }
      }
      
      if (vueRoot.__vue__) {
        // Vue 2 + Router 2/3
        const vue = vueRoot.__vue__;
        return vue.$router || vue.$root?.$router || vue.$root?.$options?.router || vue._router;
      }
    } catch (e) {
      console.error('[VueDetect] findVueRouter error:', e);
    }
    return null;
  }
  
  // 路径拼接
  function joinPath(base, path) {
    if (!path) return base || '/';
    if (path.startsWith('/')) return path;
    if (!base || base === '/') return '/' + path;
    return (base.endsWith('/') ? base.slice(0, -1) : base) + '/' + path;
  }
  
  // 判断 meta.auth 是否表示需要鉴权
  function isAuthTrue(val) {
    return val === true || val === 'true' || val === 1 || val === '1';
  }
  
  // 提取 Router 基础路径
  function extractRouterBase(router) {
    try {
      return router.options?.base || router.history?.base || '';
    } catch (e) {
      return '';
    }
  }
  
  // URL 清理
  function cleanUrl(url) {
    return url.replace(/([^:]\/)\/+/g, '$1').replace(/\/$/, '');
  }
  
  // 分析页面链接
  function analyzePageLinks() {
    const result = {
      detectedBasePath: '',
      commonPrefixes: []
    };
    
    try {
      const links = Array.from(document.querySelectorAll('a[href]'))
        .map(a => a.getAttribute('href'))
        .filter(href => href && href.startsWith('/') && !href.startsWith('//') && !href.includes('.'));
      
      if (links.length < 3) return result;
      
      const pathSegments = links.map(link => link.split('/').filter(Boolean));
      const firstSegments = {};
      
      pathSegments.forEach(segments => {
        if (segments.length > 0) {
          const first = segments[0];
          firstSegments[first] = (firstSegments[first] || 0) + 1;
        }
      });
      
      const sortedPrefixes = Object.entries(firstSegments)
        .sort((a, b) => b[1] - a[1])
        .map(entry => ({ prefix: entry[0], count: entry[1] }));
      
      result.commonPrefixes = sortedPrefixes;
      
      if (sortedPrefixes.length > 0 && sortedPrefixes[0].count / links.length > 0.6) {
        result.detectedBasePath = '/' + sortedPrefixes[0].prefix;
      }
    } catch (e) {
      console.error('[VueDetect] analyzePageLinks error:', e);
    }
    
    return result;
  }
  
  // 修改路由 meta auth 字段
  function patchAllRouteAuth(router) {
    const modified = [];
    
    function patchMeta(route) {
      if (route.meta && typeof route.meta === 'object') {
        Object.keys(route.meta).forEach(key => {
          if (key.toLowerCase().includes('auth') && isAuthTrue(route.meta[key])) {
            route.meta[key] = false;
            modified.push({ path: route.path, name: route.name });
          }
        });
      }
    }
    
    try {
      if (typeof router.getRoutes === 'function') {
        router.getRoutes().forEach(patchMeta);
      } else if (router.options?.routes) {
        function walkRoutes(routes) {
          if (!Array.isArray(routes)) return;
          routes.forEach(route => {
            patchMeta(route);
            if (Array.isArray(route.children)) walkRoutes(route.children);
          });
        }
        walkRoutes(router.options.routes);
      } else if (router.matcher) {
        if (typeof router.matcher.getRoutes === 'function') {
          router.matcher.getRoutes().forEach(patchMeta);
        }
      } else {
        console.warn('[VueDetect] 未识别的 Vue Router 版本，跳过 Route Auth Patch');
      }
    } catch (e) {
      console.error('[VueDetect] patchAllRouteAuth error:', e);
    }
    
    if (modified.length) {
      console.log('[VueDetect] 已修改的路由 auth meta:', modified);
    }
    
    return modified;
  }
  
  // 清除路由守卫
  function patchRouterGuards(router) {
    try {
      ['beforeEach', 'beforeResolve', 'afterEach'].forEach(hook => {
        if (typeof router[hook] === 'function') {
          router[hook] = () => {};
        }
      });
      
      ['beforeGuards', 'beforeResolveGuards', 'afterGuards', 'beforeHooks', 'resolveHooks', 'afterHooks']
        .forEach(prop => {
          if (Array.isArray(router[prop])) {
            router[prop].length = 0;
          }
        });
      
      console.log('[VueDetect] 路由守卫已清除');
    } catch (e) {
      console.error('[VueDetect] patchRouterGuards error:', e);
    }
  }
  
  // 数据序列化（避免循环引用）
  function sanitizeRouteObject(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    const sanitized = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        const value = obj[key];
        if (value instanceof Function || value instanceof Promise) {
          sanitized[key] = '[Function]';
        } else if (typeof value === 'object' && value !== null) {
          sanitized[key] = '[Object]';
        } else {
          sanitized[key] = value;
        }
      }
    }
    return sanitized;
  }
  
  // 列出所有路由
  function listAllRoutes(router) {
    const list = [];
    try {
      if (typeof router.getRoutes === 'function') {
        router.getRoutes().forEach(r => {
          list.push({ name: r.name, path: r.path, meta: sanitizeRouteObject(r.meta || {}) });
        });
      } else if (router.options?.routes) {
        function traverse(routes, basePath = '') {
          routes.forEach(r => {
            const fullPath = joinPath(basePath, r.path);
            list.push({ name: r.name, path: fullPath, meta: sanitizeRouteObject(r.meta || {}) });
            if (Array.isArray(r.children)) traverse(r.children, fullPath);
          });
        }
        traverse(router.options.routes);
      } else if (router.matcher?.getRoutes) {
        router.matcher.getRoutes().forEach(r => {
          list.push({ name: r.name, path: r.path, meta: sanitizeRouteObject(r.meta || {}) });
        });
      } else if (router.history?.current?.matched) {
        router.history.current.matched.forEach(r => {
          list.push({ name: r.name, path: r.path, meta: sanitizeRouteObject(r.meta || {}) });
        });
      } else {
        console.warn('[VueDetect] 无法列出路由信息');
      }
    } catch (e) {
      console.error('[VueDetect] listAllRoutes error:', e);
    }
    return list;
  }
  
  // 执行完整分析
  function performFullAnalysis() {
    const result = {
      vueDetected: false,
      vueVersion: null,
      routerDetected: false,
      modifiedRoutes: [],
      allRoutes: [],
      routerBase: '',
      pageAnalysis: {
        detectedBasePath: '',
        commonPrefixes: []
      },
      currentPath: window.location.pathname,
      currentHash: window.location.hash
    };
    
    try {
      result.vueDetected = true;
      const vueRoot = findVueRoot(document.body);
      result.vueVersion = getVueVersion(vueRoot);
      
      const router = findVueRouter(vueRoot);
      if (!router) {
        console.error('[VueDetect] 未检测到 Vue Router 实例');
        return result;
      }
      
      result.routerDetected = true;
      result.routerBase = extractRouterBase(router);
      result.pageAnalysis = analyzePageLinks();
      result.modifiedRoutes = patchAllRouteAuth(router);
      patchRouterGuards(router);
      result.allRoutes = listAllRoutes(router);
      
      return result;
    } catch (e) {
      console.error('[VueDetect] performFullAnalysis error:', e);
      return { ...result, error: e.toString() };
    }
  }
  
  // ======== 对外暴露的 API ========
  
  window.__BUTTER_COOKIE_VUE = {
    // 检测 Vue
    detectVue: function() {
      if (vueDetectionResult) return vueDetectionResult;
      
      const vueRoot = findVueRoot(document.body);
      vueDetectionResult = {
        detected: !!vueRoot,
        method: vueRoot ? 'Immediate detection' : 'Detection failed'
      };
      
      if (vueRoot) {
        vueDetectionResult.vueVersion = getVueVersion(vueRoot);
      }
      
      return vueDetectionResult;
    },
    
    // 分析路由
    analyzeRouter: function() {
      if (routerAnalysisResult) return routerAnalysisResult;
      
      const vueRoot = findVueRoot(document.body);
      if (!vueRoot) {
        routerAnalysisResult = {
          vueDetected: false,
          routerDetected: false,
          error: 'Vue not detected'
        };
        return routerAnalysisResult;
      }
      
      routerAnalysisResult = performFullAnalysis();
      return routerAnalysisResult;
    },
    
    // 获取分析结果
    getResult: function() {
      return {
        vue: vueDetectionResult,
        router: routerAnalysisResult
      };
    },
    
    // 清除缓存
    clearCache: function() {
      vueDetectionResult = null;
      routerAnalysisResult = null;
    }
  };
  
  // ======== 自动检测（可选）========
  // 如果页面加载完成后需要立即检测，可以取消下面的注释
  /*
  document.addEventListener('DOMContentLoaded', function() {
    setTimeout(() => {
      window.__BUTTER_COOKIE_VUE.detectVue();
    }, 500);
  });
  */
  
})();
