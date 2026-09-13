/**
 * 工具函数
 * ============================================================================

 */

import { fastHash } from './crypto.js';

function safeNumber(value, fallback = 0) {
    return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

/**
 * 采集运行环境指纹。它的价值是"跨记录的环境漂移分析"（换设备、疑似自动化），
 * 这类判断真正做起来应该在服务端（README §9.1 第 5 条），客户端只负责如实留痕。
 */
function captureRuntimeContext() {
    const nav = typeof navigator !== 'undefined' ? navigator : {};
    const scr = typeof screen !== 'undefined' ? screen : {};
    const perf = typeof performance !== 'undefined' ? performance : null;

    let timeZone = 'unknown';
    try { timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown'; } catch { /* 忽略 */ }

    return {
        memoryUsage: safeNumber(perf?.memory?.usedJSHeapSize),
        userAgentHash: fastHash(String(nav.userAgent || '')),
        screenSize: `${safeNumber(scr.width)}x${safeNumber(scr.height)}`,
        timeZone,
        language: String(nav.language || 'unknown'),
        platform: String(nav.platform || 'unknown'),
        colorDepth: safeNumber(scr.colorDepth),
        pixelRatio: safeNumber(typeof globalThis.devicePixelRatio === 'number' ? globalThis.devicePixelRatio : 1, 1),
        timestamp: Date.now(),
        performanceNow: Math.round(safeNumber(perf?.now?.())),
    };
}

function deepFreeze(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    Object.freeze(obj);
    for (const prop of Object.getOwnPropertyNames(obj)) {
        const value = obj[prop];
        if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) deepFreeze(value);
    }
    return obj;
}

function deepEqual(a, b) {
    if (a === b) return true;
    if (a === null || b === null || a === undefined || b === undefined) return false;
    if (typeof a !== typeof b) return false;
    if (typeof a !== 'object') return false;
    if (Array.isArray(a) !== Array.isArray(b)) return false;
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    if (keysA.length !== keysB.length) return false;
    for (const key of keysA) {
        if (!Object.prototype.hasOwnProperty.call(b, key)) return false;
        if (!deepEqual(a[key], b[key])) return false;
    }
    return true;
}

function safeStringify(obj) {
    const seen = new WeakSet();
    return JSON.stringify(obj, (key, value) => {
        if (typeof value === 'object' && value !== null) {
            if (seen.has(value)) return '[Circular]';
            seen.add(value);
        }
        return value;
    });
}

/**
 * 反调试启发式。
 *
 * v1 的 antiDebugDetection 有三个会误伤正常玩家的判据，已全部移除：
 *   · navigator.plugins.length === 0 —— Firefox 与多数移动浏览器普遍命中；
 *   · window.chrome && !window.chrome.loadTimes —— loadTimes 早已废弃；
 *   · 每 2 秒执行一次 `new Function('debugger')()` —— 会真的冻住正常玩家的 DevTools。
 * 任一命中就把 debugDetected 永久置真、之后所有 recordOperation 抛错，
 * 结果是"正常玩家玩不了，作弊者照样作弊"。
 *
 * 现在只保留信噪比可接受的判据，并且返回"信号"而非"结论"——
 * 由引擎累计多次命中后才认定，且默认只留痕不阻断。
 */
function detectDebugSignals() {
    const signals = [];

    // 自动化浏览器（Selenium / Puppeteer 默认会置位）
    try {
        if (typeof navigator !== 'undefined' && navigator.webdriver === true) signals.push('webdriver');
    } catch { /* 忽略 */ }

    // 时间侧信道：阈值给得很宽，避免把低端设备的卡顿当成断点
    try {
        const start = performance.now();
        let acc = 0;
        for (let i = 0; i < 20000; i++) acc += Math.sqrt(i);
        const elapsed = performance.now() - start;
        if (elapsed > 250) signals.push(`timing:${Math.round(elapsed)}ms`);
        if (acc < 0) signals.push('impossible');   // 防止循环被优化掉
    } catch { /* 忽略 */ }

    return { suspicious: signals.length > 0, signals, at: Date.now() };
}

/**
 * `debugger` 陷阱。会在 DevTools 打开时真的断下来，对正常玩家是明显的骚扰，
 * 因此不进默认检测链；确实需要时由宿主自行按需调用。
 */
function debuggerTrapDetect(thresholdMs = 100) {
    const start = performance.now();
    // eslint-disable-next-line no-debugger
    debugger;
    return performance.now() - start > thresholdMs;
}

export {
    captureRuntimeContext, deepFreeze, deepEqual, safeStringify,
    detectDebugSignals, debuggerTrapDetect,
};
