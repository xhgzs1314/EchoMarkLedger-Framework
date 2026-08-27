/**
 * 工具函数模块
 */

async function sha256(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(String(input));
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function sha256Sync(input) {
    // 备用
    let h1 = 0x6a09e667, h2 = 0xbb67ae85, h3 = 0x3c6ef372, h4 = 0xa54ff53a;
    const str = String(input);
    for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        h1 = ((h1 << 5) + h1 + c + (h1 >>> 27)) | 0;
        h2 = ((h2 << 7) + h2 + c + (h2 >>> 25)) | 0;
        h3 = ((h3 << 11) + h3 + c + (h3 >>> 21)) | 0;
        h4 = ((h4 << 13) + h4 + c + (h4 >>> 19)) | 0;
    }
    const pad = (n) => (n >>> 0).toString(16).padStart(8, '0');
    return (pad(h1) + pad(h2) + pad(h3) + pad(h4)).repeat(2).slice(0, 64);
}

function generateNonce(length = 16) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

function fisherYatesShuffle(array, seed) {
    const arr = [...array];
    let state = parseInt(seed.slice(0, 16), 16) || 1;
    const lcg = () => {
        state = (state * 1664525 + 1013904223) % 4294967296;
        return state / 4294967296;
    };
    for (let i = arr.length - 1; i > 0; i--) {
        const j = Math.floor(lcg() * (i + 1));
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

function deriveRandomFromSeed(seed, min, max) {
    let state = parseInt(seed.slice(0, 16), 16) || 1;
    const lcg = () => {
        state = (state * 1664525 + 1013904223) % 4294967296;
        return state / 4294967296;
    };
    lcg(); 
    return Math.floor(lcg() * (max - min + 1)) + min;
}

function captureRuntimeContext() {
    return {
        memoryUsage: performance.memory ? performance.memory.usedJSHeapSize : 0,
        userAgentHash: sha256Sync(navigator.userAgent),
        screenSize: `${screen.width}x${screen.height}`,
        timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        language: navigator.language,
        platform: navigator.platform,
        colorDepth: screen.colorDepth,
        pixelRatio: window.devicePixelRatio || 1,
        timestamp: Date.now(),
        performanceNow: performance.now()
    };
}

function deepEqual(a, b) {
    if (a === b) return true;
    if (a == null || b == null) return false;
    if (typeof a !== typeof b) return false;
    if (typeof a !== 'object') return false;
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    if (keysA.length !== keysB.length) return false;
    for (const key of keysA) {
        if (!keysB.includes(key)) return false;
        if (!deepEqual(a[key], b[key])) return false;
    }
    return true;
}

function serializeForHash(obj) {
    if (obj === null || obj === undefined) return '';
    if (typeof obj === 'string') return obj;
    if (typeof obj === 'number') return String(obj);
    if (typeof obj === 'boolean') return obj ? '1' : '0';
    if (Array.isArray(obj)) return obj.map(serializeForHash).join('|');
    if (typeof obj === 'object') {
        const keys = Object.keys(obj).sort();
        return keys.map(k => `${k}:${serializeForHash(obj[k])}`).join(';');
    }
    return String(obj);
}

function antiDebugDetection() {
    const start = performance.now();
    (function(){})['constructor']('debugger')();
    const end = performance.now();
    const hasWebdriver = !!navigator.webdriver;
    const hasChromeMissing = window.chrome && !window.chrome.loadTimes;
    const hasNoPlugins = navigator.plugins.length === 0;
    return (end - start) > 100 || hasWebdriver || hasChromeMissing || hasNoPlugins;
}

function deepFreeze(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    Object.freeze(obj);
    Object.getOwnPropertyNames(obj).forEach(prop => {
        if (obj[prop] !== null && typeof obj[prop] === 'object') deepFreeze(obj[prop]);
    });
    return obj;
}

async function deriveDynamicSalt(stateHash, offset, extra = '') {
    return await sha256(`${stateHash}:${offset}:${extra}:${Date.now()}`);
}

async function deriveOffset(stateHash, operationType, timestamp, index) {
    const hash = await sha256(`${stateHash}:${operationType}:${timestamp}:${index}`);
    return parseInt(hash.slice(0, 8), 16) % 1000000;
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
function computeSlotPosition(logicalIndex, seed, slotSpace = 100000) {
    const hash = sha256Sync(`${seed}:${logicalIndex}:slot`);
    return parseInt(hash.slice(0, 12), 16) % slotSpace;
}
export { 
  sha256, sha256Sync, generateNonce, fisherYatesShuffle, 
  deriveRandomFromSeed, captureRuntimeContext, deepEqual, 
  serializeForHash, antiDebugDetection, deepFreeze, 
  deriveDynamicSalt, deriveOffset, safeStringify, computeSlotPosition 
};