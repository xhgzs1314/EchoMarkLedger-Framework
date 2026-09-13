/**
 * 测试用的浏览器环境模拟。
 * 真实目标是浏览器；这里用 fake-indexeddb + Node 的 WebCrypto 把框架跑起来，
 * 以便把"攻击者视角"的对抗测试固化成可重复执行的回归。
 */
import 'fake-indexeddb/auto';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
globalThis.window = globalThis;

globalThis.navigator = {
    userAgent: 'TestAgent/2.0',
    language: 'zh-CN',
    platform: 'Test',
    webdriver: false,
};
globalThis.screen = { width: 1920, height: 1080, colorDepth: 24 };
globalThis.devicePixelRatio = 1;
globalThis.outerWidth = 1920; globalThis.innerWidth = 1920;
globalThis.outerHeight = 1080; globalThis.innerHeight = 1000;
globalThis.location = { origin: 'https://test.local' };

// 简易 localStorage（高水位镜像会用到）
const _ls = new Map();
globalThis.localStorage = {
    getItem: (k) => (_ls.has(k) ? _ls.get(k) : null),
    setItem: (k, v) => { _ls.set(k, String(v)); },
    removeItem: (k) => { _ls.delete(k); },
    clear: () => { _ls.clear(); },
};

/**
 * 加载 IIFE 产物，返回其公开命名空间（冻结的 EchoMarkSys）。
 * 产物内部名为 __EchoMarkInternal；公开 API 是它的 .EchoMarkSys。
 */
export function loadBundle(path) {
    const code = readFileSync(path, 'utf8');
    const internal = new Function(`${code}; return __EchoMarkInternal;`)();
    return internal.EchoMarkSys;
}

/** 一个带内存存档槽的引擎工厂，省掉每个用例都写 onLoad/onSave。 */
export function makeEngineFactory(EchoMarkLedger) {
    return function createEngine(gameId, options = {}) {
        const box = { save: null };
        const engine = new EchoMarkLedger({
            gameId,
            onLoad: async () => box.save,
            onSave: async (save) => { box.save = save; },
            ...options,
        });
        return { engine, box };
    };
}

export const clone = (value) => JSON.parse(JSON.stringify(value));
