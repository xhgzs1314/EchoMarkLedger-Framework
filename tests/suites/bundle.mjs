/**
 * 真实产物（dist/）的行为。
 *
 */
import { readFileSync, existsSync } from 'node:fs';
import { loadBundle } from '../env.mjs';
import { clone } from '../helpers.mjs';

export const name = 'bundle：产物不依赖可写全局（v1 一行即可劫持）';

const FORBIDDEN = [
    'sha256', 'hmac', 'canonical', 'canonicalFor', 'fastHash',
    'serializeForHash', 'sha256Sync', 'QuadStorage', 'EchoMarkLedger',
    'computeSlotPosition', 'loadIdentity', 'deepFreeze', 'safeStringify',
];

export default async function (t) {
    const core = 'dist/EchoMarkLedger.js';
    const secure = 'dist/EchoMarkLedger-secure.js';
    t.ok(existsSync(core) && existsSync(secure), '两个产物都已构建（先跑 npm run build）');

    // ---- 1. 沙箱体检：产物是否读取了禁用的全局名 ----
    for (const [path, label] of [[core, '核心版'], [secure, '完整版']]) {
        const touched = auditFreeGlobals(readFileSync(path, 'utf8'));
        t.eq(touched.length, 0,
            `${label}产物没有读取任何内部助手的全局名${touched.length ? `（命中 ${touched.join(', ')}）` : ''}`);
    }

    // ---- 2. 体检器本身不是空跑：喂一段确实会读全局的代码 ----
    const sanity = auditFreeGlobals('var EchoMarkSys = (function(){ return typeof sha256; })();');
    t.ok(sanity.includes('sha256'), '体检器能抓到真正的自由全局读取（避免用例形同空转）');

    // ---- 3. 产物暴露面 ----
    const S = loadBundle(core);
    t.ok(Object.isFrozen(S), 'EchoMarkSys 命名空间已冻结');
    t.eq(typeof S.EchoMarkLedger, 'function', '引擎类可用');
    for (const name of ['sha256', 'sha256Sync', 'serializeForHash', 'canonical', 'hmac', 'generateNonce']) {
        t.eq(S[name], undefined, `内部实现 ${name} 不对外导出`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'EchoMarkSys');
    t.ok(descriptor && descriptor.writable === false && descriptor.configurable === false,
        'window.EchoMarkSys 是不可写、不可配置的（v1 的十几个全局全部可写）');

    // ---- 4. 尝试劫持：v1 的一行攻击在这里必须无效 ----
    const box = { save: null };
    const engine = new S.EchoMarkLedger({
        gameId: `bundle-${Math.random().toString(36).slice(2, 8)}`,
        enableDebugProbe: false,
        onLoad: async () => box.save,
        onSave: async (save) => { box.save = save; },
    });
    const init = await engine.init();
    let hook = init.currentHook;
    for (let i = 0; i < 2; i++) {
        hook = (await engine.recordOperation({ type: 'STEP', i }, hook)).currentHook;
    }
    const good = clone(await engine.exportSave());
    t.eq((await engine.verifySave(good)).valid, true, '产物上的正常流程可用');

    const savedGlobals = {};
    for (const name of FORBIDDEN) savedGlobals[name] = globalThis[name];
    try {
        // v1 的攻击原文
        for (const name of FORBIDDEN) {
            try { globalThis[name] = () => 'f'.repeat(64); } catch { /* 只读则更好 */ }
        }
        globalThis.sha256 = async () => 'f'.repeat(64);
        globalThis.serializeForHash = () => '';

        t.eq((await engine.verifySave(good)).valid, true,
            '【核心回归】劫持全部旧全局名后，真存档仍然通过（引擎不再从全局解析依赖）');

        const tampered = clone(good);
        tampered.records[1].params.customData = { coins: 1e9 };
        t.invalid(await engine.verifySave(tampered), '状态哈希验证失败',
            '【核心回归】劫持全局的同时篡改存档，仍被检出（v1 在此返回 valid:true）');

        const stepAfter = await engine.recordOperation({ type: 'AFTER_HIJACK' }, engine.lastHook);
        t.eq(stepAfter.index, 3, '劫持全局后写入仍然正常');
    } finally {
        for (const name of FORBIDDEN) {
            if (savedGlobals[name] === undefined) delete globalThis[name];
            else globalThis[name] = savedGlobals[name];
        }
    }

    engine.destroy();
    t.note('无法防御的边界：在产物加载之前就替换 crypto（扩展 / 用户脚本 / 被改的 SW / 本地代理）');
}

/** 在"全局读取会被记录"的沙箱里求值，返回被触碰的禁用名。 */
function auditFreeGlobals(code) {
    const touched = new Set();
    const provided = {
        crypto: globalThis.crypto, TextEncoder, TextDecoder, console,
        Date, Math, JSON, Object, Array, String, Number, Boolean,
        Error, TypeError, RangeError, Promise, Symbol, Map, Set,
        WeakMap, WeakSet, Proxy, Reflect, Function, Uint8Array, ArrayBuffer,
        Intl, isNaN, isFinite, parseInt, parseFloat,
        structuredClone: globalThis.structuredClone,
        setTimeout, clearTimeout, setInterval, clearInterval,
        performance: globalThis.performance,
    };
    const fakeGlobal = { ...provided };
    provided.globalThis = fakeGlobal;
    provided.window = fakeGlobal;
    provided.self = fakeGlobal;

    const scope = new Proxy(Object.create(null), {
        has: () => true,
        get(_target, prop) {
            if (typeof prop === 'string' && FORBIDDEN.includes(prop)) touched.add(prop);
            if (prop === Symbol.unscopables) return undefined;
            return provided[prop];
        },
        set: () => true,
    });

    try {
        // eslint-disable-next-line no-new-func
        new Function('scope', `with (scope) { ${code}\n }`)(scope);
    } catch { /* 求值中断不影响结论：只看是否触碰禁用名 */ }
    return [...touched];
}
