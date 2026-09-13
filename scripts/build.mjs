/**
 * 构建脚本。
 *
 */

import { build } from 'esbuild';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const keepNames = process.env.EMK_KEEP_NAMES !== '0';

const TARGETS = [
    { entry: 'src/entry.js', outfile: 'dist/EchoMarkLedger.js', label: '核心版' },
    { entry: 'src/entry-full.js', outfile: 'dist/EchoMarkLedger-secure.js', label: '完整版（含 L1–L6）' },
];

/**
 * 不该出现在产物里的自由全局引用。
 * 这些名字必须由模块内部的 import 解析，一旦以裸标识符形式出现在全局读取位置
 */
const FORBIDDEN_GLOBALS = [
    'sha256', 'hmac', 'canonical', 'canonicalFor', 'fastHash',
    'serializeForHash', 'sha256Sync', 'generateNonce', 'randomHex',
    'QuadStorage', 'EchoMarkLedger', 'computeSlotPosition', 'safeStringify',
    'deepFreeze', 'deepEqual', 'captureRuntimeContext', 'loadIdentity',
];

/**
 * 在一个"全局读取会被记录"的沙箱里求值产物，看它是否去读了上面那些名字。
 * 比正则扫描可靠得多：压缩后的局部变量名已被改写，只有真正的全局读取才会命中。
 */
function auditFreeGlobals(code, label) {
    const touched = new Set();
    const sandbox = Object.create(null);

    // 产物真正需要的宿主能力。给足，让模块顶层代码完整求值——
    // 否则求值中途报错，这次体检就等于没做。
    const provided = {
        crypto: globalThis.crypto,
        TextEncoder: globalThis.TextEncoder,
        TextDecoder: globalThis.TextDecoder,
        console,
        Date, Math, JSON, Object, Array, String, Number, Boolean, Error, TypeError, RangeError,
        Promise, Symbol, Map, Set, WeakMap, WeakSet, Proxy, Reflect, Function,
        Uint8Array, ArrayBuffer, Intl, isNaN, isFinite, parseInt, parseFloat,
        structuredClone: globalThis.structuredClone,
        setTimeout, clearTimeout, setInterval, clearInterval,
        performance: globalThis.performance,
    };
    // 模块里以 globalThis.xxx / window.xxx 形式访问的宿主对象
    const fakeGlobal = { ...provided };
    provided.globalThis = fakeGlobal;
    provided.window = fakeGlobal;
    provided.self = fakeGlobal;

    const handler = {
        has() { return true; },   // 让所有标识符都走 get，而不是抛 ReferenceError
        get(_t, prop) {
            if (typeof prop === 'string' && FORBIDDEN_GLOBALS.includes(prop)) touched.add(prop);
            if (prop in provided) return provided[prop];
            if (prop === Symbol.unscopables) return undefined;
            return undefined;
        },
        set() { return true; },
    };

    const scope = new Proxy(sandbox, handler);
    try {
        // eslint-disable-next-line no-new-func
        const run = new Function('scope', `with (scope) { ${code}\n; return typeof __EchoMarkInternal; }`);
        run(scope);
    } catch (error) {
        // 求值失败不代表体检失败（沙箱缺少 indexedDB 等），只要没碰禁用名即可
        if (touched.size === 0) {
            console.log(`    · ${label} 沙箱求值提前结束（${error.message.slice(0, 60)}），未触碰禁用全局`);
        }
    }

    if (touched.size > 0) {
        throw new Error(
            `${label} 产物存在自由全局引用: ${[...touched].join(', ')}\n`
            + '        说明有模块漏了 import —— 这正是 v1 被一行 window 赋值劫持的根因。'
        );
    }
    return true;
}

mkdirSync(path.join(root, 'dist'), { recursive: true });

console.log('========================================');
console.log('构建 EchoMarkLedger v2');
console.log(`  keep-names: ${keepNames ? '开' : '关'}`);
console.log('========================================');

for (const target of TARGETS) {
    await build({
        absWorkingDir: root,
        entryPoints: [target.entry],
        bundle: true,
        outfile: target.outfile,
        format: 'iife',
        // 内部名。公开的 window.EchoMarkSys 由 entry 用 defineProperty 定义成
        // 不可写、不可配置的冻结对象；若让 esbuild 也往同名全局上赋值，
        // 两者会打架（var 赋值静默失败，行为取决于加载顺序）。
        globalName: '__EchoMarkInternal',
        minify: true,
        keepNames,
        target: 'es2022',
        legalComments: 'none',
    });

    const code = readFileSync(path.join(root, target.outfile), 'utf8');
    const sizeKb = (Buffer.byteLength(code) / 1024).toFixed(1);
    console.log(`  ✓ ${target.outfile}  ${sizeKb} KB  (${target.label})`);
    auditFreeGlobals(code, target.label);
    console.log('    · 自由全局引用体检通过');
}

console.log('========================================');
console.log('构建完成');
console.log('========================================');
