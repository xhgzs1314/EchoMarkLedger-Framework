/**
 * 伪造抵抗
 * v2 的每一个字段都要设备绑定密钥才能算出来，无密钥方造不出来。
 */
import { makeEngine, play, clone } from '../helpers.mjs';
import { canonicalFor } from '../../src/core/canonical.js';
import { sha256 } from '../../src/core/crypto.js';
import { destroyIdentity } from '../../src/core/keystore.js';

export const name = 'forgery：无密钥伪造、全局劫持、设备绑定';

export default async function (t) {
    const { engine, gameId } = makeEngine('forge');
    const init = await engine.init();
    await play(engine, 2);
    const real = clone(await engine.exportSave());
    t.eq((await engine.verifySave(real)).valid, true, '真存档通过校验');

    // ---- 1. 攻击者拥有全部源码与算法，只是没有密钥 ----
    const forged = await forgeWithoutKey({
        gameId, version: engine.version, installId: engine.installId,
        macImpl: async (purpose, payload) => await sha256(canonicalFor(purpose, payload)),
        customData: { coins: 999999999, allPuzzlesSolved: true },
    });
    t.invalid(
        await engine.verifySave(forged, { requireStorageWitness: false }),
        '创世哈希验证失败',
        '【核心回归】无密钥全链伪造被拒（v1 在此返回 valid: true）');

    // ---- 2. 攻击者把哈希函数换成常量，试图让整条链"塌缩" ----
    const K = 'f'.repeat(64);
    const collapsed = await forgeWithoutKey({
        gameId, version: engine.version, installId: engine.installId,
        macImpl: async () => K,
        customData: { coins: 1e12 },
    });
    t.invalid(
        await engine.verifySave(collapsed, { requireStorageWitness: false }),
        '', '常量塌缩伪造被拒');

    // ---- 3. 加载后替换 window.crypto 不影响已捕获的原生引用 ----
    const savedCrypto = globalThis.crypto;
    let hijackWorked = false;
    try {
        Object.defineProperty(globalThis, 'crypto', {
            value: {
                subtle: {
                    digest: async () => new Uint8Array(32).fill(0xff).buffer,
                    sign: async () => new Uint8Array(32).fill(0xff).buffer,
                },
                getRandomValues: (a) => a.fill(1),
            },
            configurable: true, writable: true,
        });
        // 劫持之后真存档仍应通过（说明引擎用的是模块加载期捕获的引用）
        const stillValid = await engine.verifySave(real);
        t.eq(stillValid.valid, true, '替换 window.crypto 之后真存档仍然通过（原生引用已在模块加载期捕获）');
        hijackWorked = true;
    } finally {
        Object.defineProperty(globalThis, 'crypto', {
            value: savedCrypto, configurable: true, writable: true,
        });
    }
    t.ok(hijackWorked, 'crypto 劫持用例执行完毕');

    // ---- 4. 全局命名空间是否只读 ----
    // 源码模式下 entry 未被加载，这里直接验证暴露面的设计约束：
    // 内部密码学实现不在任何公开导出里（bundle 套件会在真实产物上再验一次）
    const coreModule = await import('../../src/entry.js');
    t.eq(coreModule.EchoMarkSys.canonical, undefined, 'canonical 不对外导出');
    t.eq(coreModule.EchoMarkSys.hmac, undefined, 'hmac 不对外导出');
    t.eq(coreModule.EchoMarkSys.loadIdentity, undefined, 'keystore 内部不对外导出');
    t.ok(Object.isFrozen(coreModule.EchoMarkSys), '导出命名空间已冻结');

    // ---- 5. 换 gameId 的存档不通过 ----
    const other = makeEngine('forge-other');
    await other.engine.init();
    await play(other.engine, 2);
    const otherSave = clone(await other.engine.exportSave());
    t.invalid(await engine.verifySave(otherSave), '', '另一个 gameId 的存档不通过（既不同设备身份也不同 gameId）');
    other.engine.destroy();

    // ---- 6. 设备绑定：清掉密钥库后，旧存档不再可用 ----
    const keep = clone(await engine.exportSave());
    const oldInstallId = engine.installId;
    engine.destroy();
    await destroyIdentity(gameId);

    const reborn = makeEngine('forge', { gameId });
    await reborn.engine.init();
    t.neq(reborn.engine.installId, oldInstallId, '清掉密钥库后设备身份已更换');
    t.invalid(
        await reborn.engine.verifySave(keep),
        '另一台设备',
        '旧设备的存档被明确拒绝（reason: foreign-device），而不是含糊地报"损坏"');
    t.eq((await reborn.engine.verifySave(keep)).reason, 'foreign-device', '拒绝原因是机器可判别的 foreign-device');
    reborn.engine.destroy();

    t.note('v1 在用例 1 与 2 上均返回 valid:true —— 这是 v2 引入设备绑定密钥后最关键的翻转');
}

/** 用给定的（非密钥）哈希实现，按 v2 的结构造一份存档。 */
async function forgeWithoutKey({ gameId, version, installId, macImpl, customData }) {
    const ZERO = '0'.repeat(64);
    const ts = Date.now();
    const nonce = 'ab'.repeat(16);
    const runtimeContext = {};

    const H0 = await macImpl('genesis', { gameId, version, timestamp: ts, nonce, runtimeContext, installId });
    const hook0 = await macImpl('hook-genesis', { H: H0, nonce });
    const dyn0 = await macImpl('dynamic', { H: H0, nonce, index: 0 });
    const comp0 = await macImpl('composite', { dynamic: dyn0, prevHook: ZERO, hook: hook0 });

    const records = [{
        index: 0, H: H0,
        params: {
            operation: { type: 'GENESIS', gameId }, prevHash: ZERO,
            timestamp: ts, nonce, runtimeContext, customData: {},
        },
        verify: { dynamic: dyn0, hook: hook0, composite: comp0 },
        linkedVerifications: [],
    }];

    const operation = { type: 'ALL_PUZZLES_CLEARED' };
    const H1 = await macImpl('record', {
        index: 1, prevHash: H0, operation, timestamp: ts + 1, nonce, runtimeContext, customData,
    });
    const hook1 = await macImpl('hook', { H: H1, nonce, timestamp: ts + 1 });
    const dyn1 = await macImpl('dynamic', { H: H1, nonce, index: 1 });
    const comp1 = await macImpl('composite', { dynamic: dyn1, prevHook: hook0, hook: hook1 });

    records.push({
        index: 1, H: H1,
        params: { operation, prevHash: H0, timestamp: ts + 1, nonce, runtimeContext, customData },
        verify: { dynamic: dyn1, hook: hook1, composite: comp1 },
        linkedVerifications: [],
    });

    return {
        formatVersion: 2, version, genesisHash: H0, installId, records,
        metadata: { gameId, createTime: ts, lastPlayTime: ts, totalOperations: 1 },
        checkpoint: {
            index: 1,
            verifyHash: await macImpl('checkpoint', { H: H1, genesisHash: H0, index: 1 }),
            chainMac: await macImpl('chain', {
                gameId, version, installId, genesisHash: H0, lastIndex: 1, hashes: [H0, H1],
            }),
        },
    };
}
