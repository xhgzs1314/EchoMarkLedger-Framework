/** v1 → v2 迁移工具 */
import { makeEngine, play, clone } from '../helpers.mjs';
import { migrateV1ToV2, verifyV1Save, v1Serialize } from '../../src/migrate.js';
import { sha256 } from '../../src/core/crypto.js';

export const name = 'migrate：v1 存档迁移到 v2';

export default async function (t) {
    const gameId = `mig-${Math.random().toString(36).slice(2, 8)}`;
    const version = '1.0.0';

    const v1Save = await buildV1Save(gameId, version, [
        { type: 'PUZZLE_SOLVED', puzzleId: 1 },
        { type: 'PUZZLE_SOLVED', puzzleId: 2 },
    ]);

    // v1 校验器能认出好存档
    const good = await verifyV1Save(v1Save, { gameId, version });
    t.eq(good.valid, true, 'v1 校验器接受未被篡改的 v1 存档');

    // 也能认出被改过的
    const tampered = clone(v1Save);
    tampered.records[1].params.customData = { coins: 1e9 };
    const bad = await verifyV1Save(tampered, { gameId, version });
    t.eq(bad.valid, false, 'v1 校验器拒绝被篡改的 v1 存档');
    t.eq(bad.corruptedIndex, 1, '定位到被改的那条');

    // v2 引擎直接吃 v1 存档应给出明确提示，而不是含糊报错
    const { engine } = makeEngine('mig', { gameId });
    await engine.init();
    const direct = await engine.verifySave(v1Save);
    t.eq(direct.valid, false, 'v2 引擎不接受 v1 存档');
    t.eq(direct.reason, 'format', '拒绝原因是 format');
    t.ok(String(direct.details).includes('migrateV1ToV2'), '错误信息直接指向迁移工具');

    // 迁移
    const result = await migrateV1ToV2(v1Save, engine);
    t.eq(result.migrated, true, '迁移成功');
    t.eq(result.v1Verification.valid, true, '迁移结果里带着 v1 校验结论');
    t.eq((await engine.verifySave(clone(result.save))).valid, true, '迁移产出的 v2 存档通过校验');

    const migratedRecord = engine.getHistory().find((r) => r.operation.type === 'MIGRATED_V1');
    t.ok(migratedRecord, '链上留下了 MIGRATED_V1 记录');
    const detail = result.save.records[migratedRecord.index].params.customData.migration;
    t.eq(detail.v1RecordCount, 3, '迁移摘要记录了原链长度');
    t.eq(detail.v1GenesisHash, v1Save.genesisHash, '迁移摘要保留了原创世哈希');
    t.eq(detail.v1Verified, true, '迁移摘要如实记录了 v1 是否通过校验');
    t.eq(detail.v1Digest.length, 3, '迁移摘要保留了逐条摘要作为审计证据');

    // 被篡改的 v1 存档默认拒绝迁移
    const engine2 = makeEngine('mig2');
    await engine2.engine.init();
    const refused = await migrateV1ToV2(tampered, engine2.engine);
    t.eq(refused.migrated, false, '被篡改的 v1 存档默认拒绝迁移');
    t.ok(String(refused.error).includes('acceptUnverified'), '错误信息说明了强制迁移的开关');

    const forced = await migrateV1ToV2(tampered, engine2.engine, { acceptUnverified: true });
    t.eq(forced.migrated, true, '显式传 acceptUnverified 可以强行迁移');
    const forcedDetail = forced.save.records.at(-1).params.customData.migration;
    t.eq(forcedDetail.v1Verified, false, '强行迁移会在链上如实标记 v1 未通过校验');
    t.note('迁移只能"尽力确认老存档没被手改"——v1 本来就挡不住整链重伪造，结论仅供参考');

    engine.destroy();
    engine2.engine.destroy();
}

/** 按 v1 的算法造一份真实的 v1 存档。 */
async function buildV1Save(gameId, version, operations) {
    const ZERO = '0'.repeat(64);
    const runtimeContext = { screenSize: '1920x1080', language: 'zh-CN' };
    const gNonce = 'a'.repeat(64);
    const gTs = Date.now() - 10000;

    const genesisHash = await sha256(v1Serialize({
        gameId, version, timestamp: gTs, nonce: gNonce, runtimeContext,
    }));
    const gHook = await sha256(`${genesisHash}:hook:${gNonce}`);
    const gDyn = await sha256(`${genesisHash}:dynamic:${gNonce}`);

    const records = [{
        index: 0, H: genesisHash,
        params: {
            operation: { type: 'GENESIS', gameId }, prevHash: ZERO,
            timestamp: gTs, nonce: gNonce, runtimeContext,
        },
        verify: {
            dynamic: gDyn, hook: gHook,
            composite: await sha256(`${gDyn}:${ZERO}:${gHook}`),
        },
        linkedVerifications: [],
    }];

    let prevHash = genesisHash;
    let prevHook = gHook;
    for (let i = 1; i <= operations.length; i++) {
        const operation = operations[i - 1];
        const timestamp = gTs + i * 1000;
        const nonce = String(i).repeat(32).slice(0, 32);
        const customData = {};
        const H = await sha256(v1Serialize({
            prevHash, operation, timestamp, nonce, runtimeContext, customData,
        }));
        const hook = await sha256(`${H}:hook:${nonce}:${timestamp}`);
        const dynamic = await sha256(`${H}:dynamic:${nonce}:${i}`);
        const composite = await sha256(`${dynamic}:${prevHook}:${hook}`);
        records.push({
            index: i, H,
            params: { operation, prevHash, timestamp, nonce, runtimeContext, customData },
            verify: { dynamic, hook, composite },
            linkedVerifications: [],
        });
        prevHash = H;
        prevHook = hook;
    }

    const last = records.at(-1);
    return {
        version, genesisHash, records,
        metadata: { gameId, createTime: gTs, lastPlayTime: Date.now(), totalOperations: operations.length },
        checkpoint: {
            index: last.index,
            verifyHash: await sha256(`${last.H}:${genesisHash}:${last.index}`),
        },
    };
}
