/**
 * v1 → v2 存档迁移
 */

import { sha256 } from './core/crypto.js';

const V1_ZERO = '0'.repeat(64);

/** v1 的 serializeForHash，原样复刻，仅用于校验老存档。 */
function v1Serialize(obj) {
    if (obj === null || obj === undefined) return '';
    if (typeof obj === 'string') return obj;
    if (typeof obj === 'number') return String(obj);
    if (typeof obj === 'boolean') return obj ? '1' : '0';
    if (Array.isArray(obj)) return obj.map(v1Serialize).join('|');
    if (typeof obj === 'object') {
        return Object.keys(obj).sort().map((k) => `${k}:${v1Serialize(obj[k])}`).join(';');
    }
    return String(obj);
}

/**
 * 按 v1 规则校验一份老存档。
 * @returns {Promise<{valid: boolean, corruptedIndex?: number, error?: string, lastHash?: string}>}
 */
async function verifyV1Save(saveData, { gameId, version }) {
    if (!saveData || typeof saveData !== 'object') return { valid: false, error: '存档为空' };
    if (!saveData.genesisHash || !Array.isArray(saveData.records) || saveData.records.length === 0) {
        return { valid: false, error: '不是一份 v1 存档结构' };
    }
    if (saveData.formatVersion !== undefined) {
        return { valid: false, error: `这不是 v1 存档（formatVersion=${saveData.formatVersion}）` };
    }

    for (let i = 0; i < saveData.records.length; i++) {
        const record = saveData.records[i];
        if (!record?.params?.timestamp || !record.verify) {
            return { valid: false, corruptedIndex: i, error: `记录 ${i} 结构无效` };
        }
        if (record.index !== i) {
            return { valid: false, corruptedIndex: i, error: `索引不连续: 期望 ${i}, 实际 ${record.index}` };
        }

        if (i === 0) {
            const expected = await sha256(v1Serialize({
                gameId, version,
                timestamp: record.params.timestamp,
                nonce: record.params.nonce,
                runtimeContext: record.params.runtimeContext,
            }));
            if (expected !== record.H) return { valid: false, corruptedIndex: 0, error: '创世哈希验证失败' };
            const expectedHook = await sha256(`${record.H}:hook:${record.params.nonce}`);
            if (expectedHook !== record.verify.hook) {
                return { valid: false, corruptedIndex: 0, error: '创世 hook 不匹配' };
            }
        } else {
            const prev = saveData.records[i - 1];
            if (record.params.prevHash !== prev.H) {
                return { valid: false, corruptedIndex: i, error: '前序哈希不匹配' };
            }
            const expected = await sha256(v1Serialize({
                prevHash: record.params.prevHash,
                operation: record.params.operation,
                timestamp: record.params.timestamp,
                nonce: record.params.nonce,
                runtimeContext: record.params.runtimeContext,
                customData: record.params.customData || {},
            }));
            if (expected !== record.H) return { valid: false, corruptedIndex: i, error: '状态哈希验证失败' };

            const expectedHook = await sha256(`${record.H}:hook:${record.params.nonce}:${record.params.timestamp}`);
            if (expectedHook !== record.verify.hook) {
                return { valid: false, corruptedIndex: i, error: 'hook 不匹配' };
            }
            const expectedDynamic = await sha256(`${record.H}:dynamic:${record.params.nonce}:${i}`);
            if (expectedDynamic !== record.verify.dynamic) {
                return { valid: false, corruptedIndex: i, error: 'dynamic 验证失败' };
            }
            const expectedComposite = await sha256(`${expectedDynamic}:${prev.verify.hook}:${expectedHook}`);
            if (expectedComposite !== record.verify.composite) {
                return { valid: false, corruptedIndex: i, error: 'composite 验证失败' };
            }
        }
    }

    const last = saveData.records[saveData.records.length - 1];
    return { valid: true, lastHash: last.H, lastIndex: last.index };
}

/**
 * 把一份 v1 存档迁移成当前设备上的 v2 链。
 *
 * @param {Object} v1Save    v1 的 exportSave() 产物
 * @param {Object} engine    已 init() 完成的 v2 引擎（决定 gameId / version / 设备密钥）
 * @param {Object} options
 * @param {boolean} options.acceptUnverified  v1 校验失败时是否仍然迁移（默认 false）
 * @returns {Promise<{migrated: boolean, save?: Object, v1Verification: Object, error?: string}>}
 */
async function migrateV1ToV2(v1Save, engine, options = {}) {
    const v1Verification = await verifyV1Save(v1Save, {
        gameId: engine.gameId, version: engine.version,
    });

    if (!v1Verification.valid && !options.acceptUnverified) {
        return {
            migrated: false,
            v1Verification,
            error: `v1 存档未通过校验（${v1Verification.error}）；确认仍要迁移请传 { acceptUnverified: true }`,
        };
    }

    const summary = {
        v1GenesisHash: v1Save.genesisHash,
        v1LastHash: v1Verification.lastHash ?? v1Save.records.at(-1)?.H ?? null,
        v1RecordCount: v1Save.records.length,
        v1Verified: v1Verification.valid,
        migratedAt: Date.now(),
        // 只保留摘要，不整链搬运：老链本身已无权威性，留着只为审计追溯
        v1Digest: v1Save.records.map((r) => ({
            index: r.index,
            H: r.H,
            type: r.params?.operation?.type ?? 'unknown',
            timestamp: r.params?.timestamp ?? 0,
        })),
    };

    const state = engine.getCurrentState();
    if (!state) return { migrated: false, v1Verification, error: '目标引擎尚未初始化' };

    await engine.recordOperation({ type: 'MIGRATED_V1' }, state.hook, { migration: summary });

    return { migrated: true, save: await engine.exportSave(), v1Verification };
}

export { migrateV1ToV2, verifyV1Save, v1Serialize };
