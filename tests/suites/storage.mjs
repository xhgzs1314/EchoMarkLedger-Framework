/**
 * 四表存储
 */
import { makeEngine, play, clone } from '../helpers.mjs';
import { verifyStorageSnapshot, recordCore } from '../../src/core/storage.js';

export const name = 'storage：四表成为真正的第二证人';

export default async function (t) {
    const { engine } = makeEngine('st');
    await engine.init();
    await play(engine, 3);

    const integrity = await engine.storage.verifyIntegrity();
    t.eq(integrity.valid, true, `四表自检通过（${integrity.checks.length} 项检查）`);
    t.ok(integrity.checks.some((c) => c.name === 'row_mac_valid' && c.valid), '行 MAC 检查存在且通过');
    t.ok(integrity.checks.some((c) => c.name === 'seed_diversity' && c.valid), '四个种子互不相同');

    // 创世单条记录也必须通过（v1 在此必然失败）
    const solo = makeEngine('st-solo');
    await solo.engine.init();
    const soloIntegrity = await solo.engine.storage.verifyIntegrity();
    t.eq(soloIntegrity.valid, true, '【核心回归】只有创世记录时四表自检通过（v1 的 shuffle_diversity 必然失败）');
    solo.engine.destroy();

    const save = clone(await engine.exportSave());
    t.eq((await engine.verifySave(save)).valid, true, '含四表快照的存档通过校验');

    // ---- 剥掉四表快照 ----
    const stripped = clone(save);
    delete stripped._storageData;
    const strippedResult = await engine.verifySave(stripped);
    t.eq(strippedResult.valid, false, '【核心回归】剥掉 _storageData 被拒（v1 会走重建分支照样通过）');
    t.eq(strippedResult.reason, 'missing-witness', '拒绝原因是 missing-witness');
    t.eq((await engine.verifySave(stripped, { requireStorageWitness: false })).valid, true,
        '显式关闭见证要求后可以加载裁剪过的存档');

    // ---- 改四表里的记录内容 ----
    const editedRow = clone(save);
    editedRow._storageData.storeA[2].data.params.customData = { coins: 1e9 };
    t.invalid(await engine.verifySave(editedRow), '四表', '改 storeA 的记录内容被检出');

    // ---- 同时改穿 A 与 A'（v1 只比对二者一致，改穿即可）----
    const bothEdited = clone(save);
    for (const store of ['storeA', 'storeAPrime']) {
        bothEdited._storageData[store][2].data.params.customData = { coins: 1e9 };
    }
    t.invalid(await engine.verifySave(bothEdited), '四表',
        '【核心回归】同时改穿 A 与 A\' 仍被行 MAC 检出（v1 此时无从发现）');

    // ---- 改影子映射 ----
    const mappingEdited = clone(save);
    mappingEdited._storageData.storeB[1].mapping.recordMac = 'a'.repeat(64);
    t.invalid(await engine.verifySave(mappingEdited), '四表', '改影子映射的 recordMac 被检出');

    // ---- 改槽位 ----
    const slotEdited = clone(save);
    slotEdited._storageData.storeA[1].slotPosition = 12345;
    t.invalid(await engine.verifySave(slotEdited), '四表', '改槽位被检出');

    // ---- 删一行导致计数失衡 ----
    const unbalanced = clone(save);
    unbalanced._storageData.storeAPrime.pop();
    t.invalid(await engine.verifySave(unbalanced), '四表', '四表计数失衡被检出');

    // ---- 四表与链条指向不同存档 ----
    const other = makeEngine('st-other');
    await other.engine.init();
    await play(other.engine, 3);
    const otherSave = clone(await other.engine.exportSave());
    const spliced = clone(save);
    spliced._storageData = otherSave._storageData;
    t.invalid(await engine.verifySave(spliced), '四表', '把别处的四表快照拼过来被检出');
    other.engine.destroy();

    // ---- 直接改活的 IndexedDB ----
    const rows = await engine.storage.getAllFromStore('storeA');
    const victim = rows.find((r) => r.recordIndex === 2);
    victim.data.params.customData = { coins: 777 };
    await new Promise((resolve, reject) => {
        const tx = engine.storage.db.transaction(['storeA'], 'readwrite');
        const store = tx.objectStore('storeA');
        const clear = store.index('recordIndex').openCursor(2);
        clear.onsuccess = () => {
            const cursor = clear.result;
            if (cursor) { cursor.update(victim); }
        };
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
    });
    const afterDirectEdit = await engine.storage.verifyIntegrity();
    t.eq(afterDirectEdit.valid, false, '直接改活的 IndexedDB 被 verifyIntegrity 检出');
    t.ok(afterDirectEdit.checks.some((c) => !c.valid && c.name === 'row_mac_valid'),
        '检出方式是行 MAC 不匹配（需要设备密钥才能重签）');

    // ---- 纯函数快照校验器可独立使用 ----
    const standalone = await verifyStorageSnapshot(
        save._storageData, async () => 'not-the-real-key', engine.storage.SLOT_SPACE);
    t.eq(standalone.valid, false, '用错误的密钥校验四表快照必然失败');
    t.eq(typeof recordCore(save.records[1]).linkedVerifications, 'undefined',
        'recordCore 排除了可变的 linkedVerifications');

    engine.destroy();
}
