/**
 * verifySave 的只读性与边界隔离
 *
 */
import { makeEngine, play, clone } from '../helpers.mjs';

export const name = 'readonly：verifySave 不产生副作用、导出无别名';

export default async function (t) {
    const { engine } = makeEngine('ro');
    await engine.init();
    await play(engine, 2);
    const oldBackup = clone(await engine.exportSave());
    await play(engine, 4);

    const memBefore = engine.getHistory().length;
    const idxBefore = engine.currentIndex;
    const hashBefore = engine.currentHash;
    const hookBefore = engine.lastHook;
    const dbBefore = JSON.stringify((await engine.storage.getAllFromStore('storeA')).map((r) => r.recordIndex));

    // 校验一份"合法但更旧"的存档 —— v1 会把库回滚到它
    const result = await engine.verifySave(oldBackup);
    t.eq(result.valid, true, '旧备份本身是合法的');

    t.eq(engine.getHistory().length, memBefore, '内存记录数不变');
    t.eq(engine.currentIndex, idxBefore, 'currentIndex 不变');
    t.eq(engine.currentHash, hashBefore, 'currentHash 不变');
    t.eq(engine.lastHook, hookBefore, 'lastHook 不变');
    t.eq(JSON.stringify((await engine.storage.getAllFromStore('storeA')).map((r) => r.recordIndex)),
        dbBefore, '【核心回归】IndexedDB 完全不变（v1 在此被回滚）');

    // 校验一份损坏的存档同样不应有副作用
    const broken = clone(oldBackup);
    broken.records[1].params.customData = { x: 1 };
    await engine.verifySave(broken);
    t.eq(JSON.stringify((await engine.storage.getAllFromStore('storeA')).map((r) => r.recordIndex)),
        dbBefore, '校验损坏存档后 IndexedDB 仍不变');
    t.eq(engine.currentIndex, idxBefore, '校验损坏存档后进度不变');

    const reexport = clone(await engine.exportSave());
    t.eq(reexport.records.length, reexport._storageData.storeA.length,
        '导出的链条长度与四表行数一致（v1 在此为 7 / 3）');
    t.eq((await engine.verifySave(reexport)).valid, true, '多次校验后自家存档依然有效');

    // ---- exportSave 不别名内部状态 ----
    const snapshot = await engine.exportSave();
    const lengthAtSnapshot = snapshot.records.length;
    await play(engine, 2);
    t.eq(snapshot.records.length, lengthAtSnapshot, '【核心回归】快照不随后续操作变化（v1 会跟着变）');
    t.neq(snapshot.records, engine.getHistory(), '导出的数组不是内部数组');

    // ---- loadSave 之后不与调用方共享引用（TOCTOU）----
    const toLoad = clone(await engine.exportSave());
    const loaded = await engine.loadSave(toLoad);
    t.eq(loaded.valid, true, 'loadSave 成功');
    const operationBefore = JSON.stringify(engine.getHistory()[1].operation);
    toLoad.records[1].params.customData = { coins: 1e9 };
    toLoad.records[1].params.operation = { type: 'HACKED' };
    t.eq(JSON.stringify(engine.getHistory()[1].operation), operationBefore,
        '【核心回归】校验通过后改调用方对象，引擎内部不受影响（v1 会被改掉）');

    // ---- 只读视图确实只读 ----
    t.ok(Object.isFrozen(engine.getCurrentState()), 'getCurrentState 返回冻结对象');
    t.ok(Object.isFrozen(engine.getHistory()), 'getHistory 返回冻结数组');
    let threw = false;
    try { engine.currentIndex = 9999; } catch { threw = true; }
    t.ok(threw, '给 currentIndex 赋值抛错（只有 getter，没有 setter）');
    t.neq(engine.currentIndex, 9999, 'currentIndex 未被改动');

    threw = false;
    try { engine.recordOperation = () => {}; } catch { threw = true; }
    t.ok(threw, '替换 recordOperation 方法抛错');

    t.eq(engine.records, undefined, 'records 不再是公开属性（已改为 #私有字段）');

    engine.destroy();
}
