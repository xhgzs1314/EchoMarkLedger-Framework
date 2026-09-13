/**
 * 存档合并写入与显式落盘
 *
 * 背景：每条记录成功后都会触发 onSave，而 onSave 拿到的是完整存档，
 * 于是单条写入的固定开销与链长成正比，连续写入 N 条整体是 O(N²)。
 * 实测 200 条：每条都导出 ≈15.5ms/条；合并写入后 ≈4.7ms/条。
 */
import { makeEngine, clone } from '../helpers.mjs';

export const name = 'persistence：合并写入不丢进度';

export default async function (t) {
    // ---- 默认行为：每条都落盘 ----
    const immediate = makeEngine('pers-now');
    const i1 = await immediate.engine.init();
    let hook = i1.currentHook;
    let saveCalls = 0;
    const originalOnSave = immediate.engine.onSave;
    immediate.engine.onSave = async (save) => { saveCalls++; await originalOnSave(save); };

    for (let i = 0; i < 5; i++) {
        hook = (await immediate.engine.recordOperation({ type: 'OP', i }, hook)).currentHook;
    }
    t.eq(saveCalls, 5, '默认每条记录都触发一次 onSave');
    t.eq(immediate.box.save.records.length, 6, '落地存档是最新的');
    immediate.engine.destroy();

    // ---- 合并写入 ----
    const debounced = makeEngine('pers-debounce', { saveDebounceMs: 30 });
    const i2 = await debounced.engine.init();
    let hook2 = i2.currentHook;
    let debouncedCalls = 0;
    const original2 = debounced.engine.onSave;
    debounced.engine.onSave = async (save) => { debouncedCalls++; await original2(save); };

    for (let i = 0; i < 20; i++) {
        hook2 = (await debounced.engine.recordOperation({ type: 'OP', i }, hook2)).currentHook;
    }
    t.ok(debouncedCalls < 20, `20 条连续写入只触发了 ${debouncedCalls} 次导出（而不是 20 次）`);

    await debounced.engine.flush();
    t.eq(debounced.box.save.records.length, 21, '【关键】flush 之后落地存档是完整的，没有丢进度');
    t.eq((await debounced.engine.verifySave(clone(debounced.box.save))).valid, true, '落地存档有效');

    // 不显式 flush，等窗口自然过去也应落盘
    hook2 = (await debounced.engine.recordOperation({ type: 'LAST' }, hook2)).currentHook;
    await new Promise((resolve) => setTimeout(resolve, 120));
    t.eq(debounced.box.save.records.length, 22, '窗口过去后自动落盘');
    t.eq((await debounced.engine.verifySave(clone(debounced.box.save))).valid, true, '自动落盘的存档有效');

    // flush 幂等
    await debounced.engine.flush();
    await debounced.engine.flush();
    t.eq(debounced.box.save.records.length, 22, '重复 flush 不产生副作用');

    // 重开后能恢复到最新进度
    const gameId = debounced.gameId;
    const lastSave = debounced.box.save;
    debounced.engine.destroy();
    const reopened = makeEngine('pers-debounce', { gameId, saveDebounceMs: 30 });
    reopened.box.save = lastSave;
    const restored = await reopened.engine.init();
    t.eq(restored.restored, true, '重开后恢复成功');
    t.eq(restored.lastIndex, 21, '恢复到合并写入之后的最新进度');
    reopened.engine.destroy();

    t.note('开启 saveDebounceMs 后，请在关卡结束 / visibilitychange / pagehide 时调用 flush()');
}
