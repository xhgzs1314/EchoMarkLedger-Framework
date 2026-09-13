/** 链条正常流程与各类篡改检测。 */
import { makeEngine, play, clone } from '../helpers.mjs';

export const name = 'chain：正常流程、恢复、各类篡改定位';

export default async function (t) {
    const { engine, box } = makeEngine('chain');
    const init = await engine.init();
    t.eq(init.restored, false, '首次 init 不是恢复');
    t.ok(init.H && init.currentHook, 'init 返回创世哈希与钩子');

    await play(engine, 4, (i) => ({ type: 'PUZZLE_SOLVED', puzzleId: i }));
    const save = clone(await engine.exportSave());
    t.eq(save.records.length, 5, '创世 + 4 步 = 5 条记录');
    t.eq(save.formatVersion, 2, '存档格式版本为 2');
    t.eq((await engine.verifySave(save)).valid, true, '自家存档校验通过');

    // ---- 篡改：改内容 ----
    const mod = clone(save);
    mod.records[2].params.customData = { cheated: true };
    t.invalid(await engine.verifySave(mod), '状态哈希验证失败', '改 customData 被检出');
    t.eq((await engine.verifySave(mod)).corruptedIndex, 2, 'corruptedIndex 精确定位到第 2 条');

    const modOp = clone(save);
    modOp.records[3].params.operation.puzzleId = 999;
    t.invalid(await engine.verifySave(modOp), '状态哈希验证失败', '改 operation 被检出');

    // ---- 篡改：改冗余校验值 ----
    for (const field of ['dynamic', 'hook', 'composite']) {
        const bad = clone(save);
        bad.records[2].verify[field] = 'a'.repeat(64);
        t.invalid(await engine.verifySave(bad), '', `改 verify.${field} 被检出`);
    }

    // ---- 篡改：结构 ----
    const removed = clone(save);
    removed.records.splice(2, 1);
    t.invalid(await engine.verifySave(removed), '', '删中间一条被检出');

    const swapped = clone(save);
    [swapped.records[1], swapped.records[2]] = [swapped.records[2], swapped.records[1]];
    t.invalid(await engine.verifySave(swapped), '', '调换顺序被检出');

    const truncated = clone(save);
    truncated.records.pop();
    truncated.checkpoint.index = truncated.records.length - 1;
    t.invalid(await engine.verifySave(truncated), '', '截断链条被检出');

    const noCheckpoint = clone(save);
    delete noCheckpoint.checkpoint;
    t.invalid(await engine.verifySave(noCheckpoint), '校验点', '删掉校验点被检出');

    const badChainMac = clone(save);
    badChainMac.checkpoint.chainMac = 'b'.repeat(64);
    t.invalid(await engine.verifySave(badChainMac), '整链 MAC', '改整链 MAC 被检出');

    // ---- 篡改：把交叉验证抹成 pending ----
    const wiped = clone(save);
    const link = wiped.records[0].linkedVerifications.find((l) => l.offset > 0);
    link.salt = 'pending'; link.V = 'pending';
    t.invalid(await engine.verifySave(wiped), 'pending', '把已算好的交叉验证抹成 pending 被检出');

    // ---- 时间戳回退 ----
    const backwards = clone(save);
    backwards.records[3].params.timestamp = 1;
    t.invalid(await engine.verifySave(backwards), '', '时间戳被改会破坏哈希（顺带覆盖回退检查）');

    // ---- 钩子链 ----
    await t.rejects(engine.recordOperation({ type: 'X' }, 'wrong-hook'), '钩子验证失败', '错误的钩子被拒');
    await t.rejects(engine.recordOperation({ type: 'X' }, null), '钩子验证失败', '空钩子被拒');
    await t.rejects(engine.recordOperation({ noType: 1 }, engine.lastHook), 'type', '缺 type 的操作被拒');
    const staleHook = save.records[1].verify.hook;
    await t.rejects(engine.recordOperation({ type: 'X' }, staleHook), '钩子验证失败', '重放旧钩子被拒');

    engine.destroy();

    // ---- 恢复 ----
    const again = makeEngine('chain', { gameId: engine.gameId });
    again.box.save = box.save;
    const restored = await again.engine.init();
    t.eq(restored.restored, true, '重开后能恢复存档');
    t.eq(restored.lastIndex, 4, '恢复到正确的进度（创世 + 4 步；被拒的写入不入链）');
    again.engine.destroy();

    // ---- 只有创世记录的存档（v1 必然丢失）----
    const fresh = makeEngine('chain-genesis');
    await fresh.engine.init();
    t.eq(fresh.box.save.records.length, 1, '刚 init 完只有创世记录');
    const genesisOnly = fresh.box.save;
    fresh.engine.destroy();

    const reopened = makeEngine('chain-genesis', { gameId: fresh.gameId });
    reopened.box.save = genesisOnly;
    const r = await reopened.engine.init();
    t.eq(r.restored, true, '仅含创世记录的存档能恢复（v1 因 shuffle_diversity 必然失败而静默丢档）');
    reopened.engine.destroy();

    // ---- 业务语义钩子：写入与校验对称 ----
    const guarded = makeEngine('chain-semantic', {
        validateOperation: (op) => (op.type === 'BUY' && op.amount > 100
            ? { valid: false, reason: '单次金额超限' } : true),
    });
    const gi = await guarded.engine.init();
    await t.rejects(
        guarded.engine.recordOperation({ type: 'BUY', amount: 500 }, gi.currentHook),
        '金额超限', '业务规则在写入期生效');
    const okStep = await guarded.engine.recordOperation({ type: 'BUY', amount: 10 }, gi.currentHook);
    t.eq(okStep.index, 1, '合法操作正常写入');
    const guardedSave = clone(await guarded.engine.exportSave());
    t.eq((await guarded.engine.verifySave(guardedSave)).valid, true, '合法链条通过校验');
    guarded.engine.destroy();
}
