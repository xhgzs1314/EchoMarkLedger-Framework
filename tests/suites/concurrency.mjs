/**
 * 并发写入
 */
import { makeEngine, clone } from '../helpers.mjs';

export const name = 'concurrency：并发写入串行化（v1 会写坏自家存档）';

export default async function (t) {
    const { engine } = makeEngine('conc');
    const init = await engine.init();

    // 50 个并发调用共用同一个钩子：只应有 1 个成功
    const attempts = Array.from({ length: 50 }, (_, i) =>
        engine.recordOperation({ type: 'RACE', i }, init.currentHook));
    const settled = await Promise.allSettled(attempts);
    const fulfilled = settled.filter((s) => s.status === 'fulfilled');
    const rejected = settled.filter((s) => s.status === 'rejected');

    t.eq(fulfilled.length, 1, '50 个共用同一钩子的并发调用，恰好 1 个成功');
    t.eq(rejected.length, 49, '其余 49 个全部被钩子链拒绝');
    t.ok(rejected.every((r) => String(r.reason.message).includes('钩子验证失败')),
        '被拒原因都是钩子验证失败');

    const history = engine.getHistory();
    t.eq(history.length, 2, '链上只有创世 + 1 条');
    t.ok(history.every((r, i) => r.index === i), `索引严格连续: [${history.map((r) => r.index).join(',')}]`);

    const save = clone(await engine.exportSave());
    t.eq((await engine.verifySave(save)).valid, true, '并发冲击之后自家存档仍然有效（v1 在此为 false）');

    // 正确的串行链式调用：50 步全部成功
    let hook = engine.lastHook;
    for (let i = 0; i < 50; i++) {
        hook = (await engine.recordOperation({ type: 'SEQ', i }, hook)).currentHook;
    }
    t.eq(engine.currentIndex, 51, '串行 50 步全部写入');
    const big = clone(await engine.exportSave());
    t.eq((await engine.verifySave(big)).valid, true, '52 条记录的链条校验通过');

    // 并发 loadSave / recordOperation 混合：不应出现交错损坏
    const mixed = await Promise.allSettled([
        engine.recordOperation({ type: 'MIX' }, engine.lastHook),
        engine.loadSave(big, { allowRollback: true }),
        engine.recordOperation({ type: 'MIX2' }, engine.lastHook),
    ]);
    t.ok(mixed.every((m) => m.status === 'fulfilled' || m.status === 'rejected'), '混合并发不抛未捕获异常');
    const after = clone(await engine.exportSave());
    t.eq((await engine.verifySave(after)).valid, true, '混合并发之后链条仍然自洽');

    engine.destroy();
}
