/**
 * 反回滚高水位
 */
import { makeEngine, play, clone } from '../helpers.mjs';
import { loadHighWater, loadIdentity, mirrorKeyName, destroyIdentity } from '../../src/core/keystore.js';

export const name = 'rollback：旧存档不能无声覆盖新进度';

export default async function (t) {
    const { engine, gameId } = makeEngine('rb');
    await engine.init();
    await play(engine, 2);
    const earlyBackup = clone(await engine.exportSave());
    t.eq(earlyBackup.checkpoint.index, 2, '备份时进度为 2');

    await play(engine, 5);
    t.eq(engine.currentIndex, 7, '继续玩到进度 7');

    // 默认拒绝
    const rejected = await engine.loadSave(earlyBackup);
    t.eq(rejected.valid, false, '【核心回归】旧备份默认被拒（v1 返回 valid:true）');
    t.eq(rejected.reason, 'rollback', '拒绝原因是机器可判别的 rollback');
    t.ok(String(rejected.error).includes('低于本机已记录的最高进度'), '错误信息说明了高水位');
    t.eq(engine.currentIndex, 7, '被拒后当前进度不变');

    // verifySave 只看链条合法性，不看高水位 —— 分工明确
    t.eq((await engine.verifySave(earlyBackup)).valid, true,
        'verifySave 仍判定该存档链条合法（回滚是策略问题，不是完整性问题）');

    // 显式放行
    const allowed = await engine.loadSave(earlyBackup, { allowRollback: true });
    t.eq(allowed.valid, true, '显式传 allowRollback 可以接受回滚');
    t.eq(engine.currentIndex, 2, '进度确实回到了 2');

    // 高水位只升不降
    const hw = await loadHighWater(gameId, ...(await keyOf(engine)));
    t.eq(hw.index, 7, '高水位仍停在 7（只升不降）');

    // 回滚后继续玩，越过高水位后恢复正常
    await play(engine, 6);
    t.eq(engine.currentIndex, 8, '回滚后继续玩到 8');
    const now = clone(await engine.exportSave());
    const reload = await engine.loadSave(now);
    t.eq(reload.valid, true, '进度超过高水位后正常加载');

    // 伪造的高水位不应把玩家锁死：MAC 校验不过的水位记录会被直接丢弃
    globalThis.localStorage.setItem(
        mirrorKeyName(gameId),
        JSON.stringify({ index: 99999, H: 'x'.repeat(64), mac: 'f'.repeat(64) }));
    const stillOk = await engine.loadSave(now);
    t.eq(stillOk.valid, true, 'MAC 不合法的伪造高水位被忽略，不会把正常玩家锁死');

    // 但清掉镜像与库之后回滚防护确实失效 —— 如实覆盖这个已知边界
    globalThis.localStorage.removeItem(mirrorKeyName(gameId));
    await destroyIdentity(gameId);
    const afterWipe = makeEngine('rb', { gameId });
    await afterWipe.engine.init();
    t.eq(afterWipe.engine.currentIndex, 0, '密钥库被清空后只能从新创世开始（旧存档一并失效）');
    t.note('高水位存于 keystore 库 + localStorage 两处，两处都清掉即可绕过；它抬成本，不是密码学保证');
    afterWipe.engine.destroy();

    engine.destroy();
}

/** 从引擎借一次身份用于直接查高水位（仅测试用途）。 */
async function keyOf(engine) {
    const identity = await loadIdentity(engine.gameId);
    return [identity.key, identity.installId];
}
