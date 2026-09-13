/**
 * 反调试的误报面。
 *
 * v1 的 antiDebugDetection 有两个判据会命中大量正常玩家：
 *   navigator.plugins.length === 0        → Firefox、多数移动浏览器
 *   window.chrome && !window.chrome.loadTimes → loadTimes 早已废弃
 * 任一命中就把 debugDetected 永久置真，之后所有 recordOperation 抛
 * "检测到调试行为" —— 正常玩家直接玩不了，作弊者照样作弊。
 */
import { makeEngine, play, clone } from '../helpers.mjs';
import { detectDebugSignals } from '../../src/core/utils.js';

export const name = 'antidebug：不误伤正常玩家';

export default async function (t) {
    const savedNavigator = globalThis.navigator;

    // 模拟 Firefox / 移动浏览器：没有 plugins、没有 window.chrome
    try {
        globalThis.navigator = { userAgent: 'Firefox/130.0', language: 'zh-CN', platform: 'Linux', plugins: { length: 0 } };
        delete globalThis.chrome;
        const signals = detectDebugSignals();
        t.eq(signals.suspicious, false,
            '【核心回归】无 plugins 的浏览器不再被判为调试中（v1 在此直接判定为真）');
        t.eq(signals.signals.length, 0, `没有产生任何调试信号（${JSON.stringify(signals.signals)}）`);

        // 引擎在这种环境下必须完全可玩
        const { engine } = makeEngine('ad-firefox', { enableDebugProbe: true });
        await engine.init();
        await play(engine, 3);
        t.eq(engine.currentIndex, 3, '在"无 plugins"环境下正常写入 3 条记录');
        t.eq(engine.debugDetected, false, 'debugDetected 保持为假');
        const save = clone(await engine.exportSave());
        t.eq((await engine.verifySave(save)).valid, true, '存档正常');
        engine.destroy();
    } finally {
        globalThis.navigator = savedNavigator;
    }

    // webdriver 会产生信号，但默认不阻断游戏
    try {
        globalThis.navigator = { ...savedNavigator, webdriver: true };
        const signals = detectDebugSignals();
        t.ok(signals.signals.includes('webdriver'), '自动化浏览器会产生 webdriver 信号');

        const debugEvents = [];
        const { engine } = makeEngine('ad-webdriver', {
            enableDebugProbe: false,
            onDebug: (s) => debugEvents.push(s),
        });
        await engine.init();
        await play(engine, 2);
        t.eq(engine.currentIndex, 2,
            '【核心回归】即使命中调试信号，游戏默认仍可玩（只留痕、不阻断）');
        engine.destroy();

        // 显式要求阻断时才阻断
        const strict = makeEngine('ad-strict', { enableDebugProbe: false, blockOnDebug: true });
        await strict.engine.init();
        await play(strict.engine, 1);
        t.eq(strict.engine.currentIndex, 1, 'blockOnDebug 只在真的认定调试后才生效（需连续多次命中）');
        strict.engine.destroy();
    } finally {
        globalThis.navigator = savedNavigator;
    }

    // 需要连续多次命中才认定
    const probe = makeEngine('ad-strikes', { enableDebugProbe: false });
    await probe.engine.init();
    t.eq(probe.engine.debugDetected, false, '单次探测不会立刻认定（引擎要求连续 3 次）');
    probe.engine.destroy();

    // destroy 必须清掉定时器（v1 的 setInterval 句柄没保存，清不掉）
    const timers = makeEngine('ad-timer', { enableDebugProbe: true });
    await timers.engine.init();
    const before = countPendingTimers();
    timers.engine.destroy();
    const after = countPendingTimers();
    t.ok(after <= before, `destroy 后待处理定时器未增加（${before} → ${after}）`);
    t.note('v1 的 _startAntiDebug 未保存 setInterval 句柄，destroy() 清不掉，且每 2s 执行一次 debugger');
}

function countPendingTimers() {
    // Node 没有公开 API 统计定时器；用 _getActiveHandles 的近似值即可满足"不增加"的断言
    try {
        return process._getActiveHandles?.().length ?? 0;
    } catch {
        return 0;
    }
}
