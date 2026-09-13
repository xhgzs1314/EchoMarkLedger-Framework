import { EchoMarkLedger } from '../src/core/engine.js';

export const clone = (value) => JSON.parse(JSON.stringify(value));

let seq = 0;
/** 每个用例用独立 gameId，避免共用同一个 IndexedDB 相互污染。 */
export function uniqueGameId(prefix) {
    return `${prefix}-${++seq}-${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * 建一个带内存存档槽的引擎。
 * @returns {{engine: EchoMarkLedger, box: {save: Object|null}, gameId: string}}
 */
export function makeEngine(prefix, options = {}) {
    const gameId = options.gameId || uniqueGameId(prefix);
    const box = { save: null };
    const engine = new EchoMarkLedger({
        gameId,
        onLoad: async () => box.save,
        onSave: async (save) => { box.save = save; },
        enableDebugProbe: false,     // 测试里不需要后台探针占着事件循环
        ...options,
    });
    return { engine, box, gameId };
}

/** 走 N 步操作，返回最后的 hook。 */
export async function play(engine, steps, makeOp = (i) => ({ type: 'STEP', i })) {
    let hook = engine.getCurrentState().hook;
    for (let i = 0; i < steps; i++) {
        hook = (await engine.recordOperation(makeOp(i), hook)).currentHook;
    }
    return hook;
}
