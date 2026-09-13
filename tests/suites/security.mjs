/**
 * L1–L6 运行时防护
 */
import { makeEngine, play, clone } from '../helpers.mjs';
import {
    SecurityEventBus, sealZeroTrustSystem, SecurityLevel, securityBus,
    fingerprintEngine, antiHookEngine, protectEngineInstance, getSecurityReport,
    storageHardening, debugCountermeasures,
} from '../../src/extend/security.js';
import { EchoMarkLedger } from '../../src/core/engine.js';

export const name = 'security：L1–L6 的实际行为';

export default async function (t) {
    // ---- 1. fatal 不再无限递归 ----
    const bus = new SecurityEventBus();
    let handlerCalls = 0;
    bus.setExternalHandler(() => { handlerCalls++; });
    let thrown = null;
    try { bus.emit('fatal', 'integrity', '测试 fatal'); } catch (error) { thrown = error; }
    t.eq(thrown, null, '【核心回归】fatal 事件不再抛 RangeError（v1 在此栈溢出）');
    t.ok(bus.getHistory().length < 10, `事件历史长度正常（${bus.getHistory().length} 条，v1 会冲到 1000）`);
    t.eq(bus.isDestroyed(), true, 'fatal 之后确实置位为已自毁');
    t.ok(handlerCalls >= 1 && handlerCalls < 10, `外部处理器被调用 ${handlerCalls} 次，没有递归风暴`);
    bus.reset();

    // ---- 2. 滑动窗口计数：陈旧事件不累积 ----
    const bus2 = new SecurityEventBus();
    bus2._windowMs = 50;
    for (let i = 0; i < 7; i++) bus2.emit('warn', 'debug', `第 ${i} 次`);
    t.eq(bus2.isDestroyed(), false, '窗口内 7 次 warn 尚未触发自毁');
    await new Promise((r) => setTimeout(r, 80));
    for (let i = 0; i < 7; i++) bus2.emit('warn', 'debug', `新一轮第 ${i} 次`);
    t.eq(bus2.isDestroyed(), false,
        '【核心回归】陈旧事件过期后不再累积（v1 计数器永不归零，长会话必然误自毁）');
    bus2.reset();

    // ---- 3. 自毁会真的销毁引擎 ----
    const victim = makeEngine('sec-destruct');
    await victim.engine.init();
    const bus3 = new SecurityEventBus();
    // 借用全局槽位：securityBus 与 _GLOBAL 共享状态，这里用真 securityBus 走一遍
    securityBus.reset();
    const guarded = protectEngineInstance(victim.engine);
    securityBus.emit('fatal', 'tamper', '模拟致命篡改');
    t.eq(securityBus.isDestroyed(), true, '全局总线已置位自毁');
    await t.rejects(() => guarded.exportSave(), '自毁', '自毁后经由代理的调用被拒绝');
    securityBus.reset();
    t.eq(securityBus.isDestroyed(), false, 'reset 之后状态清空（仅测试用途）');

    // ---- 4. hardenStorage 之后 init() 必须仍能工作 ----
    const hardened = makeEngine('sec-harden');
    storageHardening.harden(hardened.engine.storage);
    let hardenedInit = null;
    try { hardenedInit = await hardened.engine.init(); } catch (error) { hardenedInit = error; }
    t.ok(hardenedInit && hardenedInit.H,
        `【核心回归】加固存储后 init() 正常（v1 抛 TypeError: Cannot assign to read only property 'db'）`);
    await play(hardened.engine, 2);
    const hardenedSave = clone(await hardened.engine.exportSave());
    t.eq((await hardened.engine.verifySave(hardenedSave)).valid, true, '加固后读写与校验都正常');
    hardened.engine.destroy();

    // ---- 5. 封印系统 + 文档里的 API 必须真实存在 ----
    const secure = await sealZeroTrustSystem({
        level: SecurityLevel.MAXIMUM,
        hardenStorage: true,
        enableDebugCountermeasures: false,
    });
    t.eq(typeof secure.createSecureEngine, 'function', 'createSecureEngine 存在');
    t.eq(typeof secure.protectEngineInstance, 'function',
        'protectEngineInstance 挂在返回对象上（v1 为 undefined，README 示例跑不起来）');
    t.eq(typeof secure.getSecurityReport, 'function', 'getSecurityReport 存在');
    t.ok(Object.isFrozen(secure), '返回的导出对象已冻结');

    const proxied = secure.createSecureEngine({
        gameId: `sec-proxy-${Math.random().toString(36).slice(2, 8)}`,
        enableDebugProbe: false,
        onLoad: async () => null,
        onSave: async () => {},
    });
    const pInit = await proxied.init();
    t.ok(pInit && pInit.H, '【核心回归】MAXIMUM 级别的代理引擎能 init（私有字段 + 代理不冲突）');
    const step = await proxied.recordOperation({ type: 'VIA_PROXY' }, pInit.currentHook);
    t.eq(step.index, 1, '经由代理写入记录正常');
    t.ok(proxied.getCurrentState() !== null, '经由代理调用 getCurrentState 正常（receiver 处理正确）');
    t.eq(typeof proxied.currentHash, 'string', '经由代理读取 getter 正常');
    const proxySave = clone(await proxied.exportSave());
    t.eq((await proxied.verifySave(proxySave)).valid, true, '经由代理导出并校验正常');

    // ---- 6. L5：写保护不再依赖可绕过的调用栈白名单 ----
    let blocked = 0;
    const tryWrite = (fn) => { try { fn(); } catch { blocked++; } };
    tryWrite(() => { proxied.currentIndex = 999; });
    const renamed = function () { proxied.currentIndex = 999; };
    Object.defineProperty(renamed, 'name', { value: 'EchoMarkLedger' });
    tryWrite(renamed);
    const init = () => { proxied.currentHash = 'c'.repeat(64); };
    tryWrite(init);
    t.eq(blocked, 3,
        '【核心回归】三种写入尝试全部被拦（v1 只拦第一种，改名为 EchoMarkLedger 或 init 即可绕过）');
    t.neq(proxied.currentIndex, 999, 'currentIndex 未被改动');

    // 篡改尝试会触发分级响应，后续操作被阻断 —— 这正是 L6 该做的事
    t.eq(securityBus.isBlocked(), true, '连续篡改尝试后操作被阻断');
    await t.rejects(() => proxied.exportSave(), '阻断', '阻断生效后经由代理的调用被拒绝');

    securityBus.reset();
    proxied.destroy();

    // ---- 7. 指纹使用真 SHA-256 ----
    const fp = await fingerprintEngine.compute(function sample(a, b) { return a + b; });
    t.eq(typeof fp, 'string', '指纹计算返回字符串');
    t.eq(fp.length, 64, '指纹长度为 64 个 hex（SHA-256）');
    const fpRepeatHalf = fp.slice(0, 32) === fp.slice(32);
    t.eq(fpRepeatHalf, false,
        '【核心回归】指纹后半不是前半的重复（v1 的 sha256Sync 把 128bit 重复两遍冒充 256bit）');
    const fpCheck = await fingerprintEngine.verify('EchoMarkLedger.prototype.recordOperation');
    t.eq(fpCheck.valid, true, '已注册的方法指纹校验通过');

    // ---- 8. L4 只保留有意义的判据 ----
    t.eq(antiHookEngine.checkToStringIntegrity().tampered, false, '未被 hook 时 toString 检查为干净');
    const savedToString = Function.prototype.toString;
    try {
        // eslint-disable-next-line no-extend-native
        Function.prototype.toString = function () { return 'fake'; };
        t.eq(antiHookEngine.checkToStringIntegrity().tampered, true, '替换 toString 能被检出');
    } finally {
        Function.prototype.toString = savedToString;
    }
    t.eq(typeof antiHookEngine.detectProxy, 'undefined',
        'v1 那套靠 toString().includes("Proxy") 猜测的检测已删除（规范上 Proxy 对此透明）');

    const report = await getSecurityReport();
    t.eq(report.sealed, true, '安全报告显示系统已封印');
    t.eq(report.level, SecurityLevel.MAXIMUM, '安全报告显示级别正确');

    fingerprintEngine.stopMonitoring();
    debugCountermeasures.stopAll();
    victim.engine.destroy();
    securityBus.reset();
    t.ok(bus3 instanceof SecurityEventBus, '独立总线实例可单独构造（便于宿主隔离）');

    // ---- 9. 换掉方法也拿不到内部状态 ----
    const raw = new EchoMarkLedger({
        gameId: `sec-priv-${Math.random().toString(36).slice(2, 8)}`,
        enableDebugProbe: false,
    });
    await raw.init();
    t.eq(raw.records, undefined, '内部记录不是公开属性');
    t.eq(Object.keys(raw).includes('genesisHash'), false, 'genesisHash 不在自有可枚举属性里（是 getter）');
    const leaked = Object.keys(raw).filter((k) => /key|identity|secret/i.test(k));
    t.eq(leaked.length, 0, '实例上没有任何看起来像密钥的属性（密钥存在模块级 WeakMap）');
    raw.destroy();
}
