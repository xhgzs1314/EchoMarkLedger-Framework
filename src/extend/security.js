/**
 * ============================================================================
 * 运行时防护模块 L1–L6

 */

import { EchoMarkLedger } from '../core/engine.js';
import { QuadStorage } from '../core/storage.js';
import { sha256 } from '../core/crypto.js';
import { deepFreeze, safeStringify, detectDebugSignals } from '../core/utils.js';

const _GLOBAL = new Map();
const _INTERNAL = new WeakMap();

const SecurityLevel = Object.freeze({
    STANDARD: 'standard',   // L1 + L2
    ENHANCED: 'enhanced',   // L1–L4
    MAXIMUM: 'maximum',     // L1–L6
});

// 捕获原生引用，供 L4 比对
const _nativeToString = Function.prototype.toString;
const _nativeToStringSource = _nativeToString.call(_nativeToString);

// ============================================================================
// L6 安全事件总线
// ============================================================================
class SecurityEventBus {
    constructor() {
        this._listeners = new Map();
        this._threshold = { warn: 3, block: 5, destroy: 8 };
        this._windowMs = 60000;        // 计数滑动窗口
        this._events = new Map();      // `${severity}:${category}` -> 时间戳数组
        this._history = [];
        this._maxHistory = 1000;
        this._handler = null;
        this._destructing = false;     // 重入闸，修 v1 的无限递归
    }

    on(eventType, callback) {
        if (!this._listeners.has(eventType)) this._listeners.set(eventType, []);
        this._listeners.get(eventType).push(callback);
    }

    setExternalHandler(fn) {
        if (typeof fn === 'function') this._handler = fn;
    }

    /**
     * 滑动窗口计数。v1 的计数器永不归零，长会话里偶发 warn 累积到 8 次
     * 就会误触发自毁 —— 玩得越久越容易被自家安全模块打死。
     */
    _count(key, now) {
        const stamps = (this._events.get(key) || []).filter((t) => now - t < this._windowMs);
        stamps.push(now);
        this._events.set(key, stamps);
        return stamps.length;
    }

    emit(severity, category, message, detail = {}) {
        const now = Date.now();
        const event = { timestamp: now, severity, category, message, detail: deepFreeze({ ...detail }) };

        const count = this._count(`${severity}:${category}`, now);

        this._history.push(event);
        if (this._history.length > this._maxHistory) this._history.shift();

        if (this._handler) {
            try { this._handler(event); } catch { /* 宿主回调抛错不影响自身 */ }
        }
        for (const cb of this._listeners.get(category) || []) {
            try { cb(event); } catch { /* 同上 */ }
        }

        if (typeof console !== 'undefined' && console.warn) {
            console.warn(`[EMK-SECURE] ${String(severity).toUpperCase()} | ${category}: ${message}`);
        }

        // 已经在自毁流程里就不再分级响应，否则 fatal → 自毁 → fatal → … 无限递归
        if (this._destructing || this.isDestroyed()) return event;

        if (severity === 'fatal' || count >= this._threshold.destroy) {
            this._selfDestruct(`安全阈值突破（${severity}:${category} 在 ${this._windowMs / 1000}s 内第 ${count} 次）`);
        } else if (severity === 'critical' || count >= this._threshold.block) {
            this._blockOperations(`安全异常次数过多（${severity}:${category} × ${count}）`);
        }
        return event;
    }

    _blockOperations(reason) {
        if (_GLOBAL.get('operationsBlocked')) return;
        _GLOBAL.set('operationsBlocked', true);
        _GLOBAL.set('blockReason', reason);
        this._history.push({
            timestamp: Date.now(), severity: 'warn', category: 'system',
            message: `操作已被阻断: ${reason}`, detail: deepFreeze({}),
        });
    }

    /**
     * 自毁：销毁引擎并置位。
     * v1 在这里 emit('fatal') 导致无限递归；且它直接 throw，
     * 把错误抛进了任意调用方的上下文。v2 只置位 + 销毁，
     * 阻断由后续调用在入口处统一拒绝，不在事件流里抛异常。
     */
    _selfDestruct(reason) {
        if (this._destructing || _GLOBAL.get('selfDestructed')) return;
        this._destructing = true;
        try {
            _GLOBAL.set('selfDestructed', true);
            _GLOBAL.set('destructReason', reason);
            const engine = _GLOBAL.get('activeEngine');
            if (engine && typeof engine.destroy === 'function') {
                try { engine.destroy(); } catch { /* 已销毁 */ }
            }
            _GLOBAL.delete('activeEngine');
            this._history.push({
                timestamp: Date.now(), severity: 'fatal', category: 'system',
                message: `系统自毁: ${reason}`, detail: deepFreeze({}),
            });
            if (this._handler) {
                try {
                    this._handler({
                        timestamp: Date.now(), severity: 'fatal', category: 'system',
                        message: `系统自毁: ${reason}`, detail: deepFreeze({}),
                    });
                } catch { /* 忽略 */ }
            }
        } finally {
            this._destructing = false;
        }
    }

    getHistory() { return [...this._history]; }
    isBlocked() { return !!_GLOBAL.get('operationsBlocked'); }
    isDestroyed() { return !!_GLOBAL.get('selfDestructed'); }
    blockReason() { return _GLOBAL.get('blockReason') || _GLOBAL.get('destructReason') || null; }

    /** 测试与"玩家申诉后恢复"用。阻断在生产中应视为不可逆。 */
    reset() {
        this._events.clear();
        this._history.length = 0;
        this._destructing = false;
        _GLOBAL.delete('operationsBlocked');
        _GLOBAL.delete('blockReason');
        _GLOBAL.delete('selfDestructed');
        _GLOBAL.delete('destructReason');
    }
}
const securityBus = new SecurityEventBus();

// ============================================================================
// L3 函数指纹（真 SHA-256）
// ============================================================================
class FingerprintEngine {
    constructor() {
        this._registry = new Map();
        this._timer = null;
    }

    /** 归一化函数源码后取真 SHA-256。异步，因为 WebCrypto 是异步的。 */
    async compute(fn) {
        if (typeof fn !== 'function') return null;
        try {
            const source = _nativeToString.call(fn)
                .replace(/\/\/.*$/gm, '')
                .replace(/\/\*[\s\S]*?\*\//g, '')
                .replace(/\s+/g, ' ')
                .trim();
            return await sha256(`${fn.name || 'anonymous'}:${fn.length}:${source}`);
        } catch {
            return null;
        }
    }

    async register(name, target) {
        const fingerprint = await this.compute(target);
        if (fingerprint) {
            this._registry.set(name, { target, fingerprint, registeredAt: Date.now() });
        }
        return fingerprint;
    }

    async verify(name) {
        const entry = this._registry.get(name);
        if (!entry) return { valid: false, reason: '未注册' };
        const current = await this.compute(entry.target);
        if (!current) return { valid: false, reason: '无法计算指纹' };
        if (current !== entry.fingerprint) {
            return { valid: false, reason: '指纹不匹配', expected: entry.fingerprint, actual: current };
        }
        return { valid: true };
    }

    async verifyAll() {
        const results = [];
        let allValid = true;
        for (const name of this._registry.keys()) {
            const result = await this.verify(name);
            results.push({ name, ...result });
            if (!result.valid) allValid = false;
        }
        return { allValid, results };
    }

    startMonitoring(intervalMs = 8000) {
        if (this._timer) return;
        const tick = async () => {
            const { allValid, results } = await this.verifyAll();
            if (!allValid) {
                const failed = results.filter((r) => !r.valid);
                securityBus.emit('critical', 'integrity', `检测到 ${failed.length} 个函数指纹异常`, {
                    failed: failed.map((f) => ({ name: f.name, reason: f.reason })),
                });
            }
            this._timer = setTimeout(tick, intervalMs + Math.floor(Math.random() * 2000));
        };
        this._timer = setTimeout(tick, intervalMs);
    }

    stopMonitoring() {
        if (this._timer) { clearTimeout(this._timer); this._timer = null; }
    }
}
const fingerprintEngine = new FingerprintEngine();

// ============================================================================
// L4 反 Hook
// ============================================================================
class AntiHookEngine {
    /**
     * 检测 Function.prototype.toString 是否被替换。
     * 这是这一层里唯一信噪比可接受的判据：把模块加载期捕获的原生实现
     * 与当前实现做比对。
     *
     * v1 还有 detectProxy()，靠 `toString().includes('Proxy')`、
     * `Symbol.toStringTag === 'Proxy'` 之类猜测 —— 规范上 Proxy 对
     * 这些都是透明的，这些判据既抓不到真 Proxy 又会误报箭头函数，已删除。
     */
    checkToStringIntegrity() {
        try {
            if (Function.prototype.toString !== _nativeToString) {
                return { tampered: true, reason: 'Function.prototype.toString 已被替换' };
            }
            if (_nativeToString.call(_nativeToString) !== _nativeToStringSource) {
                return { tampered: true, reason: 'Function.prototype.toString 的源码表示已改变' };
            }
            return { tampered: false };
        } catch (error) {
            return { tampered: true, reason: `检测异常: ${error.message}` };
        }
    }

    /** 关键内置原型是否被冻结。仅作报告，不作判定。 */
    checkPrototypeState() {
        const protos = [
            ['Object', Object.prototype], ['Array', Array.prototype], ['Function', Function.prototype],
        ];
        const details = protos.map(([name, proto]) => ({
            proto: name, frozen: Object.isFrozen(proto), sealed: Object.isSealed(proto),
        }));
        return { allFrozen: details.every((d) => d.frozen), details };
    }

    fullScan() {
        const results = { toStringOk: true, prototypesFrozen: true, timestamp: Date.now() };
        const toStringCheck = this.checkToStringIntegrity();
        if (toStringCheck.tampered) {
            results.toStringOk = false;
            securityBus.emit('critical', 'hook', toStringCheck.reason, toStringCheck);
        }
        results.prototypesFrozen = this.checkPrototypeState().allFrozen;
        return results;
    }
}
const antiHookEngine = new AntiHookEngine();

// ============================================================================
// L1 / L2 封印
// ============================================================================
class SealingSystem {
    sealFunction(target, propName, fn) {
        if (typeof fn !== 'function') return false;
        try {
            Object.defineProperty(target, propName, {
                value: fn, writable: false, configurable: false, enumerable: true,
            });
            return true;
        } catch (error) {
            securityBus.emit('warn', 'tamper', `封印函数 ${propName} 失败`, { error: error.message });
            return false;
        }
    }

    sealClassPrototype(ClassConstructor, options = {}) {
        const { exclude = [], includeOnly = null } = options;
        const proto = ClassConstructor.prototype;
        for (const [name, desc] of Object.entries(Object.getOwnPropertyDescriptors(proto))) {
            if (name === 'constructor' || exclude.includes(name)) continue;
            if (includeOnly && !includeOnly.includes(name)) continue;
            if (typeof desc.value === 'function') this.sealFunction(proto, name, desc.value);
        }
        try {
            Object.freeze(proto);
        } catch (error) {
            securityBus.emit('warn', 'tamper', `冻结 ${ClassConstructor.name}.prototype 失败`, { error: error.message });
        }
    }

    /**
     * 封印对象的自有属性。
     * @param {string[]} exclude 运行期仍需写入的字段必须排除，否则会把实例弄坏
     *        —— v1 就是漏了 QuadStorage 的 db，导致 init() 抛 TypeError。
     */
    sealObjectProperties(obj, { exclude = [], recursive = false } = {}) {
        for (const [key, desc] of Object.entries(Object.getOwnPropertyDescriptors(obj))) {
            if (exclude.includes(key)) continue;
            if (desc.get || desc.set) continue;
            if (desc.writable || desc.configurable) {
                try {
                    Object.defineProperty(obj, key, {
                        value: desc.value, writable: false, configurable: false, enumerable: desc.enumerable,
                    });
                } catch { /* 不可重定义则跳过 */ }
            }
            if (recursive && desc.value && typeof desc.value === 'object' && !Object.isFrozen(desc.value)) {
                this.sealObjectProperties(desc.value, { exclude, recursive: true });
            }
        }
    }

    sealModuleExports(exports) {
        if (exports && typeof exports === 'object') {
            this.sealObjectProperties(exports);
            try { Object.freeze(exports); } catch { /* 忽略 */ }
        }
    }
}
const sealingSystem = new SealingSystem();

// ============================================================================
// L5 引擎代理（可观测性 + 阻断闸门，不是安全边界）
// ============================================================================
class SecureEngineProxy {
    constructor(engineInstance, options = {}) {
        if (!(engineInstance instanceof EchoMarkLedger)) {
            throw new TypeError('SecureEngineProxy 只能包装 EchoMarkLedger 实例');
        }
        this._options = {
            // v2 的 records 已是私有字段，不在公开属性里；这里监控的是只读 getter，
            // 它们本身已经无法被赋值，监控的意义在于发现"原型被换掉"这类异常。
            monitorProperties: ['currentIndex', 'currentHash', 'lastHook', 'genesisHash'],
            blockOnTamper: true,
            ...options,
        };
        this._original = engineInstance;
        this._snapshots = new Map();
        this._accessLog = [];
        this._maxLogSize = 500;
        this._takeSnapshot();
        _GLOBAL.set('activeEngine', engineInstance);
        return this._createProxy();
    }

    _takeSnapshot() {
        for (const prop of this._options.monitorProperties) {
            try {
                const value = this._original[prop];
                this._snapshots.set(prop, typeof value === 'object' && value !== null
                    ? safeStringify(value) : String(value));
            } catch { /* 取不到就跳过 */ }
        }
    }

    _logAccess(prop, action) {
        this._accessLog.push({ prop: String(prop), action, timestamp: Date.now() });
        if (this._accessLog.length > this._maxLogSize) this._accessLog.shift();
    }

    _createProxy() {
        const self = this;
        const original = this._original;

        const guard = (prop) => {
            self._logAccess(prop, 'write-attempt');
            securityBus.emit('critical', 'tamper', `尝试修改受保护属性 ${String(prop)}`, { prop: String(prop) });
        };

        return new Proxy(original, {
            get(target, prop) {
                // receiver 必须是 target：getter 与方法内部要访问 #私有字段，
                // 用 proxy 当 receiver 会直接抛 TypeError。
                const value = Reflect.get(target, prop, target);

                if (typeof value === 'function') {
                    return function (...args) {
                        if (securityBus.isDestroyed()) {
                            throw new Error(`引擎已安全自毁: ${securityBus.blockReason() || '未知原因'}`);
                        }
                        if (securityBus.isBlocked()) {
                            throw new Error(`操作被安全模块阻断: ${securityBus.blockReason() || '未知原因'}`);
                        }
                        try {
                            const result = value.apply(target, args);
                            if (result && typeof result.then === 'function') {
                                return result.then((res) => { self._takeSnapshot(); return res; });
                            }
                            self._takeSnapshot();
                            return result;
                        } catch (error) {
                            securityBus.emit('warn', 'state', `方法 ${String(prop)} 执行异常`, { error: error.message });
                            throw error;
                        }
                    };
                }

                if (self._options.monitorProperties.includes(prop)) {
                    const snapshot = self._snapshots.get(prop);
                    const current = typeof value === 'object' && value !== null ? safeStringify(value) : String(value);
                    if (snapshot !== undefined && snapshot !== current) {
                        securityBus.emit('critical', 'state', `属性 ${String(prop)} 在读取时与快照不一致`, {
                            prop: String(prop),
                        });
                    }
                }
                return value;
            },

            // 引擎内部一律以 target 为 this 运行，永远不会经过这些陷阱，
            // 所以这里可以无条件拒绝，不需要 v1 那种可被绕过的调用栈白名单。
            set(target, prop, value, receiver) {
                if (self._options.monitorProperties.includes(prop)) {
                    guard(prop);
                    if (self._options.blockOnTamper) {
                        throw new Error(`属性 ${String(prop)} 受安全模块保护，禁止修改`);
                    }
                    return false;
                }
                self._logAccess(prop, 'set');
                return Reflect.set(target, prop, value, receiver);
            },

            deleteProperty(target, prop) {
                if (self._options.monitorProperties.includes(prop)) { guard(prop); return false; }
                self._logAccess(prop, 'delete');
                return Reflect.deleteProperty(target, prop);
            },

            defineProperty(target, prop, descriptor) {
                if (self._options.monitorProperties.includes(prop)) { guard(prop); return false; }
                self._logAccess(prop, 'define');
                return Reflect.defineProperty(target, prop, descriptor);
            },
        });
    }
}

// ============================================================================
// 调试对抗
// ============================================================================
class DebugCountermeasures {
    constructor() {
        this._timers = [];
        this._strikes = 0;
    }

    /** 连续多次命中才上报，单次抖动不算。 */
    enableHeuristicProbe(intervalMs = 3000) {
        const tick = () => {
            const signals = detectDebugSignals();
            if (signals.suspicious) {
                if (++this._strikes >= 3) {
                    this._strikes = 0;
                    securityBus.emit('warn', 'debug', '连续多次检测到调试特征', { signals: signals.signals });
                }
            } else if (this._strikes > 0) {
                this._strikes--;
            }
            this._timers.push(setTimeout(tick, intervalMs + Math.floor(Math.random() * 1500)));
        };
        this._timers.push(setTimeout(tick, intervalMs));
    }

    /**
     * 窗口尺寸差检测 DevTools。
     * 误报面很大（缩放、扩展侧栏、分屏、移动端），只发 warn 供服务端做参考信号。
     */
    enableDevToolsDetection(intervalMs = 4000, threshold = 200) {
        const tick = () => {
            try {
                const widthDiff = window.outerWidth - window.innerWidth;
                const heightDiff = window.outerHeight - window.innerHeight;
                if (widthDiff > threshold || heightDiff > threshold) {
                    securityBus.emit('warn', 'debug', '窗口尺寸差异提示 DevTools 可能已打开', { widthDiff, heightDiff });
                }
            } catch { /* 忽略 */ }
            this._timers.push(setTimeout(tick, intervalMs));
        };
        this._timers.push(setTimeout(tick, intervalMs));
    }

    startAll() {
        this.enableHeuristicProbe();
        this.enableDevToolsDetection();
        // v1 还有 enableDebuggerTrap()：每 5s 执行一次 `debugger`。
        // 它会真的冻住正常玩家打开的 DevTools，属于骚扰而非防护，不再提供。
    }

    stopAll() {
        for (const id of this._timers) clearTimeout(id);
        this._timers = [];
        this._strikes = 0;
    }
}
const debugCountermeasures = new DebugCountermeasures();

// ============================================================================
// 存储层加固
// ============================================================================
/** 运行期仍需写入的字段。封成只读会把实例弄坏（v1 漏了 db，init() 直接抛错）。 */
const STORAGE_MUTABLE_FIELDS = Object.freeze(['db', '_macFn']);

class StorageHardening {
    harden(storageInstance) {
        if (!(storageInstance instanceof QuadStorage)) return storageInstance;
        if (_INTERNAL.has(storageInstance)) return storageInstance;

        const criticalMethods = [
            'writeRecord', 'readRecord', 'writeToStore', 'readFromStoreByIndex',
            'clearAll', 'clearStore', 'verifyIntegrity', 'exportAll', 'importAll',
        ];
        const originals = new Map();

        for (const method of criticalMethods) {
            const original = storageInstance[method];
            if (typeof original !== 'function') continue;
            originals.set(method, original);

            // 只记录、不判定。v1 在这里用 stack.includes('EchoMarkLedger') 判断
            // "是否授权调用"，那既拦不住有心人，又会因为文件路径含关键字而失效。
            const wrapped = async function (...args) {
                try {
                    return await original.apply(this, args);
                } catch (error) {
                    securityBus.emit('warn', 'integrity', `QuadStorage.${method} 执行异常`, { error: error.message });
                    throw error;
                }
            };

            try {
                Object.defineProperty(storageInstance, method, {
                    value: wrapped, writable: false, configurable: false, enumerable: true,
                });
            } catch {
                storageInstance[method] = wrapped;
            }
        }

        sealingSystem.sealObjectProperties(storageInstance, { exclude: STORAGE_MUTABLE_FIELDS });
        _INTERNAL.set(storageInstance, { hardened: true, originals });
        return storageInstance;
    }

    restore(storageInstance) {
        const internal = _INTERNAL.get(storageInstance);
        if (!internal) return;
        for (const [method, original] of internal.originals) {
            try {
                Object.defineProperty(storageInstance, method, {
                    value: original, writable: true, configurable: true, enumerable: true,
                });
            } catch { /* 已不可配置 */ }
        }
        _INTERNAL.delete(storageInstance);
    }
}
const storageHardening = new StorageHardening();

// ============================================================================
// 主入口
// ============================================================================
const ENGINE_PROTO_METHODS = [
    'recordOperation', 'loadSave', 'exportSave', 'verifySave',
    'getCurrentState', 'getHistory', 'rekey',
];
const STORAGE_PROTO_METHODS = [
    'init', 'clearAll', 'clearStore', 'writeRecord', 'readRecord', 'buildRows',
    'writeToStore', 'readFromStoreByIndex', 'getAllFromStore',
    'verifyIntegrity', 'exportAll', 'importAll', 'close',
];

/**
 * 封印系统。
 * @param {Object} options
 * @param {string}   options.level                      SecurityLevel 之一
 * @param {Function} options.onSecurityEvent            安全事件回调
 * @param {boolean}  options.hardenStorage              是否加固存储层（默认 true）
 * @param {boolean}  options.enableDebugCountermeasures 是否启用反调试（默认随 level）
 */
async function sealZeroTrustSystem(options = {}) {
    const level = options.level || SecurityLevel.ENHANCED;
    if (options.onSecurityEvent) securityBus.setExternalHandler(options.onSecurityEvent);

    // L2：冻结原型。destroy 保留可调用；构造函数里的 _setupMethodProtection
    // 依赖能在实例上定义同名属性，所以原型方法冻结不影响它。
    sealingSystem.sealClassPrototype(EchoMarkLedger, { exclude: ['destroy'] });
    sealingSystem.sealClassPrototype(QuadStorage);

    // L3：注册指纹
    for (const name of ENGINE_PROTO_METHODS) {
        if (typeof EchoMarkLedger.prototype[name] === 'function') {
            await fingerprintEngine.register(`EchoMarkLedger.prototype.${name}`, EchoMarkLedger.prototype[name]);
        }
    }
    for (const name of STORAGE_PROTO_METHODS) {
        if (typeof QuadStorage.prototype[name] === 'function') {
            await fingerprintEngine.register(`QuadStorage.prototype.${name}`, QuadStorage.prototype[name]);
        }
    }

    if (level === SecurityLevel.ENHANCED || level === SecurityLevel.MAXIMUM) {
        fingerprintEngine.startMonitoring(8000);
        antiHookEngine.fullScan();
    }
    if (level === SecurityLevel.MAXIMUM && options.enableDebugCountermeasures !== false) {
        debugCountermeasures.startAll();
    }

    const shouldHardenStorage = options.hardenStorage !== false;

    const sealedExports = Object.freeze({
        EchoMarkLedger,
        QuadStorage,
        SecurityLevel,
        securityBus,
        fingerprintEngine,
        antiHookEngine,
        sealingSystem,
        debugCountermeasures,
        storageHardening,
        SecureEngineProxy,
        protectEngineInstance,
        getSecurityReport,
        sealZeroTrustSystem,

        /** 创建受保护引擎。MAXIMUM 级别返回 SecureEngineProxy 包装。 */
        createSecureEngine(engineOptions) {
            const engine = new EchoMarkLedger(engineOptions);
            if (shouldHardenStorage && engine.storage) storageHardening.harden(engine.storage);
            if (level === SecurityLevel.MAXIMUM) return new SecureEngineProxy(engine);
            _GLOBAL.set('activeEngine', engine);
            return engine;
        },
    });

    _GLOBAL.set('sealed', true);
    _GLOBAL.set('securityLevel', level);
    _GLOBAL.set('sealedAt', Date.now());
    securityBus.emit('warn', 'system', `EchoMarkLedger 系统已封印，安全级别: ${level}`);
    return sealedExports;
}

/** ENHANCED + 存储加固，不开反调试。 */
function quickSeal(onSecurityEvent) {
    return sealZeroTrustSystem({
        level: SecurityLevel.ENHANCED, onSecurityEvent,
        hardenStorage: true, enableDebugCountermeasures: false,
    });
}

/** MAXIMUM 全开。 */
function maximumSeal(onSecurityEvent) {
    return sealZeroTrustSystem({
        level: SecurityLevel.MAXIMUM, onSecurityEvent,
        hardenStorage: true, enableDebugCountermeasures: true,
    });
}

function protectEngineInstance(engineInstance, options = {}) {
    return new SecureEngineProxy(engineInstance, options);
}

async function getSecurityReport() {
    return {
        sealed: !!_GLOBAL.get('sealed'),
        level: _GLOBAL.get('securityLevel') || 'none',
        sealedAt: _GLOBAL.get('sealedAt'),
        operationsBlocked: securityBus.isBlocked(),
        selfDestructed: securityBus.isDestroyed(),
        blockReason: securityBus.blockReason(),
        fingerprintStatus: await fingerprintEngine.verifyAll(),
        recentEvents: securityBus.getHistory().slice(-20),
    };
}

export {
    sealZeroTrustSystem, quickSeal, maximumSeal, protectEngineInstance, getSecurityReport,
    SecurityLevel, SecurityEventBus, FingerprintEngine, AntiHookEngine, SealingSystem,
    SecureEngineProxy, DebugCountermeasures, StorageHardening,
    securityBus, fingerprintEngine, antiHookEngine, sealingSystem,
    debugCountermeasures, storageHardening,
};
export default sealZeroTrustSystem;
