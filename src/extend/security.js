/**
 * ============================================================================
 * 运行时防篡改防护模块
 * ============================================================================
 * 
 * 防护层次：
 *   L1 - 模块封印 (Module Sealing)      : 冻结导出对象，防止属性覆盖
 *   L2 - 原型守卫 (Prototype Guard)     : 冻结类原型，防止原型链污染
 *   L3 - 指纹校验 (Fingerprint Check)  : 运行时计算函数指纹，检测替换
 *   L4 - 反 Hook 检测 (Anti-Hook)      : 检测 toString 篡改、Proxy 包装
 *   L5 - 状态监控 (State Monitor)       : 监控引擎实例关键属性的异常变更
 *   L6 - 安全事件总线 (Security Bus)    : 统一上报与分级响应
 * 
 * 加载要求：必须在 EchoMarkLedger.js 之后加载
 * 使用方式：import { sealZeroTrustSystem, SecurityLevel,protectEngineInstance } from './security.js'
 * 或script引入EchoMarkLedger-secure.js
 * ============================================================================
 */
// 内部符号与隐蔽存储
const _SYM_ORIGINALS = Symbol.for('ZTE._originals');
const _SYM_FINGERPRINT = Symbol.for('ZTE._fingerprints');
const _SYM_GUARD = Symbol.for('ZTE._guard');
const _SYM_SEALED = Symbol.for('ZTE._sealed');
const _SYM_PROXY = Symbol.for('ZTE._proxy');
const _INTERNAL = new WeakMap();   // 实例
const _GLOBAL = new Map();       // 模块
// 安全级别枚举
const SecurityLevel = Object.freeze({
    STANDARD: 'standard',   // L1 + L2：基础封印
    ENHANCED: 'enhanced',   // L1-L4：增加指纹与反 Hook
    MAXIMUM: 'maximum'     // L1-L6：全功能开启
});
// 安全事件总线
class SecurityEventBus {
    constructor() {
        this._listeners = new Map();
        this._threshold = { warn: 3, block: 5, destroy: 8 };
        this._counters = new Map();   // 按类型计数
        this._history = [];          // 事件日志
        this._maxHistory = 1000;
        this._handler = null;        // 外部自定义处理器
    }

    on(eventType, callback) {
        if (!this._listeners.has(eventType)) this._listeners.set(eventType, []);
        this._listeners.get(eventType).push(callback);
    }

    setExternalHandler(fn) {
        if (typeof fn === 'function') this._handler = fn;
    }

    emit(severity, category, message, detail = {}) {
        const event = {
            timestamp: Date.now(),
            severity,           // 'warn' | 'critical' | 'fatal'
            category,           // 'tamper' | 'hook' | 'integrity' | 'state' | 'debug'
            message,
            detail: deepFreeze({ ...detail })
        };
        // 计数器
        const key = `${severity}:${category}`;
        this._counters.set(key, (this._counters.get(key) || 0) + 1);
        const count = this._counters.get(key);
        // 日志
        this._history.push(event);
        if (this._history.length > this._maxHistory) this._history.shift();

        // 外部处理器
        if (this._handler) {
            try { this._handler(event); } catch (e) { }
        }
        // 内置监听器
        const listeners = this._listeners.get(category) || [];
        for (const cb of listeners) {
            try { cb(event); } catch (e) { }
        }

        // 分级响应
        if (severity === 'fatal' || count >= this._threshold.destroy) {
            this._selfDestruct('安全阈值突破，执行自毁');
        } else if (severity === 'critical' || count >= this._threshold.block) {
            this._blockOperations('安全异常次数过多，暂停服务');
        }
        // 控制台警告
        if (typeof console !== 'undefined' && console.warn) {
            console.warn(`[ZTE-SECURE] ${severity.toUpperCase()} | ${category}: ${message}`);
        }
    }

    _blockOperations(reason) {
        _GLOBAL.set('operationsBlocked', true);
        _GLOBAL.set('blockReason', reason);
        this.emit('warn', 'system', `操作已被阻断: ${reason}`);
    }

    _selfDestruct(reason) {
        _GLOBAL.set('selfDestructed', true);
        try {
            const engine = _GLOBAL.get('activeEngine');
            if (engine && typeof engine.destroy === 'function') {
                engine.destroy();
            }
        } catch (e) { }
        _GLOBAL.delete('activeEngine');
        this.emit('fatal', 'system', `系统自毁: ${reason}`);
        throw new Error(`EchoMarkLedger 安全自毁: ${reason}`);
    }

    getHistory() { return [...this._history]; }
    isBlocked() { return !!_GLOBAL.get('operationsBlocked'); }
    isDestroyed() { return !!_GLOBAL.get('selfDestructed'); }
}
const securityBus = new SecurityEventBus();
// 指纹引擎
class FingerprintEngine {
    constructor() {
        this._registry = new Map();   // target -> { hash, descriptor }
        this._checkInterval = null;
    }

    /**
     * 计算函数指纹(include-> toString、名称、参数长度、源码哈希
     */
    compute(fn) {
        if (typeof fn !== 'function') return null;
        try {
            const name = fn.name || 'anonymous';
            const length = fn.length;
            const toStr = Function.prototype.toString.call(fn);
            // 提取函数体
            const body = toStr
                .replace(/\/\/.*$/gm, '')
                .replace(/\/\*[\s\S]*?\*\//g, '')
                .replace(/\s+/g, ' ')
                .trim();
            const raw = `${name}:${length}:${body}`;
            return sha256Sync(raw);
        } catch (e) {
            return null;
        }
    }

    register(name, target) {
        const fp = this.compute(target);
        if (fp) {
            this._registry.set(name, {
                target,
                fingerprint: fp,
                registeredAt: Date.now()
            });
        }
        return fp;
    }

    verify(name) {
        const entry = this._registry.get(name);
        if (!entry) return { valid: false, reason: '未注册' };
        const current = this.compute(entry.target);
        if (!current) return { valid: false, reason: '无法计算指纹' };
        if (current !== entry.fingerprint) {
            return {
                valid: false,
                reason: '指纹不匹配',
                expected: entry.fingerprint,
                actual: current
            };
        }
        return { valid: true };
    }

    verifyAll() {
        const results = [];
        let allValid = true;
        for (const [name, entry] of this._registry) {
            const result = this.verify(name);
            results.push({ name, ...result });
            if (!result.valid) allValid = false;
        }
        return { allValid, results };
    }

    startMonitoring(intervalMs = 5000) {
        if (this._checkInterval) return;
        const jitter = () => Math.floor(Math.random() * 1000);
        const check = () => {
            const { allValid, results } = this.verifyAll();
            if (!allValid) {
                const failed = results.filter(r => !r.valid);
                securityBus.emit('critical', 'integrity',
                    `检测到 ${failed.length} 个函数指纹异常`,
                    { failed: failed.map(f => ({ name: f.name, reason: f.reason })) }
                );
            }
            // 随机抖动
            this._checkInterval = setTimeout(check, intervalMs + jitter());
        };
        this._checkInterval = setTimeout(check, intervalMs);
    }

    stopMonitoring() {
        if (this._checkInterval) {
            clearTimeout(this._checkInterval);
            this._checkInterval = null;
        }
    }
}
const fingerprintEngine = new FingerprintEngine();
// 反 Hook 检测引擎
class AntiHookEngine {
    constructor() {
        this._baselineToString = Function.prototype.toString;
        this._baselineApply = Function.prototype.apply;
        this._baselineCall = Function.prototype.call;
        this._baselineBind = Function.prototype.bind;
    }

    /**
     * 检测 Function.prototype.toString 是否被篡改
     */
    checkToStringIntegrity() {
        try {
            const testFn = function nativeCheck() { return 42; };
            const nativeStr = this._baselineToString.call(testFn);
            const currentStr = testFn.toString();
            // 如果 toString 被 hook
            if (nativeStr !== currentStr) {
                return {
                    tampered: true,
                    reason: 'Function.prototype.toString 被篡改',
                    native: nativeStr,
                    current: currentStr
                };
            }
            return { tampered: false };
        } catch (e) {
            return { tampered: true, reason: `检测异常: ${e.message}` };
        }
    }

    /**
     * 检测目标函数是否被 Proxy 包装
     */
    detectProxy(target) {
        if (typeof target !== 'function') return { proxied: false };
        try {
            // 检查 toString 结果是否包含 Proxy 特征
            const str = Function.prototype.toString.call(target);
            if (str.includes('Proxy')) {
                return { proxied: true, reason: 'toString 包含 Proxy 标识' };
            }

            // C：一般Proxy 函数没有有效的 prototype 属性描述符
            const protoDesc = Object.getOwnPropertyDescriptor(target, 'prototype');
            if (!protoDesc) {
                // 箭头函数也没有 prototype?
                if (target.prototype === undefined) {
                    // 可能箭头函数，也可能是 Proxy
                    const nameDesc = Object.getOwnPropertyDescriptor(target, 'name');
                    if (nameDesc && nameDesc.configurable === false) {
                        return { proxied: false };
                    }
                }
            }

            // 检查 Symbol.toStringTag
            const tag = target[Symbol.toStringTag];
            if (tag === 'Proxy') {
                return { proxied: true, reason: 'Symbol.toStringTag 返回 Proxy' };
            }

            // 检查是否为 revocable proxy
            try {
                const testObj = {};
                const desc = Object.getOwnPropertyDescriptor(target, 'constructor');
                if (!desc && target.prototype === undefined && target.length === 0) {
                    return { proxied: false, suspicious: true };
                }
            } catch (e) {
                return { proxied: true, reason: '属性访问异常' };
            }

            return { proxied: false };
        } catch (e) {
            return { proxied: true, reason: `检测异常: ${e.message}` };
        }
    }

    /**
     * 检测内置对象是否被污染
     */
    checkPrototypePollution() {
        const checks = [];
        const criticalProtos = [Object.prototype, Array.prototype, Function.prototype];
        for (const proto of criticalProtos) {
            const frozen = Object.isFrozen(proto);
            const sealed = Object.isSealed(proto);
            checks.push({
                proto: proto.constructor.name,
                frozen,
                sealed,
                safe: frozen || sealed
            });
        }
        const unsafe = checks.filter(c => !c.safe);
        return {
            safe: unsafe.length === 0,
            allFrozen: checks.every(c => c.frozen),
            details: checks
        };
    }

    /**
     * 综合扫描
     */
    fullScan(targetFunctions = []) {
        const results = {
            toStringOk: true,
            proxyDetected: [],
            prototypePollution: true,
            timestamp: Date.now()
        };

        // toString 完整性
        const toStringCheck = this.checkToStringIntegrity();
        if (toStringCheck.tampered) {
            results.toStringOk = false;
            securityBus.emit('critical', 'hook', toStringCheck.reason, toStringCheck);
        }

        // Proxy 检测
        for (const [name, fn] of targetFunctions) {
            const proxyCheck = this.detectProxy(fn);
            if (proxyCheck.proxied) {
                results.proxyDetected.push({ name, ...proxyCheck });
                securityBus.emit('critical', 'hook', `函数 ${name} 被 Proxy 包装`, proxyCheck);
            }
        }

        // 原型状态（仅记录）
        const pollutionCheck = this.checkPrototypePollution();
        if (!pollutionCheck.allFrozen) {
            results.prototypePollution = false;
        }

        return results;
    }
}

const antiHookEngine = new AntiHookEngine();
// 封印System
class SealingSystem {
    /**
     * 封印函数
     */
    sealFunction(target, propName, fn) {
        if (typeof fn !== 'function') return false;
        try {
            Object.defineProperty(target, propName, {
                value: fn,
                writable: false,
                configurable: false,
                enumerable: true
            });
            // 封印函数本身属性
            Object.defineProperty(fn, 'name', {
                value: fn.name,
                configurable: false
            });
            return true;
        } catch (e) {
            securityBus.emit('warn', 'tamper', `封印函数 ${propName} 失败`, { error: e.message });
            return false;
        }
    }

    /**
     * 封印类原型上所有方法
     */
    sealClassPrototype(ClassConstructor, options = {}) {
        const { exclude = [], includeOnly = null } = options;
        const proto = ClassConstructor.prototype;
        const descriptors = Object.getOwnPropertyDescriptors(proto);

        for (const [name, desc] of Object.entries(descriptors)) {
            if (name === 'constructor') continue;
            if (exclude.includes(name)) continue;
            if (includeOnly && !includeOnly.includes(name)) continue;

            if (typeof desc.value === 'function') {
                this.sealFunction(proto, name, desc.value);
            }
        }

        // 冻结原型本身
        try {
            Object.freeze(proto);
        } catch (e) {
            securityBus.emit('warn', 'tamper', `冻结 ${ClassConstructor.name}.prototype 失败`, { error: e.message });
        }
    }

    /**
     * 封印对象的所有可枚举属性
     */
    sealObjectProperties(obj, recursive = false) {
        const descriptors = Object.getOwnPropertyDescriptors(obj);
        for (const [key, desc] of Object.entries(descriptors)) {
            if (desc.writable || desc.configurable) {
                try {
                    Object.defineProperty(obj, key, {
                        value: desc.value,
                        writable: false,
                        configurable: false,
                        enumerable: desc.enumerable
                    });
                } catch (e) {
                }
            }
            if (recursive && desc.value && typeof desc.value === 'object' && !Object.isFrozen(desc.value)) {
                this.sealObjectProperties(desc.value, true);
            }
        }
    }

    /**
     * 封印模块导出对象
     */
    sealModuleExports(exports) {
        if (exports && typeof exports === 'object') {
            this.sealObjectProperties(exports, false);
            try { Object.seal(exports); } catch (e) { }
        }
    }
}
const sealingSystem = new SealingSystem();
// 安全代理包装器
class SecureEngineProxy {
    constructor(engineInstance, options = {}) {
        if (!(engineInstance instanceof EchoMarkLedger)) {
            throw new TypeError('SecureEngineProxy 只能包装 EchoMarkLedger 实例');
        }

        this._options = {
            monitorProperties: ['records', 'currentIndex', 'currentHash', 'lastHook', 'genesisHash'],
            blockOnTamper: true,
            ...options
        };

        this._original = engineInstance;
        this._propertySnapshots = new Map();
        this._accessLog = [];
        this._maxLogSize = 500;
        // 初始化快照
        this._takeSnapshot();
        // 注册全局
        _GLOBAL.set('activeEngine', engineInstance);
        return this._createProxy();
    }

    _takeSnapshot() {
        for (const prop of this._options.monitorProperties) {
            try {
                const val = this._original[prop];
                this._propertySnapshots.set(prop, {
                    type: typeof val,
                    hash: typeof val === 'object' && val !== null
                        ? sha256Sync(safeStringify(val))
                        : String(val),
                    timestamp: Date.now()
                });
            } catch (e) { }
        }
    }

    _verifySnapshot(prop, currentValue) {
        const snapshot = this._propertySnapshots.get(prop);
        if (!snapshot) return { ok: true };

        const currentHash = typeof currentValue === 'object' && currentValue !== null
            ? sha256Sync(safeStringify(currentValue))
            : String(currentValue);

        if (snapshot.hash !== currentHash) {
            return {
                ok: false,
                reason: `${prop} 哈希不匹配`,
                expected: snapshot.hash,
                actual: currentHash
            };
        }
        return { ok: true };
    }

    _logAccess(prop, action) {
        this._accessLog.push({ prop, action, timestamp: Date.now() });
        if (this._accessLog.length > this._maxLogSize) this._accessLog.shift();
    }

    _createProxy() {
        const self = this;
        const original = this._original;

        return new Proxy(original, {
            get(target, prop, receiver) {
                if (typeof prop === 'symbol' && prop !== _SYM_PROXY) {
                    self._logAccess(prop.toString(), 'get');
                }
                const value = Reflect.get(target, prop, receiver);
                // 检查属性描述符(read-only && non-configurable)
                const desc = Object.getOwnPropertyDescriptor(target, prop);
                if (desc && desc.writable === false && desc.configurable === false) {
                    return value;
                }

                if (typeof value === 'function') {
                    const originalMethod = value;

                    return function (...args) {
                        if (securityBus.isBlocked()) {
                            throw new Error(`操作被安全模块阻断: ${_GLOBAL.get('blockReason') || '未知原因'}`);
                        }
                        if (securityBus.isDestroyed()) {
                            throw new Error('引擎已安全自毁');
                        }

                        if (['recordOperation', 'loadSave', 'exportSave', 'verifySave'].includes(prop)) {
                            const entry = fingerprintEngine._registry.get(`EchoMarkLedger.prototype.${prop}`);
                            if (entry) {
                                const currentFp = fingerprintEngine.compute(originalMethod);
                                if (currentFp && currentFp !== entry.fingerprint) {
                                    securityBus.emit('critical', 'tamper', `方法 ${prop} 被篡改`);
                                    if (self._options.blockOnTamper) {
                                        throw new Error(`方法 ${prop} 完整性校验失败`);
                                    }
                                }
                            }
                        }

                        try {
                            const result = originalMethod.apply(target, args);
                            if (result && typeof result.then === 'function') {
                                return result.then(
                                    res => { self._takeSnapshot(); return res; },
                                    err => { throw err; }
                                );
                            }
                            self._takeSnapshot();
                            return result;
                        } catch (err) {
                            securityBus.emit('warn', 'state', `方法 ${prop} 执行异常`, { error: err.message });
                            throw err;
                        }
                    };
                }

                if (self._options.monitorProperties.includes(prop)) {
                    const verify = self._verifySnapshot(prop, value);
                    if (!verify.ok) {
                        securityBus.emit('critical', 'state',
                            `属性 ${prop} 在读取时被篡改`, verify);
                    }
                }

                return value;
            },

            set(target, prop, value, receiver) {
                self._logAccess(prop, 'set');
                // 检查调用栈
                const stack = new Error().stack || '';
                const isInternalCall = stack.includes('recordOperation') ||
                    stack.includes('loadSave') ||
                    stack.includes('_freezeState') ||
                    stack.includes('verifySave') ||
                    stack.includes('_updateBackwardVerifications') ||
                    stack.includes('_buildLinkedVerifications') ||
                    stack.includes('_triggerSave') ||
                    stack.includes('init') ||
                    stack.includes('EchoMarkLedger');

                if (self._options.monitorProperties.includes(prop) && !isInternalCall) {
                    securityBus.emit('critical', 'tamper',
                        `尝试非法修改属性 ${prop}`,
                        { prop, attemptedValue: value });
                    if (self._options.blockOnTamper) {
                        throw new Error(`属性 ${prop} 受安全模块保护，禁止修改`);
                    }
                }

                return Reflect.set(target, prop, value, receiver);
            },

            deleteProperty(target, prop) {
                self._logAccess(prop, 'delete');
                const stack = new Error().stack || '';
                const isInternalCall = stack.includes('recordOperation') ||
                    stack.includes('loadSave') ||
                    stack.includes('_freezeState') ||
                    stack.includes('verifySave') ||
                    stack.includes('_updateBackwardVerifications') ||
                    stack.includes('_buildLinkedVerifications') ||
                    stack.includes('_triggerSave') ||
                    stack.includes('init') ||
                    stack.includes('EchoMarkLedger');

                if (self._options.monitorProperties.includes(prop) && !isInternalCall) {
                    securityBus.emit('critical', 'tamper', `尝试删除属性 ${prop}`);
                    return false;
                }
                return Reflect.deleteProperty(target, prop);
            },

            defineProperty(target, prop, descriptor) {
                self._logAccess(prop, 'define');
                const stack = new Error().stack || '';
                const isInternalCall = stack.includes('recordOperation') ||
                    stack.includes('loadSave') ||
                    stack.includes('_freezeState') ||
                    stack.includes('verifySave') ||
                    stack.includes('_updateBackwardVerifications') ||
                    stack.includes('_buildLinkedVerifications') ||
                    stack.includes('_triggerSave') ||
                    stack.includes('init') ||
                    stack.includes('EchoMarkLedger');

                if (self._options.monitorProperties.includes(prop) && !isInternalCall) {
                    securityBus.emit('critical', 'tamper', `尝试重定义属性 ${prop}`);
                    return false;
                }
                return Reflect.defineProperty(target, prop, descriptor);
            }
        });
    }
}
// 7. 调试对抗
class DebugCountermeasures {
    constructor() {
        this._detectors = [];
        this._interval = null;
        this._debuggerTrap = null;
    }
    /**
     * 时间侧信道检测
     */
    enableTimingCheck(thresholdMs = 100) {
        const check = () => {
            const start = performance.now();
            // 极短操作
            for (let i = 0; i < 1000; i++) { Math.sqrt(i); }
            const elapsed = performance.now() - start;
            if (elapsed > thresholdMs) {
                securityBus.emit('warn', 'debug', '检测到异常执行延迟，可能处于调试状态', { elapsed });
            }
        };
        this._detectors.push(setInterval(check, 3000));
    }

    /**
     * DevTools 特征检测
     */
    enableDevToolsDetection() {
        const threshold = 160;
        const check = () => {
            const widthDiff = window.outerWidth - window.innerWidth;
            const heightDiff = window.outerHeight - window.innerHeight;
            if (widthDiff > threshold || heightDiff > threshold) {
                securityBus.emit('warn', 'debug', '检测到 DevTools 可能已打开', {
                    widthDiff, heightDiff
                });
            }
        };
        this._detectors.push(setInterval(check, 2000));
    }

    /**
     * debugger 陷阱
     */
    enableDebuggerTrap() {
        const trap = new Function('if (false) debugger;');
        this._debuggerTrap = setInterval(() => {
            try { trap(); } catch (e) { }
        }, 5000);
    }

    /**
     * 检测 console 是否被打开
     */
    enableConsoleDetection() {
        const check = () => {
            const element = new Image();
            let detected = false;
            Object.defineProperty(element, 'id', {
                get: () => { detected = true; return 'dev'; }
            });
            console.log('%c', element);
            if (detected) {
                securityBus.emit('warn', 'debug', '通过 console 副作用检测到 DevTools');
            }
        };
        this._detectors.push(setInterval(check, 5000));
    }

    startAll() {
        this.enableTimingCheck();
        this.enableDevToolsDetection();
        this.enableDebuggerTrap();
        // console 检测在某些浏览器可能误报,自行判断是否启用
        // this.enableConsoleDetection();
    }

    stopAll() {
        for (const id of this._detectors) clearInterval(id);
        this._detectors = [];
        if (this._debuggerTrap) clearInterval(this._debuggerTrap);
    }
}
const debugCountermeasures = new DebugCountermeasures();
// 存储层加固
class StorageHardening {
    constructor() {
        this._originalMethods = new WeakMap();
    }

    /**
     * 为 QuadStorage 实例添加访问日志和完整性校验
     */
    harden(storageInstance) {
        if (!(storageInstance instanceof QuadStorage)) return storageInstance;
        if (_INTERNAL.has(storageInstance)) return storageInstance;
        const self = this;
        const criticalMethods = [
            'writeRecord', 'readRecord', 'writeToStore',
            'readFromStoreByIndex', 'clearAll', 'clearStore',
            'verifyIntegrity', 'exportAll', 'importAll'
        ];
        const originals = new Map();
        for (const method of criticalMethods) {
            const original = storageInstance[method];
            if (typeof original !== 'function') continue;
            originals.set(method, original);
            const wrapped = async function (...args) {
                // 校验调用者身份
                const stack = new Error().stack || '';
                const isAuthorized = stack.includes('EchoMarkLedger') || stack.includes('help.js');
                if (!isAuthorized) {
                    securityBus.emit('warn', 'tamper',
                        `QuadStorage.${method} 被非授权调用`,
                        { stack: stack.split('\n').slice(0, 4).join('\n') });
                }

                try {
                    const result = await original.apply(this, args);
                    return result;
                } catch (e) {
                    securityBus.emit('critical', 'tamper',
                        `QuadStorage.${method} 执行异常`, { error: e.message });
                    throw e;
                }
            };

            // 使用 defineProperty 替换
            try {
                Object.defineProperty(storageInstance, method, {
                    value: wrapped,
                    writable: false,
                    configurable: false,
                    enumerable: true
                });
            } catch (e) {
                storageInstance[method] = wrapped;
            }
        }

        // 封印实例属性
        sealingSystem.sealObjectProperties(storageInstance);
        // 标记
        _INTERNAL.set(storageInstance, { hardened: true, originals });
        return storageInstance;
    }

    /**
     * 恢复原始方法
     */
    restore(storageInstance) {
        const internal = _INTERNAL.get(storageInstance);
        if (!internal || !internal.originals) return;
        for (const [method, original] of internal.originals) {
            try {
                Object.defineProperty(storageInstance, method, {
                    value: original,
                    writable: true,
                    configurable: true,
                    enumerable: true
                });
            } catch (e) {
                storageInstance[method] = original;
            }
        }
        _INTERNAL.delete(storageInstance);
    }
}

const storageHardening = new StorageHardening();
// 主入口
/**
 * 封印 EchoMarkLedger 系统
 * @param {Object} options
 * @param {string} options.level - SecurityLevel 之一
 * @param {Function} options.onSecurityEvent - 安全事件回调
 * @param {boolean} options.hardenStorage - 是否加固存储层
 * @param {boolean} options.enableDebugCountermeasures - 是否启用反调试
 * @returns {Object} 封印后的导出对象
 */
function sealZeroTrustSystem(options = {}) {
    const level = options.level || SecurityLevel.ENHANCED;
    if (options.onSecurityEvent) {
        securityBus.setExternalHandler(options.onSecurityEvent);
    }
    const utilsExports = {
        sha256, sha256Sync, generateNonce, fisherYatesShuffle,
        deriveRandomFromSeed, captureRuntimeContext, deepEqual,
        serializeForHash, antiDebugDetection, deepFreeze,
        deriveDynamicSalt, deriveOffset, safeStringify, computeSlotPosition
    };
    sealingSystem.sealModuleExports(utilsExports);
    for (const [name, fn] of Object.entries(utilsExports)) {
        fingerprintEngine.register(`utils.${name}`, fn);
    }
    sealingSystem.sealClassPrototype(EchoMarkLedger, {
        exclude: ['constructor', 'destroy']  // destroy 允许调用
    });
    sealingSystem.sealClassPrototype(QuadStorage);
    const engineProtoMethods = [
        'recordOperation', 'loadSave', 'exportSave', 'verifySave',
        'getCurrentState', 'getHistory', '_generateHook',
        '_buildLinkedVerifications', '_updateBackwardVerifications',
        '_deriveStableSalt', '_getRecentStateHashes'
    ];
    for (const name of engineProtoMethods) {
        if (typeof EchoMarkLedger.prototype[name] === 'function') {
            fingerprintEngine.register(`EchoMarkLedger.prototype.${name}`, EchoMarkLedger.prototype[name]);
        }
    }

    const storageProtoMethods = [
        'init', 'clearAll', 'clearStore', 'writeRecord', 'readRecord',
        'writeToStore', 'readFromStoreByIndex', 'getAllFromStore',
        'verifyIntegrity', 'exportAll', 'importAll', 'close'
    ];
    for (const name of storageProtoMethods) {
        if (typeof QuadStorage.prototype[name] === 'function') {
            fingerprintEngine.register(`QuadStorage.prototype.${name}`, QuadStorage.prototype[name]);
        }
    }
    // L3-L4: 增强级与最高级开启指纹监控和反 Hook
    if (level === SecurityLevel.ENHANCED || level === SecurityLevel.MAXIMUM) {
        // 指纹定时校验
        fingerprintEngine.startMonitoring(8000);
        // Hook 扫描
        const targetFunctions = [
            ...Object.entries(utilsExports),
            ...engineProtoMethods.map(m => [`EchoMarkLedger.prototype.${m}`, EchoMarkLedger.prototype[m]]),
            ...storageProtoMethods.map(m => [`QuadStorage.prototype.${m}`, QuadStorage.prototype[m]])
        ].filter(([, fn]) => typeof fn === 'function');

        antiHookEngine.fullScan(targetFunctions);
    }
    // L5-L6: 状态监控和反调试
    if (level === SecurityLevel.MAXIMUM) {
        if (options.enableDebugCountermeasures !== false) {
            debugCountermeasures.startAll();
        }
    }
    const shouldHardenStorage = options.hardenStorage !== false;
    const sealedExports = Object.freeze({
        // 原始类
        EchoMarkLedger,
        QuadStorage,
        // 工具函数
        sha256, sha256Sync, generateNonce, fisherYatesShuffle,
        deriveRandomFromSeed, captureRuntimeContext, deepEqual,
        serializeForHash, antiDebugDetection, deepFreeze,
        deriveDynamicSalt, deriveOffset, safeStringify, computeSlotPosition,
        // 安全基础设施
        SecurityLevel,
        securityBus,
        fingerprintEngine,
        antiHookEngine,
        sealingSystem,
        debugCountermeasures,
        storageHardening,
        // 高级 API
        SecureEngineProxy,
        sealZeroTrustSystem,
        // 便捷方法
        createSecureEngine: (opts) => {
            const engine = new EchoMarkLedger(opts);
            if (shouldHardenStorage && engine.storage) {
                storageHardening.harden(engine.storage);
            }
            if (level === SecurityLevel.MAXIMUM) {
                return new SecureEngineProxy(engine);
            }
            return engine;
        }
    });

    // 将封印标记写入全局
    _GLOBAL.set('sealed', true);
    _GLOBAL.set('securityLevel', level);
    _GLOBAL.set('sealedAt', Date.now());
    securityBus.emit('warn', 'system', `EchoMarkLedger 系统已封印，安全级别: ${level}`);
    return sealedExports;
}
// 便捷 API
/**
 * 快速封印
 */
function quickSeal(onSecurityEvent) {
    return sealZeroTrustSystem({
        level: SecurityLevel.ENHANCED,
        onSecurityEvent,
        hardenStorage: true,
        enableDebugCountermeasures: false
    });
}

/**
 * 最大防护
 */
function maximumSeal(onSecurityEvent) {
    return sealZeroTrustSystem({
        level: SecurityLevel.MAXIMUM,
        onSecurityEvent,
        hardenStorage: true,
        enableDebugCountermeasures: true
    });
}

/**
 * 包装已有引擎实例
 */
function protectEngineInstance(engineInstance, options = {}) {
    return new SecureEngineProxy(engineInstance, options);
}

/**
 * 获取安全状态报告
 */
function getSecurityReport() {
    const fpResult = fingerprintEngine.verifyAll();
    return {
        sealed: !!_GLOBAL.get('sealed'),
        level: _GLOBAL.get('securityLevel') || 'none',
        sealedAt: _GLOBAL.get('sealedAt'),
        operationsBlocked: securityBus.isBlocked(),
        selfDestructed: securityBus.isDestroyed(),
        fingerprintStatus: fpResult,
        recentEvents: securityBus.getHistory().slice(-20)
    };
}
export {
    sealZeroTrustSystem,
    quickSeal,
    maximumSeal,
    protectEngineInstance,
    getSecurityReport,
    SecurityLevel,
    SecurityEventBus,
    FingerprintEngine,
    AntiHookEngine,
    SealingSystem,
    SecureEngineProxy,
    DebugCountermeasures,
    StorageHardening,
    securityBus,
    fingerprintEngine,
    antiHookEngine,
    sealingSystem,
    debugCountermeasures,
    storageHardening
};
export default sealZeroTrustSystem;