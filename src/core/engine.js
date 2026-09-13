

import { canonicalFor } from './canonical.js';
import { hmac, randomHex, timingSafeEqualHex } from './crypto.js';
import { loadIdentity, rotateIdentity, loadHighWater, saveHighWater } from './keystore.js';
import {
    QuadStorage, verifyStorageWitness, describeFailures, SLOT_SPACE,
} from './storage.js';
import { captureRuntimeContext, deepFreeze, detectDebugSignals } from './utils.js';

const SAVE_FORMAT_VERSION = 2;
const ZERO_HASH = '0'.repeat(64);
const DEFAULT_MAX_RECORDS = 100000;

/**
 * 密钥句柄只存在这里，以引擎实例为键。
 * 刻意不放在实例属性上 —— 控制台里翻遍 engine 对象也找不到 key。
 */
const _identities = new WeakMap();

function deepCopy(value) {
    if (typeof structuredClone === 'function') return structuredClone(value);
    return JSON.parse(JSON.stringify(value));
}

/**
 * 链条校验器：纯函数，不碰任何实例状态、不碰数据库。
 * verifySave 与 loadSave 共用它，保证"校验通过的存档"与"被应用的存档"
 * 经过的是同一套规则。
 */
async function verifyChain(saveData, ctx) {
    const {
        gameId, version, installId, mac,
        verificationWindow, maxRecords, clockToleranceMs,
        validateOperation, requireStorageWitness, slotSpace,
    } = ctx;

    if (!saveData || typeof saveData !== 'object') return { valid: false, error: '存档为空' };
    if (saveData.formatVersion !== SAVE_FORMAT_VERSION) {
        return {
            valid: false,
            reason: 'format',
            error: `存档格式版本不受支持: ${saveData.formatVersion ?? '缺失'}（当前引擎要求 ${SAVE_FORMAT_VERSION}）`
                + (saveData.formatVersion === undefined ? '；v1 存档请先用 migrateV1ToV2 迁移' : ''),
        };
    }
    if (!saveData.genesisHash || !Array.isArray(saveData.records)) {
        return { valid: false, error: '存档结构无效' };
    }
    if (saveData.records.length === 0) return { valid: false, error: '存档不含任何记录' };
    if (saveData.records.length > maxRecords) {
        return { valid: false, error: `记录数 ${saveData.records.length} 超过上限 ${maxRecords}` };
    }
    if (saveData.installId !== installId) {
        return {
            valid: false,
            reason: 'foreign-device',
            error: '这份存档属于另一台设备（或另一个浏览器配置），本机密钥无法校验它',
        };
    }

    let computedHash = '';
    let lastTimestamp = -Infinity;

    for (let i = 0; i < saveData.records.length; i++) {
        const record = saveData.records[i];
        if (!record || typeof record !== 'object' || !record.params || !record.verify) {
            return { valid: false, corruptedIndex: i, error: `记录 ${i} 结构无效` };
        }
        if (record.index !== i) {
            return { valid: false, corruptedIndex: i, error: `索引不连续: 期望 ${i}, 实际 ${record.index}` };
        }

        const { operation, timestamp, nonce, runtimeContext, customData } = record.params;
        if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) {
            return { valid: false, corruptedIndex: i, error: `记录 ${i} 时间戳无效` };
        }
        if (timestamp + clockToleranceMs < lastTimestamp) {
            return { valid: false, corruptedIndex: i, error: `记录 ${i} 时间戳回退（${timestamp} < ${lastTimestamp}）` };
        }
        lastTimestamp = Math.max(lastTimestamp, timestamp);

        let expectedHash;
        let expectedHook;
        let prevHook;

        if (i === 0) {
            if (record.params.prevHash !== ZERO_HASH) {
                return { valid: false, corruptedIndex: 0, error: '创世记录的 prevHash 必须为 64 个 0' };
            }
            expectedHash = await mac('genesis', { gameId, version, timestamp, nonce, runtimeContext, installId });
            expectedHook = await mac('hook-genesis', { H: expectedHash, nonce });
            prevHook = ZERO_HASH;
        } else {
            const prevRecord = saveData.records[i - 1];
            if (record.params.prevHash !== prevRecord.H) {
                return { valid: false, corruptedIndex: i, error: '前序哈希不匹配' };
            }
            expectedHash = await mac('record', {
                index: i, prevHash: record.params.prevHash, operation, timestamp, nonce, runtimeContext,
                customData: customData || {},
            });
            expectedHook = await mac('hook', { H: expectedHash, nonce, timestamp });
            prevHook = prevRecord.verify.hook;
        }

        if (!timingSafeEqualHex(expectedHash, record.H)) {
            return {
                valid: false, corruptedIndex: i,
                error: i === 0 ? '创世哈希验证失败' : '状态哈希验证失败',
            };
        }
        if (!timingSafeEqualHex(expectedHook, record.verify.hook)) {
            return { valid: false, corruptedIndex: i, error: i === 0 ? '创世 hook 不匹配' : 'hook 不匹配' };
        }

        const expectedDynamic = await mac('dynamic', { H: record.H, nonce, index: i });
        if (!timingSafeEqualHex(expectedDynamic, record.verify.dynamic)) {
            return { valid: false, corruptedIndex: i, error: 'dynamic 验证失败' };
        }

        const expectedComposite = await mac('composite', { dynamic: expectedDynamic, prevHook, hook: expectedHook });
        if (!timingSafeEqualHex(expectedComposite, record.verify.composite)) {
            return { valid: false, corruptedIndex: i, error: 'composite 验证失败' };
        }

        // 双向验证网络
        const links = record.linkedVerifications;
        if (links !== undefined) {
            if (!Array.isArray(links)) {
                return { valid: false, corruptedIndex: i, error: `记录 ${i} 的 linkedVerifications 不是数组` };
            }
            for (const link of links) {
                if (!link || typeof link !== 'object') {
                    return { valid: false, corruptedIndex: i, error: `记录 ${i} 存在无效的交叉验证项` };
                }
                if (link.V === 'pending') {
                    // 只允许"还没有后继记录"的位置留占位符，否则就是有人把算好的值抹成 pending
                    if (link.offset > 0 && link.targetIndex < saveData.records.length) {
                        return {
                            valid: false, corruptedIndex: i,
                            error: `记录 ${i} 与 ${link.targetIndex} 的交叉验证被抹为 pending`,
                        };
                    }
                    continue;
                }
                if (Math.abs(link.offset) > verificationWindow || link.offset === 0) {
                    return { valid: false, corruptedIndex: i, error: `记录 ${i} 的交叉验证 offset ${link.offset} 越界` };
                }
                if (link.targetIndex !== i + link.offset) {
                    return { valid: false, corruptedIndex: i, error: `记录 ${i} 的交叉验证目标索引与 offset 不符` };
                }
                const target = saveData.records[link.targetIndex];
                if (!target) {
                    return { valid: false, corruptedIndex: i, error: `记录 ${i} 的交叉验证指向不存在的记录 ${link.targetIndex}` };
                }
                const [a, b] = link.offset < 0 ? [target.H, record.H] : [record.H, target.H];
                const expectedSalt = await mac('link-salt', { a, b, offset: link.offset });
                if (!timingSafeEqualHex(expectedSalt, link.salt)) {
                    return { valid: false, corruptedIndex: i, error: `双向验证 salt 失败: 索引 ${i} 与 ${link.targetIndex}` };
                }
                const expectedV = await mac('link', { a, b, salt: expectedSalt, offset: link.offset });
                if (!timingSafeEqualHex(expectedV, link.V)) {
                    return { valid: false, corruptedIndex: i, error: `双向验证失败: 索引 ${i} 与 ${link.targetIndex}` };
                }
            }
        }

        // 业务语义校验：与写入路径调用同一个钩子，避免 README §10.2d 的"必须对称改两处"
        if (validateOperation) {
            let verdict;
            try {
                verdict = await validateOperation(operation, customData || {}, saveData.records.slice(0, i));
            } catch (error) {
                return { valid: false, corruptedIndex: i, error: `业务校验抛错: ${error.message}` };
            }
            if (verdict === false || (verdict && verdict.valid === false)) {
                return {
                    valid: false, corruptedIndex: i, reason: 'semantic',
                    error: `业务校验拒绝记录 ${i}: ${verdict?.reason || '不合法的操作'}`,
                };
            }
        }

        computedHash = record.H;
    }

    const lastIndex = saveData.records.length - 1;
    const lastRecord = saveData.records[lastIndex];

    // 校验点
    if (!saveData.checkpoint || saveData.checkpoint.index !== lastIndex) {
        return { valid: false, error: '校验点缺失或未指向最后一条记录' };
    }
    const expectedCp = await mac('checkpoint', {
        H: lastRecord.H, genesisHash: saveData.genesisHash, index: lastIndex,
    });
    if (!timingSafeEqualHex(expectedCp, saveData.checkpoint.verifyHash)) {
        return { valid: false, error: '校验点验证失败' };
    }

    // 整链 MAC：一次性抓出截断、拼接、换设备
    const expectedChainMac = await mac('chain', {
        gameId, version, installId,
        genesisHash: saveData.genesisHash,
        lastIndex,
        hashes: saveData.records.map((r) => r.H),
    });
    if (!timingSafeEqualHex(expectedChainMac, saveData.checkpoint.chainMac)) {
        return { valid: false, error: '整链 MAC 验证失败（记录被截断、拼接或来自其它设备）' };
    }

    if (saveData.genesisHash !== saveData.records[0].H) {
        return { valid: false, error: 'genesisHash 与创世记录不一致' };
    }

    // 四表快照必须与记录链指向同一份存档
    if (saveData._storageData) {
        const witness = await verifyStorageWitness(
            saveData._storageData, saveData.records,
            (message) => hmacWith(ctx, message), slotSpace,
        );
        if (!witness.valid) {
            return { valid: false, corruptedIndex: witness.corruptedIndex, error: `四表校验失败: ${witness.error}` };
        }
    } else if (requireStorageWitness) {
        return {
            valid: false, reason: 'missing-witness',
            error: '存档缺少 _storageData 四表快照；如确为有意裁剪，请用 { requireStorageWitness: false } 加载',
        };
    }

    return {
        valid: true,
        computed: { currentHash: computedHash, lastHook: lastRecord.verify.hook, lastIndex },
    };
}

function hmacWith(ctx, message) {
    return ctx.rawMac(message);
}

class EchoMarkLedger {
    #records = [];
    #currentIndex = -1;
    #currentHash = '';
    #lastHook = '';
    #genesisHash = '';
    #frozenState = null;
    #initialized = false;
    #queue = Promise.resolve();
    #storage = null;
    #autoSaveTimer = null;
    #debugTimer = null;
    #debugDetected = false;
    #debugStrikes = 0;
    #installId = '';
    #destroyed = false;
    #saveTimer = null;
    #savePending = false;

    constructor(options = {}) {
        this.gameId = options.gameId || 'default-game';
        this.version = options.version || '1.0.0';
        this.onSave = options.onSave || null;
        this.onLoad = options.onLoad || null;
        this.onDebug = options.onDebug || null;

        this.verificationWindow = Number.isInteger(options.verificationWindow)
            ? Math.max(0, options.verificationWindow) : 3;
        this.autoSaveInterval = options.autoSaveInterval || 0;
        /**
         * 合并写入窗口（毫秒）。
         *
         * 每次 recordOperation 成功后都会触发 onSave，而 onSave 拿到的是完整存档，
         * 所以每条记录的固定开销与链长成正比 —— 连续写入 N 条就是 O(N²)。
         * 实测 200 条连续写入：0 表示每条都导出 ≈32ms/条；把导出去掉后 ≈3.9ms/条。
         *
         * 设为 >0 时，一串连续写入只在末尾导出一次，长度换来线性开销。
         * 代价是最后一次写入到落盘之间有一个窗口期，此时崩溃会丢掉窗口内的进度
         * （链条本身仍在 IndexedDB 里，不会损坏）。
         */
        this.saveDebounceMs = options.saveDebounceMs || 0;
        this.maxRecords = options.maxRecords || DEFAULT_MAX_RECORDS;
        this.clockToleranceMs = options.clockToleranceMs ?? 5 * 60 * 1000;
        this.requireStorageWitness = options.requireStorageWitness !== false;
        this.allowRollback = options.allowRollback === true;
        this.blockOnDebug = options.blockOnDebug === true;
        this.enableDebugProbe = options.enableDebugProbe !== false;
        this.validateOperation = typeof options.validateOperation === 'function'
            ? options.validateOperation : null;

        this.#storage = options.storage || new QuadStorage(`${this.gameId}_db`, 1);
        this.#storage.setMacFn((message) => this.#rawMac(message));

        this._setupMethodProtection();
    }

    /**
     * 把关键方法固定成实例上的不可写属性，阻止 `engine.recordOperation = 假货`
     * 这类最省事的替换（严格模式下直接抛 TypeError）。
     *
     * 刻意保留 configurable: true —— Proxy 规范要求"自有的不可写且不可配置属性"
     * 在 get 陷阱里必须原值返回，那样 L5 的 SecureEngineProxy 就无法包装这四个
     * 方法，阻断闸门对它们失效（v1 正是如此）。
     * 真正的保护来自 #私有字段：换掉方法的人拿不到内部状态，伪造不出合法链条。
     */
    _setupMethodProtection() {
        const critical = ['recordOperation', 'loadSave', 'exportSave', 'verifySave'];
        for (const name of critical) {
            Object.defineProperty(this, name, {
                value: this[name], writable: false, configurable: true, enumerable: true,
            });
        }
    }

    // ========== 只读视图 ==========
    // 全部是 getter：赋值在严格模式下直接抛 TypeError，无需运行时白名单。
    get initialized() { return this.#initialized; }
    get currentIndex() { return this.#currentIndex; }
    get currentHash() { return this.#currentHash; }
    get lastHook() { return this.#lastHook; }
    get genesisHash() { return this.#genesisHash; }
    get installId() { return this.#installId; }
    get debugDetected() { return this.#debugDetected; }
    get recordCount() { return this.#records.length; }
    get storage() { return this.#storage; }
    get frozenState() { return this.#frozenState; }

    // ========== 私有：签名 ==========
    #identity() {
        const identity = _identities.get(this);
        if (!identity) throw new Error('引擎未初始化（设备密钥未加载）');
        return identity;
    }

    /** 带用途标签的 MAC。用途标签做域分隔，防止某用途的合法值被搬到另一用途。 */
    async #mac(purpose, payload) {
        return await hmac(this.#identity().key, canonicalFor(purpose, payload));
    }

    /** 已经拼好消息串时用（供 QuadStorage 注入）。 */
    async #rawMac(message) {
        return await hmac(this.#identity().key, message);
    }

    #verifyContext() {
        const self = this;
        return {
            gameId: this.gameId,
            version: this.version,
            installId: this.#installId,
            verificationWindow: this.verificationWindow,
            maxRecords: this.maxRecords,
            clockToleranceMs: this.clockToleranceMs,
            requireStorageWitness: this.requireStorageWitness,
            validateOperation: this.validateOperation,
            slotSpace: this.#storage.SLOT_SPACE || SLOT_SPACE,
            mac: (purpose, payload) => self.#mac(purpose, payload),
            rawMac: (message) => self.#rawMac(message),
        };
    }

    /** 串行化所有会改动内部状态的操作。 */
    #enqueue(task) {
        const run = this.#queue.then(task, task);
        this.#queue = run.then(() => undefined, () => undefined);
        return run;
    }

    // ========== 初始化 ==========
    async init() {
        return this.#enqueue(async () => {
            if (this.#initialized) throw new Error('引擎已初始化');
            if (this.#destroyed) throw new Error('引擎已销毁');

            const identity = await loadIdentity(this.gameId);
            _identities.set(this, { key: identity.key, installId: identity.installId });
            this.#installId = identity.installId;

            await this.#storage.init();

            if (this.onLoad) {
                try {
                    const existing = await this.onLoad();
                    if (existing) {
                        const applied = await this.#applySave(existing, {});
                        if (applied.valid) {
                            this.#initialized = true;
                            this.#startDebugProbe();
                            if (this.autoSaveInterval > 0) this.#startAutoSave();
                            return {
                                H: this.#currentHash, currentHook: this.#lastHook,
                                restored: true, lastIndex: this.#currentIndex,
                            };
                        }
                        // 载入失败不静默：把原因交给宿主决定是"新开一局"还是"报错给玩家"
                        console.warn(`[EchoMarkLedger] 已有存档未通过校验，将新建存档。原因: ${applied.error}`);
                        this.#restoreEmpty();
                    }
                } catch (error) {
                    console.warn('[EchoMarkLedger] 加载已有存档失败:', error.message);
                    this.#restoreEmpty();
                }
            }

            await this.#createGenesis();
            this.#initialized = true;
            this.#startDebugProbe();
            if (this.autoSaveInterval > 0) this.#startAutoSave();
            await this.#triggerSave();

            return { H: this.#genesisHash, currentHook: this.#lastHook, restored: false };
        });
    }

    async #createGenesis() {
        const nonce = randomHex(32);
        const timestamp = Date.now();
        const runtimeContext = captureRuntimeContext();
        const installId = this.#installId;

        const H = await this.#mac('genesis', {
            gameId: this.gameId, version: this.version, timestamp, nonce, runtimeContext, installId,
        });
        const hook = await this.#mac('hook-genesis', { H, nonce });
        const dynamic = await this.#mac('dynamic', { H, nonce, index: 0 });
        const composite = await this.#mac('composite', { dynamic, prevHook: ZERO_HASH, hook });

        const genesisRecord = {
            index: 0,
            H,
            params: {
                operation: { type: 'GENESIS', gameId: this.gameId },
                prevHash: ZERO_HASH,
                timestamp, nonce, runtimeContext,
                customData: {},
            },
            verify: { dynamic, hook, composite },
            linkedVerifications: this.#pendingLinks(0),
        };

        this.#records = [genesisRecord];
        this.#genesisHash = H;
        this.#currentHash = H;
        this.#currentIndex = 0;
        this.#lastHook = hook;

        await this.#storage.clearAll();
        await this.#storage.writeRecord(genesisRecord, 0, this.#recentStateHashes(0));
        this.#freezeState();
        await this.#advanceHighWater();
    }

    #pendingLinks(index) {
        const links = [];
        for (let offset = 1; offset <= this.verificationWindow; offset++) {
            links.push({ targetIndex: index + offset, offset, salt: 'pending', V: 'pending' });
        }
        return links;
    }

    // ========== 记录操作 ==========
    async recordOperation(operation, prevHook, customData = {}) {
        return this.#enqueue(async () => {
            if (!this.#initialized) throw new Error('引擎未初始化');
            if (this.#destroyed) throw new Error('引擎已销毁');
            if (this.blockOnDebug && this.#debugDetected) throw new Error('检测到调试行为');
            if (!prevHook || !timingSafeEqualHex(prevHook, this.#lastHook)) {
                throw new Error(`钩子验证失败: 期望 ${this.#lastHook.slice(0, 16)}..., 收到 ${prevHook ? String(prevHook).slice(0, 16) + '...' : 'null'}`);
            }
            if (!operation || typeof operation !== 'object' || !operation.type) {
                throw new Error('操作对象必须包含 type 字段');
            }
            if (this.#records.length >= this.maxRecords) {
                throw new Error(`记录数已达上限 ${this.maxRecords}`);
            }
            if (this.validateOperation) {
                const verdict = await this.validateOperation(operation, customData, this.#records.slice());
                if (verdict === false || (verdict && verdict.valid === false)) {
                    throw new Error(`业务校验拒绝该操作: ${verdict?.reason || '不合法的操作'}`);
                }
            }

            const index = this.#currentIndex + 1;
            const timestamp = Date.now();
            const nonce = randomHex(16);
            const runtimeContext = captureRuntimeContext();
            const prevHash = this.#currentHash;
            const prevHook_ = this.#lastHook;

            const H = await this.#mac('record', {
                index, prevHash, operation, timestamp, nonce, runtimeContext, customData,
            });
            const hook = await this.#mac('hook', { H, nonce, timestamp });
            const dynamic = await this.#mac('dynamic', { H, nonce, index });
            const composite = await this.#mac('composite', { dynamic, prevHook: prevHook_, hook });

            const record = {
                index, H,
                params: { operation, prevHash, timestamp, nonce, runtimeContext, customData },
                verify: { dynamic, hook, composite },
                linkedVerifications: [
                    ...(await this.#buildBackwardLinks(index, H)),
                    ...this.#pendingLinks(index),
                ],
            };

            // 先把新记录入链，再回填前序记录的 pending 占位
            this.#records.push(record);
            await this.#fillForwardLinks(index, H);

            this.#currentIndex = index;
            this.#currentHash = H;
            this.#lastHook = hook;

            try {
                await this.#storage.writeRecord(record, index, this.#recentStateHashes(index));
            } catch (error) {
                // 落库失败就回滚内存，不留下"内存有、库里没有"的错位
                this.#records.pop();
                this.#currentIndex = index - 1;
                this.#currentHash = prevHash;
                this.#lastHook = prevHook_;
                await this.#clearForwardLinks(index);
                throw new Error(`记录落库失败，已回滚: ${error.message}`);
            }

            this.#freezeState();
            await this.#advanceHighWater();
            await this.#triggerSave();

            return { index, H, currentHook: hook, timestamp };
        });
    }

    async #buildBackwardLinks(index, currentHash) {
        const links = [];
        for (let offset = -this.verificationWindow; offset < 0; offset++) {
            const targetIndex = index + offset;
            if (targetIndex < 0) continue;
            const target = this.#records[targetIndex];
            if (!target) continue;
            const salt = await this.#mac('link-salt', { a: target.H, b: currentHash, offset });
            const V = await this.#mac('link', { a: target.H, b: currentHash, salt, offset });
            links.push({ targetIndex, offset, salt, V });
        }
        return links;
    }

    async #fillForwardLinks(index, currentHash) {
        for (let offset = 1; offset <= this.verificationWindow; offset++) {
            const prevIndex = index - offset;
            if (prevIndex < 0) continue;
            const prevRecord = this.#records[prevIndex];
            if (!prevRecord) continue;
            const pending = prevRecord.linkedVerifications.find(
                (link) => link.targetIndex === index && link.V === 'pending');
            if (!pending) continue;
            const salt = await this.#mac('link-salt', { a: prevRecord.H, b: currentHash, offset });
            pending.salt = salt;
            pending.V = await this.#mac('link', { a: prevRecord.H, b: currentHash, salt, offset });
        }
    }

    async #clearForwardLinks(index) {
        for (let offset = 1; offset <= this.verificationWindow; offset++) {
            const prevRecord = this.#records[index - offset];
            if (!prevRecord) continue;
            const link = prevRecord.linkedVerifications.find((l) => l.targetIndex === index);
            if (link) { link.salt = 'pending'; link.V = 'pending'; }
        }
    }

    #recentStateHashes(index) {
        const hashes = [];
        for (let i = 0; i < 4; i++) {
            const idx = index - i;
            const record = idx >= 0 ? this.#records[idx] : null;
            hashes.push(record ? record.H : (this.#genesisHash || 'genesis'));
        }
        return hashes;
    }

    // ========== 导出 ==========
    async exportSave() {
        if (!this.#initialized) throw new Error('引擎未初始化');
        const lastIndex = this.#currentIndex;
        const lastRecord = this.#records[lastIndex];

        const checkpointHash = await this.#mac('checkpoint', {
            H: lastRecord.H, genesisHash: this.#genesisHash, index: lastIndex,
        });
        const chainMac = await this.#mac('chain', {
            gameId: this.gameId, version: this.version, installId: this.#installId,
            genesisHash: this.#genesisHash, lastIndex,
            hashes: this.#records.map((r) => r.H),
        });

        // 深拷贝：v1 直接返回 this.records，调用方手里的"快照"会随后续操作一起变，
        // 且 loadSave 之后引擎与调用方共享引用，产生校验通过后再改内容的 TOCTOU。
        return {
            formatVersion: SAVE_FORMAT_VERSION,
            version: this.version,
            genesisHash: this.#genesisHash,
            installId: this.#installId,
            records: deepCopy(this.#records),
            metadata: {
                gameId: this.gameId,
                createTime: this.#records[0]?.params?.timestamp || Date.now(),
                lastPlayTime: Date.now(),
                totalOperations: lastIndex,
            },
            checkpoint: { index: lastIndex, verifyHash: checkpointHash, chainMac },
            _storageData: await this.#storage.exportAll(),
        };
    }

    // ========== 校验（只读） ==========
    /**
     * 非破坏性校验：不碰内存状态、不碰 IndexedDB。
     * v1 的同名方法内部调 loadSave，会把数据库覆盖掉。
     */
    async verifySave(saveData, options = {}) {
        if (!_identities.has(this)) throw new Error('引擎未初始化（设备密钥未加载）');
        const ctx = { ...this.#verifyContext(), ...pickVerifyOverrides(options) };
        const result = await verifyChain(saveData, ctx);
        if (!result.valid) {
            return {
                valid: false,
                corruptedIndex: result.corruptedIndex,
                reason: result.reason,
                details: result.error,
            };
        }
        return { valid: true, details: `存档有效，共 ${saveData.records.length} 条记录` };
    }

    // ========== 加载 ==========
    async loadSave(saveData, options = {}) {
        return this.#enqueue(() => this.#applySave(saveData, options));
    }

    async #applySave(saveData, options) {
        if (!_identities.has(this)) throw new Error('引擎未初始化（设备密钥未加载）');

        // 先深拷贝再校验：校验通过之后调用方再改自己手里的对象，与引擎无关
        let candidate;
        try {
            candidate = deepCopy(saveData);
        } catch (error) {
            return { valid: false, error: `存档无法复制（含不可序列化内容）: ${error.message}` };
        }

        const ctx = { ...this.#verifyContext(), ...pickVerifyOverrides(options) };
        const verified = await verifyChain(candidate, ctx);
        if (!verified.valid) {
            return {
                valid: false,
                corruptedIndex: verified.corruptedIndex,
                reason: verified.reason,
                error: verified.error,
            };
        }

        // 反回滚：拿旧备份覆盖新进度
        const identity = this.#identity();
        const highWater = await loadHighWater(this.gameId, identity.key, identity.installId);
        const allowRollback = options.allowRollback ?? this.allowRollback;
        if (highWater && verified.computed.lastIndex < highWater.index && !allowRollback) {
            return {
                valid: false,
                reason: 'rollback',
                error: `检测到回滚：存档进度 ${verified.computed.lastIndex} 低于本机已记录的最高进度 ${highWater.index}`
                    + '；确认要接受请传 { allowRollback: true }',
            };
        }

        // 备份当前状态，应用失败时原样还原（v1 失败即把引擎清空）
        const backup = this.#snapshot();
        try {
            this.#records = candidate.records;
            this.#genesisHash = candidate.genesisHash;
            this.#currentHash = verified.computed.currentHash;
            this.#currentIndex = verified.computed.lastIndex;
            this.#lastHook = verified.computed.lastHook;

            if (candidate._storageData) {
                await this.#storage.importAll(candidate._storageData);
            } else {
                await this.#storage.clearAll();
                for (let i = 0; i < this.#records.length; i++) {
                    await this.#storage.writeRecord(this.#records[i], i, this.#recentStateHashes(i));
                }
            }

            const integrity = await this.#storage.verifyIntegrity();
            if (!integrity.valid) throw new Error(`存储完整性校验失败: ${describeFailures(integrity)}`);

            this.#initialized = true;
            this.#freezeState();
            await this.#advanceHighWater();
            return { valid: true, currentHook: this.#lastHook, lastIndex: this.#currentIndex };
        } catch (error) {
            this.#restore(backup);
            try {
                if (backup.initialized && backup.records.length > 0) await this.#rewriteStorage();
            } catch { /* 还原存储失败时至少内存是干净的 */ }
            return { valid: false, error: `应用存档失败，已还原原状态: ${error.message}` };
        }
    }

    async #rewriteStorage() {
        await this.#storage.clearAll();
        for (let i = 0; i < this.#records.length; i++) {
            await this.#storage.writeRecord(this.#records[i], i, this.#recentStateHashes(i));
        }
    }

    #snapshot() {
        return {
            records: this.#records,
            currentIndex: this.#currentIndex,
            currentHash: this.#currentHash,
            lastHook: this.#lastHook,
            genesisHash: this.#genesisHash,
            initialized: this.#initialized,
            frozenState: this.#frozenState,
        };
    }

    #restore(backup) {
        this.#records = backup.records;
        this.#currentIndex = backup.currentIndex;
        this.#currentHash = backup.currentHash;
        this.#lastHook = backup.lastHook;
        this.#genesisHash = backup.genesisHash;
        this.#initialized = backup.initialized;
        this.#frozenState = backup.frozenState;
    }

    #restoreEmpty() {
        this.#records = [];
        this.#currentIndex = -1;
        this.#currentHash = '';
        this.#lastHook = '';
        this.#genesisHash = '';
        this.#initialized = false;
        this.#frozenState = null;
    }

    async #advanceHighWater() {
        const identity = _identities.get(this);
        if (!identity || this.#currentIndex < 0) return;
        try {
            await saveHighWater(this.gameId, identity.key, identity.installId,
                this.#currentIndex, this.#currentHash);
        } catch { /* 高水位是纵深防御的一层，写失败不应阻断游戏 */ }
    }

    // ========== 只读快照 ==========
    getCurrentState() {
        if (!this.#initialized || this.#currentIndex < 0) return null;
        const lastRecord = this.#records[this.#currentIndex];
        return deepFreeze({
            index: this.#currentIndex,
            H: this.#currentHash,
            hook: this.#lastHook,
            lastOperation: lastRecord ? deepCopy(lastRecord.params.operation) : null,
        });
    }

    getHistory() {
        if (!this.#initialized) return Object.freeze([]);
        return deepFreeze(this.#records.map((r) => ({
            index: r.index, H: r.H,
            operation: deepCopy(r.params.operation),
            timestamp: r.params.timestamp,
        })));
    }

    #freezeState() {
        if (this.#records.length === 0) return;
        this.#frozenState = deepFreeze({
            index: this.#currentIndex, hash: this.#currentHash,
            hook: this.#lastHook, genesisHash: this.#genesisHash,
        });
    }

    // ========== 换设备 / 云存档迁移 ==========
    /**
     * 换一把新的设备密钥并用它重签当前链条。
     * 用于"同一台设备重置身份"或"把存档迁到新设备"（在新设备上导入后调用）。
     * 会在链上追加一条 REKEY 记录，迁移这件事本身也留痕。
     */
    async rekey() {
        return this.#enqueue(async () => {
            if (!this.#initialized) throw new Error('引擎未初始化');
            const previousInstallId = this.#installId;
            const { current } = await rotateIdentity(this.gameId);
            _identities.set(this, { key: current.key, installId: current.installId });
            this.#installId = current.installId;

            const oldRecords = this.#records;
            const rekeyOperation = {
                type: 'REKEY',
                previousInstallId,
                previousGenesisHash: this.#genesisHash,
                previousRecordCount: oldRecords.length,
            };

            await this.#createGenesis();
            const state = this.getCurrentState();
            const result = await this.#recordUnlocked(rekeyOperation, state.hook, {
                legacy: oldRecords.map((r) => ({ index: r.index, H: r.H, operation: r.params.operation, timestamp: r.params.timestamp })),
            });
            await this.#triggerSave();
            return { installId: current.installId, currentHook: result.currentHook, lastIndex: result.index };
        });
    }

    /** 已经在队列里时用的写入路径（rekey 内部调用，避免自死锁）。 */
    async #recordUnlocked(operation, prevHook, customData) {
        const index = this.#currentIndex + 1;
        const timestamp = Date.now();
        const nonce = randomHex(16);
        const runtimeContext = captureRuntimeContext();
        const prevHash = this.#currentHash;
        const prevHook_ = prevHook;

        const H = await this.#mac('record', {
            index, prevHash, operation, timestamp, nonce, runtimeContext, customData,
        });
        const hook = await this.#mac('hook', { H, nonce, timestamp });
        const dynamic = await this.#mac('dynamic', { H, nonce, index });
        const composite = await this.#mac('composite', { dynamic, prevHook: prevHook_, hook });

        const record = {
            index, H,
            params: { operation, prevHash, timestamp, nonce, runtimeContext, customData },
            verify: { dynamic, hook, composite },
            linkedVerifications: [
                ...(await this.#buildBackwardLinks(index, H)),
                ...this.#pendingLinks(index),
            ],
        };
        this.#records.push(record);
        await this.#fillForwardLinks(index, H);
        this.#currentIndex = index;
        this.#currentHash = H;
        this.#lastHook = hook;
        await this.#storage.writeRecord(record, index, this.#recentStateHashes(index));
        this.#freezeState();
        await this.#advanceHighWater();
        return { index, H, currentHook: hook, timestamp };
    }

    // ========== 反调试：取证，不是闸门 ==========
    /**
     * v1 的判定包含 navigator.plugins.length === 0（Firefox、多数移动浏览器普遍命中）
     * 与已废弃的 window.chrome.loadTimes，任一命中就把 debugDetected 永久置真，
     * 之后所有 recordOperation 抛错 —— 正常玩家直接玩不了。
     *
     * v2 改为：需要连续多次命中才认定；认定后默认只上报与留痕，不阻断游戏。
     * 想恢复 v1 的阻断行为请显式传 blockOnDebug: true。
     */
    #startDebugProbe() {
        if (!this.enableDebugProbe || this.#debugTimer) return;
        const tick = () => {
            if (this.#destroyed) return;
            const signals = detectDebugSignals();
            if (signals.suspicious) {
                this.#debugStrikes++;
                if (this.#debugStrikes >= 3 && !this.#debugDetected) {
                    this.#debugDetected = true;
                    if (this.onDebug) {
                        try { this.onDebug(signals); } catch (error) { console.warn('[EchoMarkLedger] onDebug 回调抛错:', error.message); }
                    }
                }
            } else if (this.#debugStrikes > 0) {
                this.#debugStrikes--;        // 衰减，避免偶发抖动累积成误判
            }
            this.#debugTimer = setTimeout(tick, 2000 + Math.floor(Math.random() * 1500));
        };
        this.#debugTimer = setTimeout(tick, 2000);
    }

    async #triggerSave() {
        if (!this.onSave) return;
        if (this.saveDebounceMs > 0) { this.#scheduleSave(); return; }
        await this.#doSave();
    }

    async #doSave() {
        if (!this.onSave || this.#destroyed) return;
        this.#savePending = false;
        try {
            await this.onSave(await this.exportSave());
        } catch (error) {
            console.error('[EchoMarkLedger] 自动保存失败:', error);
        }
    }

    /** 合并一串连续写入，只在末尾导出一次。 */
    #scheduleSave() {
        this.#savePending = true;
        if (this.#saveTimer) clearTimeout(this.#saveTimer);
        this.#saveTimer = setTimeout(() => {
            this.#saveTimer = null;
            this.#enqueue(() => this.#doSave()).catch(() => undefined);
        }, this.saveDebounceMs);
    }

    /**
     * 立即落盘尚未写出的存档。
     * 开启 saveDebounceMs 时，在关卡结束、页面 visibilitychange / pagehide
     * 等关键时刻调用，避免窗口期内丢进度。
     */
    async flush() {
        if (this.#saveTimer) { clearTimeout(this.#saveTimer); this.#saveTimer = null; }
        if (!this.#savePending && this.saveDebounceMs > 0) return;
        return this.#enqueue(() => this.#doSave());
    }

    #startAutoSave() {
        if (this.#autoSaveTimer) clearInterval(this.#autoSaveTimer);
        this.#autoSaveTimer = setInterval(() => {
            this.#enqueue(() => this.#doSave()).catch(() => undefined);
        }, this.autoSaveInterval);
    }

    stopAutoSave() {
        if (this.#autoSaveTimer) { clearInterval(this.#autoSaveTimer); this.#autoSaveTimer = null; }
    }

    /** v1 的 destroy 清不掉反调试的 setInterval（句柄没保存），这里全部清理。 */
    destroy() {
        this.#destroyed = true;
        this.stopAutoSave();
        if (this.#saveTimer) { clearTimeout(this.#saveTimer); this.#saveTimer = null; }
        if (this.#debugTimer) { clearTimeout(this.#debugTimer); this.#debugTimer = null; }
        try { this.#storage.close(); } catch { /* 已关闭 */ }
        this.#restoreEmpty();
        _identities.delete(this);
    }
}

function pickVerifyOverrides(options) {
    const overrides = {};
    if (options.requireStorageWitness !== undefined) overrides.requireStorageWitness = options.requireStorageWitness;
    if (options.validateOperation !== undefined) overrides.validateOperation = options.validateOperation;
    if (options.maxRecords !== undefined) overrides.maxRecords = options.maxRecords;
    if (options.clockToleranceMs !== undefined) overrides.clockToleranceMs = options.clockToleranceMs;
    return overrides;
}

export { EchoMarkLedger, verifyChain, SAVE_FORMAT_VERSION, ZERO_HASH };
