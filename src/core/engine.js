/**
 * 核心引擎类
 */
class EchoMarkLedger {
    constructor(options = {}) {
        this.gameId = options.gameId || 'default-game';
        this.version = options.version || '1.0.0';
        this.onSave = options.onSave || null;
        this.onLoad = options.onLoad || null;
        this.debugfunc = options.onDebug || null;
        this.records = [];
        this.currentIndex = -1;
        this.currentHash = '';
        this.lastHook = '';
        this.genesisHash = '';
        this.verificationWindow = 3;
        this.storage = new QuadStorage(`${this.gameId}_db`, 1);
        this.frozenState = null;
        this.debugDetected = false;
        this.autoSaveInterval = options.autoSaveInterval || 0;
        this.autoSaveTimer = null;
        this.initialized = false;
        this._setupMethodProtection();
    }
    _setupMethodProtection() {
        const critical = ['recordOperation', 'loadSave', 'exportSave', 'verifySave'];
        for (const name of critical) {
            const original = this[name];
            Object.defineProperty(this, name, {
                value: original,
                writable: false,      
                configurable: false,  
                enumerable: true
            });
        }
    }
    // ========== Hook 生成公式==========
    async _generateHook(H, nonce, timestamp, isGenesis = false) {
        if (isGenesis) {
            return await sha256(`${H}:hook:${nonce}`);
        }
        return await sha256(`${H}:hook:${nonce}:${timestamp}`);
    }

    // ========== 初始化 ==========
    async init(options = {}) {
        if (this.initialized) throw new Error('引擎已初始化');
        await this.storage.init();
        if (this.onLoad) {
            try {
                const existingSave = await this.onLoad();
                if (existingSave) {
                    const loadResult = await this.loadSave(existingSave);
                    if (loadResult.valid) {
                        this.initialized = true;
                        return { H: this.currentHash, currentHook: this.lastHook, restored: true, lastIndex: this.currentIndex };
                    }
                }
            } catch (e) {
                console.warn('加载已有存档失败:', e.message);
            }
        }
        const genesisNonce = generateNonce(32);
        const genesisTimestamp = Date.now();
        const runtimeContext = captureRuntimeContext();
        const genesisInput = serializeForHash({
            gameId: this.gameId, version: this.version,
            timestamp: genesisTimestamp, nonce: genesisNonce, runtimeContext
        });
        this.genesisHash = await sha256(genesisInput);
        this.currentHash = this.genesisHash;
        this.currentIndex = 0;
        // 创世 hook
        this.lastHook = await this._generateHook(this.genesisHash, genesisNonce, genesisTimestamp, true);
        const genesisRecord = {
            index: 0, H: this.genesisHash,
            params: {
                operation: { type: 'GENESIS', gameId: this.gameId },
                prevHash: '0'.repeat(64),
                timestamp: genesisTimestamp, nonce: genesisNonce, runtimeContext
            },
            verify: {
                dynamic: await sha256(`${this.genesisHash}:dynamic:${genesisNonce}`),
                hook: this.lastHook,
                composite: await sha256(`${await sha256(`${this.genesisHash}:dynamic:${genesisNonce}`)}:${'0'.repeat(64)}:${this.lastHook}`)
            },
            linkedVerifications: []
        };

        this.records = [genesisRecord];
        await this.storage.writeRecord(genesisRecord, 0, [this.genesisHash, this.genesisHash, this.genesisHash, this.genesisHash]);
        this._freezeState();
        this._startAntiDebug();
        if (this.autoSaveInterval > 0) this._startAutoSave();
        this.initialized = true;
        await this._triggerSave();

        return { H: this.genesisHash, currentHook: this.lastHook, restored: false };
    }

    // ========== 记录操作 ==========
    async recordOperation(operation, prevHook, customData = {}) {
        if (!this.initialized) throw new Error('引擎未初始化');
        if (this.debugDetected) throw new Error('检测到调试行为');
        if (!prevHook || prevHook !== this.lastHook) {
            throw new Error(`钩子验证失败: 期望 ${this.lastHook.slice(0, 16)}..., 收到 ${prevHook ? prevHook.slice(0, 16) + '...' : 'null'}`);
        }
        if (!operation || typeof operation !== 'object' || !operation.type) {
            throw new Error('操作对象必须包含 type 字段');
        }
        const newIndex = this.currentIndex + 1;
        const timestamp = Date.now();
        const nonce = generateNonce(16);
        const runtimeContext = captureRuntimeContext();
        const prevHash = this.currentHash;
        const hashInput = serializeForHash({
            prevHash, operation, timestamp, nonce, runtimeContext, customData
        });
        const newHash = await sha256(hashInput);
        const newHook = await this._generateHook(newHash, nonce, timestamp, false);
        const dynamicVerify = await sha256(`${newHash}:dynamic:${nonce}:${newIndex}`);
        const compositeVerify = await sha256(`${dynamicVerify}:${this.lastHook}:${newHook}`);
        const linkedVerifications = await this._buildLinkedVerifications(newIndex, newHash, prevHash);
        const record = {
            index: newIndex, H: newHash,
            params: { operation, prevHash, timestamp, nonce, runtimeContext, customData },
            verify: { dynamic: dynamicVerify, hook: newHook, composite: compositeVerify },
            linkedVerifications
        };
        await this._updateBackwardVerifications(newIndex, newHash);
        this.records.push(record);
        this.currentIndex = newIndex;
        this.currentHash = newHash;
        this.lastHook = newHook;
        const stateHashes = this._getRecentStateHashes(4);
        await this.storage.writeRecord(record, newIndex, stateHashes);
        this._freezeState();
        await this._triggerSave();
        return { index: newIndex, H: newHash, currentHook: newHook, timestamp };
    }

    // ========== 双向验证网络 ==========
    async _buildLinkedVerifications(index, currentHash, prevHash) {
        const verifications = [];
        const window = this.verificationWindow;

        for (let offset = -window; offset < 0; offset++) {
            const targetIndex = index + offset;
            if (targetIndex < 0) continue;
            const targetRecord = this.records[targetIndex];
            if (!targetRecord) continue;

            const salt = await this._deriveStableSalt(currentHash, targetRecord.H, offset);
            const V = await sha256(`${targetRecord.H}:${currentHash}:${salt}:${offset}`);
            verifications.push({ targetIndex, offset, salt, V });
        }

        for (let offset = 1; offset <= window; offset++) {
            verifications.push({
                targetIndex: index + offset,
                offset,
                salt: 'pending',
                V: 'pending'
            });
        }

        return verifications;
    }

    async _updateBackwardVerifications(currentIndex, currentHash) {
        const window = this.verificationWindow;

        for (let offset = 1; offset <= window; offset++) {
            const prevIndex = currentIndex - offset;
            if (prevIndex < 0) continue;

            const prevRecord = this.records[prevIndex];
            if (!prevRecord) continue;

            const pendingEntry = prevRecord.linkedVerifications.find(
                v => v.targetIndex === currentIndex && v.V === 'pending'
            );

            if (pendingEntry) {
                const salt = await this._deriveStableSalt(prevRecord.H, currentHash, offset);
                const V = await sha256(`${prevRecord.H}:${currentHash}:${salt}:${offset}`);
                pendingEntry.salt = salt;
                pendingEntry.V = V;
            }
        }
    }

    async _deriveStableSalt(hashA, hashB, offset) {
        return await sha256(`${hashA}:${hashB}:${offset}:v1`);
    }

    _getRecentStateHashes(count) {
        const hashes = [];
        for (let i = 0; i < count; i++) {
            const idx = this.currentIndex - i;
            if (idx >= 0 && this.records[idx]) hashes.push(this.records[idx].H);
            else if (this.genesisHash) hashes.push(this.genesisHash);
            else hashes.push('genesis');
        }
        return hashes;
    }

    // ========== 加载存档 ==========
    async loadSave(saveData) {
        if (!saveData) return { valid: false, error: '存档为空' };
        if (!saveData.version || !saveData.genesisHash || !Array.isArray(saveData.records)) {
            return { valid: false, error: '存档结构无效' };
        }

        // ========== 用临时变量验证 ==========
        let tempRecords = [];
        let tempGenesisHash = '';
        let tempCurrentHash = '';
        let tempCurrentIndex = -1;
        let tempLastHook = '';
        try {
            let computedHash = saveData.genesisHash;
            for (let i = 0; i < saveData.records.length; i++) {
                const record = saveData.records[i];

                if (record.index !== i) {
                    return { valid: false, corruptedIndex: i, error: `索引不连续: 期望 ${i}, 实际 ${record.index}` };
                }
                if (i === 0) {
                    // 验证创世记录
                    const expectedHash = await sha256(serializeForHash({
                        gameId: this.gameId, version: this.version,
                        timestamp: record.params.timestamp,
                        nonce: record.params.nonce,
                        runtimeContext: record.params.runtimeContext
                    }));
                    if (expectedHash !== record.H) {
                        return { valid: false, corruptedIndex: 0, error: '创世哈希验证失败' };
                    }

                    const expectedHook = await this._generateHook(record.H, record.params.nonce, record.params.timestamp, true);
                    if (expectedHook !== record.verify.hook) {
                        return { valid: false, corruptedIndex: 0, error: '创世 hook 不匹配' };
                    }

                    computedHash = record.H;
                } else {
                    // 验证非创世记录
                    const prevRecord = saveData.records[i - 1];
                    if (record.params.prevHash !== prevRecord.H) {
                        return { valid: false, corruptedIndex: i, error: '前序哈希不匹配' };
                    }
                    const hashInput = serializeForHash({
                        prevHash: record.params.prevHash,
                        operation: record.params.operation,
                        timestamp: record.params.timestamp,
                        nonce: record.params.nonce,
                        runtimeContext: record.params.runtimeContext,
                        customData: record.params.customData || {}
                    });
                    const expectedHash = await sha256(hashInput);
                    if (expectedHash !== record.H) {
                        return { valid: false, corruptedIndex: i, error: '状态哈希验证失败' };
                    }

                    const expectedHook = await this._generateHook(record.H, record.params.nonce, record.params.timestamp, false);
                    if (expectedHook !== record.verify.hook) {
                        return { valid: false, corruptedIndex: i, error: 'hook 不匹配' };
                    }

                    const expectedDynamic = await sha256(`${record.H}:dynamic:${record.params.nonce}:${i}`);
                    if (expectedDynamic !== record.verify.dynamic) {
                        return { valid: false, corruptedIndex: i, error: 'dynamic 验证失败' };
                    }

                    const prevHook = prevRecord.verify.hook;
                    const expectedComposite = await sha256(`${expectedDynamic}:${prevHook}:${expectedHook}`);
                    if (expectedComposite !== record.verify.composite) {
                        return { valid: false, corruptedIndex: i, error: 'composite 验证失败' };
                    }

                    computedHash = record.H;
                }

                // 验证双向网络
                if (record.linkedVerifications && record.linkedVerifications.length > 0) {
                    for (const verify of record.linkedVerifications) {
                        if (verify.V === 'pending') continue;
                        const targetRecord = saveData.records[verify.targetIndex];
                        if (!targetRecord) continue;
                        let expectedV;
                        if (verify.offset < 0) {
                            expectedV = await sha256(
                                `${targetRecord.H}:${record.H}:${verify.salt}:${verify.offset}`
                            );
                        } else {
                            expectedV = await sha256(
                                `${record.H}:${targetRecord.H}:${verify.salt}:${verify.offset}`
                            );
                        }

                        if (expectedV !== verify.V) {
                            return {
                                valid: false,
                                corruptedIndex: i,
                                error: `双向验证失败: 索引 ${i} 与 ${verify.targetIndex}`
                            };
                        }
                    }
                }
            }

            // 校验点验证
            if (saveData.checkpoint) {
                const cpRecord = saveData.records[saveData.checkpoint.index];
                if (cpRecord) {
                    const expectedCp = await sha256(`${cpRecord.H}:${saveData.genesisHash}:${saveData.checkpoint.index}`);
                    if (expectedCp !== saveData.checkpoint.verifyHash) {
                        return { valid: false, error: '校验点验证失败' };
                    }
                }
            }

            // ========== 赋值 ==========
            tempRecords = saveData.records;
            tempGenesisHash = saveData.genesisHash;
            tempCurrentHash = computedHash;
            tempCurrentIndex = saveData.records.length - 1;
            tempLastHook = saveData.records[tempCurrentIndex]?.verify?.hook || '';

        } catch (error) {
            return { valid: false, error: `验证异常: ${error.message}` };
        }

        // ========== 原子性应用状态 ==========
        try {
            this.records = tempRecords;
            this.genesisHash = tempGenesisHash;
            this.currentHash = tempCurrentHash;
            this.currentIndex = tempCurrentIndex;
            this.lastHook = tempLastHook;
            // 恢复
            if (saveData._storageData) {
                await this.storage.importAll(saveData._storageData);
                const integrity = await this.storage.verifyIntegrity();
                if (!integrity.valid) {
                    // 回滚
                    throw new Error(`存储完整性校验失败: ${integrity.checks.filter(c => !c.valid).map(c => c.detail).join(', ')}`);
                }
            } else {
                await this.storage.clearAll();
                for (let i = 0; i < this.records.length; i++) {
                    const stateHashes = this._getRecentStateHashesAtIndex(i);
                    await this.storage.writeRecord(this.records[i], i, stateHashes);
                }
            }

            this.initialized = true;
            this._freezeState();
            return { valid: true, currentHook: this.lastHook, lastIndex: this.currentIndex };

        } catch (error) {
            // ========== 回滚代偿 ==========
            this.records = [];
            this.currentIndex = -1;
            this.currentHash = '';
            this.genesisHash = '';
            this.lastHook = '';
            this.initialized = false;

            return { valid: false, error: `应用存档失败: ${error.message}` };
        }
    }

    _getRecentStateHashesAtIndex(index) {
        const hashes = [];
        for (let i = 0; i < 4; i++) {
            const idx = index - i;
            if (idx >= 0 && this.records[idx]) hashes.push(this.records[idx].H);
            else if (this.genesisHash) hashes.push(this.genesisHash);
            else hashes.push('genesis');
        }
        return hashes;
    }

    // ========== 导出存档 ==========
    async exportSave() {
        if (!this.initialized) throw new Error('引擎未初始化');
        const checkpointHash = await sha256(`${this.currentHash}:${this.genesisHash}:${this.currentIndex}`);
        const storageData = await this.storage.exportAll();

        return {
            version: this.version, genesisHash: this.genesisHash,
            records: this.records,
            metadata: {
                gameId: this.gameId,
                createTime: this.records[0]?.params?.timestamp || Date.now(),
                lastPlayTime: Date.now(), totalOperations: this.currentIndex
            },
            checkpoint: { index: this.currentIndex, verifyHash: checkpointHash },
            _storageData: storageData
        };
    }

    // ========== 验证存档 ==========
    async verifySave(saveData) {
        // 保存当前状态
        const snapshot = {
            records: this.records,
            currentIndex: this.currentIndex,
            currentHash: this.currentHash,
            lastHook: this.lastHook,
            genesisHash: this.genesisHash,
            initialized: this.initialized
        };

        try {
            const loadResult = await this.loadSave(saveData);
            if (!loadResult.valid) {
                return { valid: false, corruptedIndex: loadResult.corruptedIndex, details: loadResult.error };
            }
            return { valid: true, details: `存档有效，共 ${saveData.records.length} 条记录` };
        } finally {
            // 恢复状态
            this.records = snapshot.records;
            this.currentIndex = snapshot.currentIndex;
            this.currentHash = snapshot.currentHash;
            this.lastHook = snapshot.lastHook;
            this.genesisHash = snapshot.genesisHash;
            this.initialized = snapshot.initialized;
        }
    }

    getCurrentState() {
        if (!this.initialized || this.currentIndex < 0) return null;
        const lastRecord = this.records[this.currentIndex];
        return deepFreeze({
            index: this.currentIndex, H: this.currentHash,
            hook: this.lastHook, lastOperation: lastRecord ? { ...lastRecord.params.operation } : null
        });
    }

    getHistory() {
        if (!this.initialized) return [];
        return Object.freeze(this.records.map(r => ({
            index: r.index, H: r.H,
            operation: { ...r.params.operation }, timestamp: r.params.timestamp
        })));
    }

    _freezeState() {
        if (this.records.length > 0) {
            this.frozenState = deepFreeze({
                index: this.currentIndex, hash: this.currentHash,
                hook: this.lastHook, genesisHash: this.genesisHash
            });
        }
    }

    _startAntiDebug() {
        setInterval(() => {
            if (antiDebugDetection()) {
                this.debugDetected = true;
                if(this.debugfunc !== null){
                    this.debugfunc();
                }
            }
        }, 2000);
    }

    async _triggerSave() {
        if (this.onSave) {
            try { await this.onSave(await this.exportSave()); } catch (e) { console.error('自动保存失败:', e); }
        }
    }

    _startAutoSave() {
        if (this.autoSaveTimer) clearInterval(this.autoSaveTimer);
        this.autoSaveTimer = setInterval(async () => await this._triggerSave(), this.autoSaveInterval);
    }

    stopAutoSave() {
        if (this.autoSaveTimer) { clearInterval(this.autoSaveTimer); this.autoSaveTimer = null; }
    }

    destroy() {
        this.stopAutoSave();
        this.storage.close();
        this.records = [];
        this.currentIndex = -1;
        this.currentHash = '';
        this.lastHook = '';
        this.initialized = false;
    }
}
export { EchoMarkLedger };