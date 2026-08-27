/**
 * 四表存储系统模块
 */
class QuadStorage {
    constructor(dbName = 'EchoMarkLedger', version = 1) {
        this.dbName = dbName;
        this.version = version;
        this.db = null;
        this.storeNames = ['storeA', 'storeAPrime', 'storeB', 'storeBPrime'];
        this.SLOT_SPACE = 100000;
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => { this.db = request.result; resolve(); };
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                ['storeA', 'storeAPrime', 'storeB', 'storeBPrime'].forEach(storeName => {
                    if (!db.objectStoreNames.contains(storeName)) {
                        const store = db.createObjectStore(storeName, { autoIncrement: true });
                        store.createIndex('recordIndex', 'recordIndex', { unique: false });
                        store.createIndex('slotPosition', 'slotPosition', { unique: false });
                    }
                });
            };
        });
    }

    async clearAll() {
        for (const storeName of this.storeNames) await this.clearStore(storeName);
    }

    async clearStore(storeName) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([storeName], 'readwrite');
            const request = transaction.objectStore(storeName).clear();
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    computeShuffleSeeds(stateHashes) {
        return {
            A: stateHashes[0] || 'genesis',
            APrime: stateHashes[1] || 'genesis_prime',
            B: stateHashes[2] || 'genesis_b',
            BPrime: stateHashes[3] || 'genesis_b_prime'
        };
    }

    async writeRecord(record, index, stateHashes) {
        const seeds = this.computeShuffleSeeds(stateHashes);
        // 固定位置空间
        const posA = computeSlotPosition(index, seeds.A, this.SLOT_SPACE);
        const posAPrime = computeSlotPosition(index, seeds.APrime, this.SLOT_SPACE);
        const posB = computeSlotPosition(index, seeds.B, this.SLOT_SPACE);
        const posBPrime = computeSlotPosition(index, seeds.BPrime, this.SLOT_SPACE);
        const recordHash = await sha256(safeStringify(record));
        const shadowMapping = {
            logicalIndex: index,
            posA, posAPrime, posB, posBPrime,
            recordHash,
            timestamp: Date.now()
        };

        // 主表 A
        await this.writeToStore('storeA', {
            recordIndex: index,
            slotPosition: posA,
            data: record,
            seed: seeds.A
        });

        // 备份表 A'
        await this.writeToStore('storeAPrime', {
            recordIndex: index,
            slotPosition: posAPrime,
            data: record,
            seed: seeds.APrime
        });

        // 影子表 B
        await this.writeToStore('storeB', {
            recordIndex: index,
            slotPosition: posB,
            mapping: shadowMapping,
            seed: seeds.B
        });

        // 备份影子表 B'
        await this.writeToStore('storeBPrime', {
            recordIndex: index,
            slotPosition: posBPrime,
            mapping: shadowMapping,
            seed: seeds.BPrime
        });
    }

    async writeToStore(storeName, data) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.add(data);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async readFromStoreByIndex(storeName, recordIndex) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([storeName], 'readonly');
            const store = transaction.objectStore(storeName);
            const index = store.index('recordIndex');
            const request = index.get(recordIndex);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async readRecord(index, stateHashes) {
        const seeds = this.computeShuffleSeeds(stateHashes);
        // 计算期望位置
        const expectedPosA = computeSlotPosition(index, seeds.A, this.SLOT_SPACE);
        const expectedPosAPrime = computeSlotPosition(index, seeds.APrime, this.SLOT_SPACE);
        const expectedPosB = computeSlotPosition(index, seeds.B, this.SLOT_SPACE);
        const expectedPosBPrime = computeSlotPosition(index, seeds.BPrime, this.SLOT_SPACE);
        // recordIndex 读取
        const recordA = await this.readFromStoreByIndex('storeA', index);
        const recordAPrime = await this.readFromStoreByIndex('storeAPrime', index);

        if (!recordA || !recordAPrime) {
            throw new Error(`记录 ${index} 不存在`);
        }
        // 验证 A 和 A' 内容一致
        if (!deepEqual(recordA.data, recordAPrime.data)) {
            throw new Error(`记录 ${index} 主表与备份表内容不一致`);
        }

        // 验证物理位置与种子一致
        if (recordA.slotPosition !== expectedPosA) {
            throw new Error(`记录 ${index} 主表位置不匹配: 存储=${recordA.slotPosition}, 期望=${expectedPosA}`);
        }
        if (recordAPrime.slotPosition !== expectedPosAPrime) {
            throw new Error(`记录 ${index} 备份表位置不匹配`);
        }

        // r&c 影子映射
        const mappingB = await this.readFromStoreByIndex('storeB', index);
        const mappingBPrime = await this.readFromStoreByIndex('storeBPrime', index);

        if (!mappingB || !mappingBPrime) {
            throw new Error(`记录 ${index} 的影子映射不存在`);
        }
        // 验证 B 和 B' 一致
        if (!deepEqual(mappingB.mapping, mappingBPrime.mapping)) {
            throw new Error(`记录 ${index} 影子表与备份影子表不一致`);
        }

        // 验证映射关系中的位置
        if (mappingB.mapping.posA !== expectedPosA ||
            mappingB.mapping.posAPrime !== expectedPosAPrime ||
            mappingB.mapping.posB !== expectedPosB ||
            mappingB.mapping.posBPrime !== expectedPosBPrime) {
            throw new Error(`记录 ${index} 影子映射位置不匹配`);
        }

        // 验证记录哈希
        const currentHash = await sha256(safeStringify(recordA.data));
        if (mappingB.mapping.recordHash !== currentHash) {
            throw new Error(`记录 ${index} 哈希校验失败`);
        }

        return {
            record: recordA.data,
            verified: true,
            positions: { A: expectedPosA, APrime: expectedPosAPrime, B: expectedPosB, BPrime: expectedPosBPrime }
        };
    }

    async getAllFromStore(storeName) {
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction([storeName], 'readonly');
            const request = transaction.objectStore(storeName).getAll();
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async verifyIntegrity() {
        const results = { valid: true, checks: [] };
        try {
            const recordsA = await this.getAllFromStore('storeA');
            const recordsAPrime = await this.getAllFromStore('storeAPrime');
            const recordsB = await this.getAllFromStore('storeB');
            const recordsBPrime = await this.getAllFromStore('storeBPrime');
            // 检查数量
            if (recordsA.length !== recordsAPrime.length ||
                recordsA.length !== recordsB.length ||
                recordsA.length !== recordsBPrime.length) {
                results.checks.push({
                    name: 'record_count_match', valid: false,
                    detail: `A=${recordsA.length}, A'=${recordsAPrime.length}, B=${recordsB.length}, B'=${recordsBPrime.length}`
                });
                results.valid = false;
                return results;
            }
            results.checks.push({ name: 'record_count_match', valid: true, detail: `共 ${recordsA.length} 条` });
            // 排序后比较内容
            const sortedA = recordsA.sort((a, b) => a.recordIndex - b.recordIndex);
            const sortedAPrime = recordsAPrime.sort((a, b) => a.recordIndex - b.recordIndex);
            const sortedB = recordsB.sort((a, b) => a.recordIndex - b.recordIndex);
            const sortedBPrime = recordsBPrime.sort((a, b) => a.recordIndex - b.recordIndex);

            let aMatch = true;
            for (let i = 0; i < sortedA.length; i++) {
                if (!deepEqual(sortedA[i].data, sortedAPrime[i].data)) {
                    aMatch = false;
                    results.checks.push({ name: 'a_aprime_content_match', valid: false, detail: `索引 ${sortedA[i].recordIndex}` });
                    break;
                }
            }
            if (aMatch) results.checks.push({ name: 'a_aprime_content_match', valid: true, detail: '内容一致' });
            else results.valid = false;

            let bMatch = true;
            for (let i = 0; i < sortedB.length; i++) {
                if (!deepEqual(sortedB[i].mapping, sortedBPrime[i].mapping)) {
                    bMatch = false;
                    results.checks.push({ name: 'b_bprime_mapping_match', valid: false, detail: `索引 ${sortedB[i].recordIndex}` });
                    break;
                }
            }
            if (bMatch) results.checks.push({ name: 'b_bprime_mapping_match', valid: true, detail: '映射一致' });
            else results.valid = false;

            // 验证 A-B 映射
            let mappingValid = true;
            for (let i = 0; i < sortedA.length; i++) {
                const recA = sortedA[i];
                const mapB = sortedB.find(m => m.recordIndex === recA.recordIndex);
                if (!mapB) {
                    mappingValid = false;
                    results.checks.push({ name: 'a_b_mapping_valid', valid: false, detail: `索引 ${recA.recordIndex} 无映射` });
                    break;
                }
                const expectedPosA = computeSlotPosition(recA.recordIndex, recA.seed, this.SLOT_SPACE);
                if (mapB.mapping.posA !== expectedPosA || mapB.mapping.posA !== recA.slotPosition) {
                    mappingValid = false;
                    results.checks.push({
                        name: 'a_b_mapping_valid', valid: false,
                        detail: `索引 ${recA.recordIndex}: A位置=${recA.slotPosition}, 期望=${expectedPosA}, B映射=${mapB.mapping.posA}`
                    });
                    break;
                }
            }
            if (mappingValid) results.checks.push({ name: 'a_b_mapping_valid', valid: true, detail: '映射关系正确' });
            else results.valid = false;

            // 检查洗牌多样性
            const aPositions = sortedA.map(r => r.slotPosition).join(',');
            const aPrimePositions = sortedAPrime.map(r => r.slotPosition).join(',');
            if (aPositions === aPrimePositions && recordsA.length > 0) {
                results.checks.push({ name: 'shuffle_diversity', valid: false, detail: 'A与A排列相同' });
                results.valid = false;
            } else {
                results.checks.push({ name: 'shuffle_diversity', valid: true, detail: '排列方式不同' });
            }

        } catch (error) {
            results.valid = false;
            results.checks.push({ name: 'integrity_check_error', valid: false, detail: error.message });
        }
        return results;
    }

    async exportAll() {
        return {
            storeA: await this.getAllFromStore('storeA'),
            storeAPrime: await this.getAllFromStore('storeAPrime'),
            storeB: await this.getAllFromStore('storeB'),
            storeBPrime: await this.getAllFromStore('storeBPrime')
        };
    }

    async importAll(data) {
        await this.clearAll();
        for (const item of data.storeA || []) await this.writeToStore('storeA', item);
        for (const item of data.storeAPrime || []) await this.writeToStore('storeAPrime', item);
        for (const item of data.storeB || []) await this.writeToStore('storeB', item);
        for (const item of data.storeBPrime || []) await this.writeToStore('storeBPrime', item);
    }

    close() {
        if (this.db) { this.db.close(); this.db = null; }
    }
}
export { QuadStorage };