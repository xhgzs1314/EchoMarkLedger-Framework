/**
 * 四表散射存储（QuadStorage）
 */

import { canonicalFor } from './canonical.js';
import { fastHash, timingSafeEqualHex } from './crypto.js';

const STORE_NAMES = Object.freeze(['storeA', 'storeAPrime', 'storeB', 'storeBPrime']);
const SLOT_SPACE = 100000;

/** 槽位散射。只要求分布均匀，不要求抗碰撞，故使用 fastHash。 */
function computeSlotPosition(logicalIndex, seed, slotSpace = SLOT_SPACE) {
    return parseInt(fastHash(`${seed}:${logicalIndex}:slot`).slice(0, 12), 16) % slotSpace;
}

/**
 * 由最近若干条状态哈希派生四个互不相同的散射种子。
 * 域标签（:A / :A' / :B / :B'）保证即使四个输入哈希完全相同，
 * 四个种子——从而四个槽位——依然不同。
 */
function computeShuffleSeeds(stateHashes = []) {
    const pick = (i) => stateHashes[i] || stateHashes[0] || 'genesis';
    return {
        A: fastHash(`${pick(0)}:A`),
        APrime: fastHash(`${pick(1)}:A'`),
        B: fastHash(`${pick(2)}:B`),
        BPrime: fastHash(`${pick(3)}:B'`),
    };
}

/**
 * 记录内核：记录中创建后就不再变动的部分。
 *
 * 刻意排除 linkedVerifications —— 双向验证网络的前向链接是以 pending 占位、
 * 由后续记录回填的，所以它是记录里唯一可变的字段。四表存的是内核，
 * 从而"库里的副本"与"链条"永远可以逐字节比对；交叉链接本身由链条校验器
 * 用设备密钥单独校验，不依赖四表。
 */
function recordCore(record) {
    return {
        index: record.index,
        H: record.H,
        params: record.params,
        verify: record.verify,
    };
}

const ROW_PURPOSE = Object.freeze({
    storeA: 'row-a',
    storeAPrime: 'row-a-prime',
    storeB: 'row-b',
    storeBPrime: 'row-b-prime',
});

/** 参与 MAC 的字段（不含 mac 本身）。 */
function rowPayload(storeName, row) {
    if (storeName === 'storeA' || storeName === 'storeAPrime') {
        return { recordIndex: row.recordIndex, slotPosition: row.slotPosition, seed: row.seed, data: row.data };
    }
    return { recordIndex: row.recordIndex, slotPosition: row.slotPosition, seed: row.seed, mapping: row.mapping };
}

async function signRow(macFn, storeName, row) {
    return await macFn(canonicalFor(ROW_PURPOSE[storeName], rowPayload(storeName, row)));
}

function deepEqual(a, b) {
    if (a === b) return true;
    if (a === null || b === null || a === undefined || b === undefined) return false;
    if (typeof a !== typeof b) return false;
    if (typeof a !== 'object') return false;
    if (Array.isArray(a) !== Array.isArray(b)) return false;
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    if (keysA.length !== keysB.length) return false;
    for (const key of keysA) {
        if (!Object.prototype.hasOwnProperty.call(b, key)) return false;
        if (!deepEqual(a[key], b[key])) return false;
    }
    return true;
}

class QuadStorage {
    /**
     * @param {string} dbName
     * @param {number} version
     * @param {Object} options
     * @param {(message: string) => Promise<string>} options.macFn
     *        行 MAC 的签名函数，由引擎注入。存储层拿不到密钥本体，
     *        只拿到一个"能签名"的能力，密钥始终留在引擎的私有作用域里。
     */
    constructor(dbName = 'EchoMarkLedger', version = 1, options = {}) {
        this.dbName = dbName;
        this.version = version;
        this.db = null;
        this.storeNames = STORE_NAMES;
        this.SLOT_SPACE = options.slotSpace || SLOT_SPACE;
        this._macFn = options.macFn || null;
    }

    setMacFn(macFn) { this._macFn = macFn; }

    _mac() {
        if (!this._macFn) throw new Error('QuadStorage 未注入 macFn，无法签发行 MAC');
        return this._macFn;
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);
            request.onerror = () => reject(request.error);
            request.onsuccess = () => { this.db = request.result; resolve(); };
            request.onupgradeneeded = () => {
                const db = request.result;
                for (const storeName of STORE_NAMES) {
                    if (db.objectStoreNames.contains(storeName)) continue;
                    const store = db.createObjectStore(storeName, { autoIncrement: true });
                    // unique：同一个逻辑索引只能有一行，杜绝重复索引注入
                    store.createIndex('recordIndex', 'recordIndex', { unique: true });
                    store.createIndex('slotPosition', 'slotPosition', { unique: false });
                }
            };
        });
    }

    _tx(mode, stores = STORE_NAMES) {
        if (!this.db) throw new Error('QuadStorage 未初始化');
        return this.db.transaction(stores, mode);
    }

    async clearAll() {
        return new Promise((resolve, reject) => {
            const tx = this._tx('readwrite');
            for (const storeName of STORE_NAMES) tx.objectStore(storeName).clear();
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error);
        });
    }

    async clearStore(storeName) {
        return new Promise((resolve, reject) => {
            const tx = this._tx('readwrite', [storeName]);
            tx.objectStore(storeName).clear();
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error);
        });
    }

    computeShuffleSeeds(stateHashes) { return computeShuffleSeeds(stateHashes); }

    /** 构建一条记录对应的四行（含 MAC），不落库。导出/校验共用同一套构建逻辑。 */
    async buildRows(record, index, stateHashes) {
        const macFn = this._mac();
        const core = recordCore(record);
        const seeds = computeShuffleSeeds(stateHashes);
        const posA = computeSlotPosition(index, seeds.A, this.SLOT_SPACE);
        const posAPrime = computeSlotPosition(index, seeds.APrime, this.SLOT_SPACE);
        const posB = computeSlotPosition(index, seeds.B, this.SLOT_SPACE);
        const posBPrime = computeSlotPosition(index, seeds.BPrime, this.SLOT_SPACE);

        const mapping = {
            logicalIndex: index,
            posA, posAPrime, posB, posBPrime,
            recordMac: await macFn(canonicalFor('storage-record', core)),
        };

        const rows = {
            storeA: { recordIndex: index, slotPosition: posA, seed: seeds.A, data: core },
            storeAPrime: { recordIndex: index, slotPosition: posAPrime, seed: seeds.APrime, data: core },
            storeB: { recordIndex: index, slotPosition: posB, seed: seeds.B, mapping },
            storeBPrime: { recordIndex: index, slotPosition: posBPrime, seed: seeds.BPrime, mapping },
        };
        for (const storeName of STORE_NAMES) {
            rows[storeName].mac = await signRow(macFn, storeName, rows[storeName]);
        }
        return rows;
    }

    /** 四表写入在同一个事务里完成：要么四行全在，要么一行都不在。 */
    async writeRecord(record, index, stateHashes) {
        const rows = await this.buildRows(record, index, stateHashes);
        return new Promise((resolve, reject) => {
            const tx = this._tx('readwrite');
            for (const storeName of STORE_NAMES) tx.objectStore(storeName).add(rows[storeName]);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error || new Error('四表写入事务被中止'));
        });
    }

    async writeToStore(storeName, data) {
        return new Promise((resolve, reject) => {
            const tx = this._tx('readwrite', [storeName]);
            const request = tx.objectStore(storeName).add(data);
            request.onsuccess = () => resolve(request.result);
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error);
        });
    }

    async readFromStoreByIndex(storeName, recordIndex) {
        return new Promise((resolve, reject) => {
            const tx = this._tx('readonly', [storeName]);
            const request = tx.objectStore(storeName).index('recordIndex').get(recordIndex);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async getAllFromStore(storeName) {
        return new Promise((resolve, reject) => {
            const tx = this._tx('readonly', [storeName]);
            const request = tx.objectStore(storeName).getAll();
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async readRecord(index, stateHashes) {
        const macFn = this._mac();
        const seeds = computeShuffleSeeds(stateHashes);
        const expected = {
            posA: computeSlotPosition(index, seeds.A, this.SLOT_SPACE),
            posAPrime: computeSlotPosition(index, seeds.APrime, this.SLOT_SPACE),
            posB: computeSlotPosition(index, seeds.B, this.SLOT_SPACE),
            posBPrime: computeSlotPosition(index, seeds.BPrime, this.SLOT_SPACE),
        };

        const rows = {};
        for (const storeName of STORE_NAMES) {
            rows[storeName] = await this.readFromStoreByIndex(storeName, index);
            if (!rows[storeName]) throw new Error(`记录 ${index} 在 ${storeName} 中不存在`);
        }

        for (const storeName of STORE_NAMES) {
            const row = rows[storeName];
            const mac = await signRow(macFn, storeName, row);
            if (!timingSafeEqualHex(mac, row.mac || '')) {
                throw new Error(`记录 ${index} 在 ${storeName} 的行 MAC 校验失败`);
            }
        }

        if (!deepEqual(rows.storeA.data, rows.storeAPrime.data)) {
            throw new Error(`记录 ${index} 主表与备份表内容不一致`);
        }
        if (!deepEqual(rows.storeB.mapping, rows.storeBPrime.mapping)) {
            throw new Error(`记录 ${index} 影子表与备份影子表不一致`);
        }
        if (rows.storeA.slotPosition !== expected.posA) {
            throw new Error(`记录 ${index} 主表位置不匹配: 存储=${rows.storeA.slotPosition}, 期望=${expected.posA}`);
        }
        if (rows.storeAPrime.slotPosition !== expected.posAPrime) {
            throw new Error(`记录 ${index} 备份表位置不匹配`);
        }

        const mapping = rows.storeB.mapping;
        if (mapping.posA !== expected.posA || mapping.posAPrime !== expected.posAPrime ||
            mapping.posB !== expected.posB || mapping.posBPrime !== expected.posBPrime) {
            throw new Error(`记录 ${index} 影子映射位置不匹配`);
        }

        const recordMac = await macFn(canonicalFor('storage-record', rows.storeA.data));
        if (!timingSafeEqualHex(recordMac, mapping.recordMac || '')) {
            throw new Error(`记录 ${index} 内容 MAC 校验失败`);
        }

        return { record: rows.storeA.data, verified: true, positions: expected };
    }

    async verifyIntegrity() {
        const snapshot = await this.exportAll();
        return await verifyStorageSnapshot(snapshot, this._mac(), this.SLOT_SPACE);
    }

    async exportAll() {
        const out = {};
        for (const storeName of STORE_NAMES) out[storeName] = await this.getAllFromStore(storeName);
        return out;
    }

    /** 导入同样在单个事务里完成。 */
    async importAll(data) {
        return new Promise((resolve, reject) => {
            const tx = this._tx('readwrite');
            for (const storeName of STORE_NAMES) {
                const store = tx.objectStore(storeName);
                store.clear();
                for (const row of data?.[storeName] || []) store.add(row);
            }
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error || new Error('四表导入事务被中止'));
        });
    }

    close() {
        if (this.db) { this.db.close(); this.db = null; }
    }
}

/**
 * 校验一份四表快照的自洽性（不访问数据库，纯函数）。
 * v1 的 shuffle_diversity 检查在此被替换为"四个种子必须互不相同"——
 * 那才是当初想表达的不变量，而且不会在只有一条记录时必然失败。
 */
async function verifyStorageSnapshot(snapshot, macFn, slotSpace = SLOT_SPACE) {
    const results = { valid: true, checks: [] };
    const fail = (name, detail) => {
        results.checks.push({ name, valid: false, detail });
        results.valid = false;
        return results;
    };
    const pass = (name, detail) => results.checks.push({ name, valid: true, detail });

    try {
        const tables = {};
        for (const storeName of STORE_NAMES) {
            if (!Array.isArray(snapshot?.[storeName])) return fail('snapshot_shape', `${storeName} 缺失或不是数组`);
            tables[storeName] = [...snapshot[storeName]].sort((a, b) => a.recordIndex - b.recordIndex);
        }

        const count = tables.storeA.length;
        for (const storeName of STORE_NAMES) {
            if (tables[storeName].length !== count) {
                return fail('record_count_match', STORE_NAMES
                    .map((n) => `${n}=${tables[n].length}`).join(', '));
            }
        }
        pass('record_count_match', `共 ${count} 条`);

        // 索引集合必须恰好是 0..count-1，无重复、无空洞
        for (const storeName of STORE_NAMES) {
            for (let i = 0; i < count; i++) {
                if (tables[storeName][i].recordIndex !== i) {
                    return fail('index_continuity', `${storeName} 第 ${i} 行的 recordIndex=${tables[storeName][i].recordIndex}`);
                }
            }
        }
        pass('index_continuity', '索引连续无重复');

        for (let i = 0; i < count; i++) {
            for (const storeName of STORE_NAMES) {
                const row = tables[storeName][i];
                const mac = await signRow(macFn, storeName, row);
                if (!timingSafeEqualHex(mac, row.mac || '')) {
                    return fail('row_mac_valid', `索引 ${i} 在 ${storeName} 的行 MAC 不匹配`);
                }
                const expectedSlot = computeSlotPosition(row.recordIndex, row.seed, slotSpace);
                if (row.slotPosition !== expectedSlot) {
                    return fail('slot_position_valid', `索引 ${i} 在 ${storeName}: 槽位=${row.slotPosition}, 期望=${expectedSlot}`);
                }
            }

            const a = tables.storeA[i], aPrime = tables.storeAPrime[i];
            const b = tables.storeB[i], bPrime = tables.storeBPrime[i];

            if (!deepEqual(a.data, aPrime.data)) return fail('a_aprime_content_match', `索引 ${i}`);
            if (!deepEqual(b.mapping, bPrime.mapping)) return fail('b_bprime_mapping_match', `索引 ${i}`);

            const seeds = [a.seed, aPrime.seed, b.seed, bPrime.seed];
            if (new Set(seeds).size !== 4) return fail('seed_diversity', `索引 ${i} 的四个散射种子并非互不相同`);

            const mapping = b.mapping;
            if (mapping.posA !== a.slotPosition || mapping.posAPrime !== aPrime.slotPosition ||
                mapping.posB !== b.slotPosition || mapping.posBPrime !== bPrime.slotPosition) {
                return fail('a_b_mapping_valid', `索引 ${i} 影子映射与实际槽位不一致`);
            }

            const recordMac = await macFn(canonicalFor('storage-record', a.data));
            if (!timingSafeEqualHex(recordMac, mapping.recordMac || '')) {
                return fail('record_mac_valid', `索引 ${i} 内容 MAC 不匹配`);
            }
        }
        pass('row_mac_valid', '全部行 MAC 有效');
        pass('slot_position_valid', '全部槽位与种子一致');
        pass('a_aprime_content_match', '内容一致');
        pass('b_bprime_mapping_match', '映射一致');
        pass('seed_diversity', '四个种子互不相同');
        pass('a_b_mapping_valid', '映射关系正确');
        pass('record_mac_valid', '内容 MAC 有效');
    } catch (error) {
        return fail('integrity_check_error', error.message);
    }
    return results;
}

/**
 * 交叉校验四表快照与记录链是否指向同一份存档。
 * v1 完全没有这一步：_storageData 与 records 互不校验，删掉这个 JSON 键
 * 就会走 loadSave 的 else 分支重建，于是四表对存档完整性的贡献是零。
 */
async function verifyStorageWitness(snapshot, records, macFn, slotSpace = SLOT_SPACE) {
    const selfCheck = await verifyStorageSnapshot(snapshot, macFn, slotSpace);
    if (!selfCheck.valid) return { valid: false, error: `四表快照自检失败: ${describeFailures(selfCheck)}` };

    if (snapshot.storeA.length !== records.length) {
        return { valid: false, error: `四表条数 ${snapshot.storeA.length} 与记录链长度 ${records.length} 不一致` };
    }

    const byIndex = new Map(snapshot.storeA.map((row) => [row.recordIndex, row]));
    for (let i = 0; i < records.length; i++) {
        const row = byIndex.get(i);
        if (!row) return { valid: false, corruptedIndex: i, error: `四表中缺少索引 ${i}` };
        const rowMac = await macFn(canonicalFor('storage-record', row.data));
        const chainMac = await macFn(canonicalFor('storage-record', recordCore(records[i])));
        if (!timingSafeEqualHex(rowMac, chainMac)) {
            return { valid: false, corruptedIndex: i, error: `索引 ${i} 的四表内容与记录链不一致` };
        }
    }
    return { valid: true };
}

function describeFailures(result) {
    return result.checks.filter((c) => !c.valid).map((c) => `${c.name}: ${c.detail}`).join('; ');
}

export {
    QuadStorage, computeSlotPosition, computeShuffleSeeds, recordCore,
    verifyStorageSnapshot, verifyStorageWitness, describeFailures,
    STORE_NAMES, SLOT_SPACE, deepEqual,
};
