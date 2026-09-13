/**
 * 设备密钥库 + 反回滚高水位
 * ============================================================================
 * 存放两样东西，都放在**独立于游戏数据库**的另一个 IndexedDB 里：
 *
 *   1) 设备身份：一把 extractable:false 的 HMAC 密钥 + 一个随机 installId。
 *      密钥明文页面代码读不到（浏览器不提供导出通道），所以：
 *        · 攻击者无法把框架源码拷到 Node 里离线造存档；
 *        · 攻击者无法把伪造存档分享给别人（别人的设备算出的 MAC 不一样）。
 *      同源页面内的代码可以从这里把 CryptoKey 句柄取出来，
 *      再调 crypto.subtle.sign 用它重签整条链。这一步挡不住
 *
 *   2) 高水位 {index, H}，用同一把密钥签名。
 *      用于识别"把旧备份贴回来"的回滚攻击。同时镜像一份到 localStorage：
 *      两处都要清掉才能绕过，而且攻击者得先知道它们存在。
 */

import { fastHash, generateLedgerKey, hmac, randomHex, timingSafeEqualHex } from './crypto.js';
import { canonicalFor } from './canonical.js';

const STORE = 'k';
const IDENTITY_KEY = 'identity';
const HIGHWATER_KEY = 'hw';

function originTag() {
    try {
        if (typeof location !== 'undefined' && location.origin) return location.origin;
    } catch { /* 沙箱化的 iframe 读 location 可能抛错 */ }
    return 'no-origin';
}

/** 库名不用显眼的名字，避免在 DevTools 的 Application 面板里一眼就被认出来。 */
function keystoreDbName(gameId) {
    return `emk_${fastHash(`${originTag()}:${gameId}`).slice(0, 16)}`;
}

function mirrorKeyName(gameId) {
    return `_emk_${fastHash(`hw:${originTag()}:${gameId}`).slice(0, 12)}`;
}

function openDb(gameId) {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(keystoreDbName(gameId), 1);
        request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

function idbGet(db, key) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction([STORE], 'readonly');
        const request = tx.objectStore(STORE).get(key);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

function idbPut(db, key, value) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction([STORE], 'readwrite');
        const request = tx.objectStore(STORE).put(value, key);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

function idbDelete(db, key) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction([STORE], 'readwrite');
        const request = tx.objectStore(STORE).delete(key);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

function readMirror(gameId) {
    try {
        if (typeof localStorage === 'undefined') return null;
        const raw = localStorage.getItem(mirrorKeyName(gameId));
        return raw ? JSON.parse(raw) : null;
    } catch { return null; }
}

function writeMirror(gameId, value) {
    try {
        if (typeof localStorage === 'undefined') return;
        localStorage.setItem(mirrorKeyName(gameId), JSON.stringify(value));
    } catch { /* 隐私模式 / 配额满：镜像只是冗余，失败不影响主流程 */ }
}

/**
 * 取出（或首次创建）本设备的账本身份。
 * @returns {Promise<{key: CryptoKey, installId: string, createdAt: number, fresh: boolean}>}
 */
async function loadIdentity(gameId) {
    const db = await openDb(gameId);
    try {
        const existing = await idbGet(db, IDENTITY_KEY);
        if (existing && existing.key && typeof existing.installId === 'string') {
            return { key: existing.key, installId: existing.installId, createdAt: existing.createdAt, fresh: false };
        }
        const identity = {
            key: await generateLedgerKey(),
            installId: randomHex(16),
            createdAt: Date.now(),
        };
        await idbPut(db, IDENTITY_KEY, identity);
        return { ...identity, fresh: true };
    } finally {
        db.close();
    }
}

/** 换设备 / 云存档迁移用：生成一把新密钥并替换设备身份，返回新旧两把。 */
async function rotateIdentity(gameId) {
    const previous = await loadIdentity(gameId);
    const db = await openDb(gameId);
    try {
        const identity = {
            key: await generateLedgerKey(),
            installId: randomHex(16),
            createdAt: Date.now(),
        };
        await idbPut(db, IDENTITY_KEY, identity);
        await idbDelete(db, HIGHWATER_KEY);
        writeMirror(gameId, null);
        return { previous, current: { ...identity, fresh: true } };
    } finally {
        db.close();
    }
}

async function signHighWater(key, gameId, installId, index, H) {
    return await hmac(key, canonicalFor('highwater', { gameId, installId, index, H }));
}

/**
 * 读高水位。IndexedDB 与 localStorage 两处取较高者，任一处被清掉仍保留防护。
 * MAC 校验失败的记录直接丢弃（当作没有高水位），不让伪造的水位卡死正常玩家。
 */
async function loadHighWater(gameId, key, installId) {
    const candidates = [];
    try {
        const db = await openDb(gameId);
        try {
            const stored = await idbGet(db, HIGHWATER_KEY);
            if (stored) candidates.push(stored);
        } finally { db.close(); }
    } catch { /* 库打不开时退化为只用镜像 */ }

    const mirrored = readMirror(gameId);
    if (mirrored) candidates.push(mirrored);

    let best = null;
    for (const candidate of candidates) {
        if (!candidate || typeof candidate.index !== 'number' || typeof candidate.H !== 'string') continue;
        const expected = await signHighWater(key, gameId, installId, candidate.index, candidate.H);
        if (!timingSafeEqualHex(expected, candidate.mac || '')) continue;
        if (!best || candidate.index > best.index) best = { index: candidate.index, H: candidate.H };
    }
    return best;
}

/** 只升不降地推进高水位。 */
async function saveHighWater(gameId, key, installId, index, H) {
    const current = await loadHighWater(gameId, key, installId);
    if (current && current.index >= index) return current;

    const record = { index, H, mac: await signHighWater(key, gameId, installId, index, H) };
    try {
        const db = await openDb(gameId);
        try { await idbPut(db, HIGHWATER_KEY, record); } finally { db.close(); }
    } catch { /* 主存失败仍写镜像 */ }
    writeMirror(gameId, record);
    return { index, H };
}

/** 测试与"重置存档"用：彻底抹掉设备身份与高水位。会导致现有存档永久失效。 */
async function destroyIdentity(gameId) {
    writeMirror(gameId, null);
    try {
        if (typeof localStorage !== 'undefined') localStorage.removeItem(mirrorKeyName(gameId));
    } catch { /* 忽略 */ }
    await new Promise((resolve) => {
        const request = indexedDB.deleteDatabase(keystoreDbName(gameId));
        request.onsuccess = request.onerror = request.onblocked = () => resolve();
    });
}

export {
    loadIdentity, rotateIdentity, loadHighWater, saveHighWater, destroyIdentity,
    keystoreDbName, mirrorKeyName,
};
