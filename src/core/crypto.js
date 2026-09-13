/**
 * 密码学核心
 * ============================================================================
 * 设计原则：
 * 账本主链一律使用 HMAC-SHA-256，密钥是设备绑定的不可导出 CryptoKey。
 *    这是 v2 与 v1 的根本区别：v1 全是公开可重算的 SHA-256，任何拿到源码的人
 *    都能离线造出一份"合法"存档；v2 没有密钥就算不出任何一个字段。
 */

const _globalCrypto = globalThis.crypto;
if (!_globalCrypto || !_globalCrypto.subtle) {
    throw new Error('EchoMarkLedger 需要 WebCrypto（crypto.subtle）；请在 HTTPS 或 localhost 下运行');
}

const _subtle = _globalCrypto.subtle;
const _digest = _subtle.digest.bind(_subtle);
const _sign = _subtle.sign.bind(_subtle);
const _generateKey = _subtle.generateKey.bind(_subtle);
const _getRandomValues = _globalCrypto.getRandomValues.bind(_globalCrypto);
const _TextEncoder = globalThis.TextEncoder;
const _encoder = new _TextEncoder();
const _encode = _encoder.encode.bind(_encoder);

const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));

function toHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let out = '';
    for (let i = 0; i < bytes.length; i++) out += HEX[bytes[i]];
    return out;
}

/** 真 SHA-256（WebCrypto）。用于函数指纹等不需要密钥的场合。 */
async function sha256(input) {
    return toHex(await _digest('SHA-256', _encode(String(input))));
}

/** HMAC-SHA-256。key 必须是 usages 含 'sign' 的 CryptoKey。 */
async function hmac(key, message) {
    return toHex(await _sign('HMAC', key, _encode(String(message))));
}

/** 生成一把设备绑定的不可导出 HMAC 密钥。extractable:false 是整套方案的基石。 */
async function generateLedgerKey() {
    return await _generateKey(
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,              // extractable: false —— 页面代码永远读不到密钥明文
        ['sign']
    );
}

function randomBytes(length) {
    const array = new Uint8Array(length);
    _getRandomValues(array);
    return array;
}

/** 随机 hex 串（v1 的 generateNonce）。 */
function randomHex(length = 16) {
    return toHex(randomBytes(length));
}

/**
 * 定长 hex 串的等时比较。
 * 纯前端里计时侧信道基本不可用（攻击者本来就能直接读内存），
 * 但代价近乎为零，且能避免"逐字节猜 MAC"这类低级可能性。
 */
function timingSafeEqualHex(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

/**
 * 非密码学快速哈希，128 bit。
 *
 * 只用于 QuadStorage 的槽位散射（把逻辑索引打散到 10 万槽位空间），
 *   那个场合只需要"分布均匀"，不需要抗碰撞。
 *
 * v1 把同样的算法命名为 sha256Sync 并用于 L3 函数指纹与 L5 状态快照，
 * 且把 128 bit 输出重复两遍伪装成 256 bit —— 指纹碰撞可构造，指纹校验可绕过。
 * v2 改名为 fastHash 以杜绝误用；所有安全用途已改为上面的真 sha256 / hmac。
 */
function fastHash(input) {
    const str = String(input);
    let h1 = 0x9e3779b1, h2 = 0x85ebca77, h3 = 0xc2b2ae3d, h4 = 0x27d4eb2f;
    for (let i = 0; i < str.length; i++) {
        const c = str.charCodeAt(i);
        h1 = Math.imul(h1 ^ c, 0x85ebca6b); h1 = (h1 << 13) | (h1 >>> 19);
        h2 = Math.imul(h2 ^ c, 0xc2b2ae35); h2 = (h2 << 17) | (h2 >>> 15);
        h3 = Math.imul(h3 ^ (c + i), 0x27d4eb2f); h3 = (h3 << 11) | (h3 >>> 21);
        h4 = Math.imul(h4 ^ (c * 31), 0x165667b1); h4 = (h4 << 7) | (h4 >>> 25);
        h1 ^= h4; h2 ^= h1; h3 ^= h2; h4 ^= h3;
    }
    h1 ^= h1 >>> 15; h2 ^= h2 >>> 13; h3 ^= h3 >>> 16; h4 ^= h4 >>> 11;
    const pad = (n) => (n >>> 0).toString(16).padStart(8, '0');
    return pad(h1) + pad(h2) + pad(h3) + pad(h4);
}

export {
    sha256, hmac, generateLedgerKey,
    randomBytes, randomHex, timingSafeEqualHex, fastHash, toHex,
};
