/**
 * 规范化编码（Canonical Encoding）
 * ============================================================================
 *
 * 本模块的编码是单射的：每个值都带类型标签，每个变长值都带精确长度前缀
 *
 *   null        n
 *   undefined   u
 *   false/true  b0 / b1
 *   number      d<len>:<repr>
 *   string      s<len>:<原文>          len = UTF-16 code unit 数
 *   array       a<count>:<元素编码…>
 *   object      o<count>:<键编码><值编码>…   键按 code unit 序排序
 *
 * 不接受 Date / Map / Set / 函数 / Symbol / BigInt：v1 会静默 String(obj) 兜底，
 * 把 {} 和 [object Object] 混为一谈，这里改为显式抛错，让问题在写入期暴露
 */

const CANONICAL_VERSION = 'c2';

// 恶意存档可以用深嵌套在加载期打爆调用栈，这里设硬上限
const MAX_DEPTH = 64;
const MAX_NODES = 100000;

class CanonicalEncodeError extends Error {
    constructor(message, path) {
        super(path ? `${message}（路径 ${path}）` : message);
        this.name = 'CanonicalEncodeError';
        this.path = path;
    }
}

function encodeValue(value, depth, path, counter) {
    if (++counter.n > MAX_NODES) {
        throw new CanonicalEncodeError(`节点数超过上限 ${MAX_NODES}`, path);
    }
    if (depth > MAX_DEPTH) {
        throw new CanonicalEncodeError(`嵌套深度超过上限 ${MAX_DEPTH}`, path);
    }

    if (value === null) return 'n';
    if (value === undefined) return 'u';

    const type = typeof value;

    if (type === 'boolean') return value ? 'b1' : 'b0';

    if (type === 'number') {
        if (!Number.isFinite(value)) {
            throw new CanonicalEncodeError(`数值必须有限，收到 ${String(value)}`, path);
        }
        // -0 与 0 在 JSON 往返后不可区分，统一归一化，避免"编码不同、语义相同"
        const repr = String(value === 0 ? 0 : value);
        return `d${repr.length}:${repr}`;
    }

    if (type === 'string') return `s${value.length}:${value}`;

    if (type === 'bigint' || type === 'symbol' || type === 'function') {
        throw new CanonicalEncodeError(`不支持的类型 ${type}`, path);
    }

    if (Array.isArray(value)) {
        let out = `a${value.length}:`;
        for (let i = 0; i < value.length; i++) {
            out += encodeValue(value[i], depth + 1, `${path}[${i}]`, counter);
        }
        return out;
    }

    if (type === 'object') {
        const proto = Object.getPrototypeOf(value);
        if (proto !== Object.prototype && proto !== null) {
            throw new CanonicalEncodeError(
                `只接受纯对象，收到 ${value.constructor?.name || '未知类型'}`, path);
        }
        // 只取自有可枚举键；排序保证同一对象总是得到同一编码
        const keys = Object.keys(value).sort();
        let out = `o${keys.length}:`;
        for (const key of keys) {
            out += `s${key.length}:${key}`;
            out += encodeValue(value[key], depth + 1, `${path}.${key}`, counter);
        }
        return out;
    }

    throw new CanonicalEncodeError(`不支持的类型 ${type}`, path);
}

/**
 * 把任意 JSON 可表达的值编码为唯一的字符串。
 * 相同语义必然得到相同编码；不同语义必然得到不同编码。
 */
function canonical(value) {
    return `${CANONICAL_VERSION}|${encodeValue(value, 0, '$', { n: 0 })}`;
}

/**
 * 带用途标签的编码。用于 HMAC 的域分隔：
 * 让"记录哈希""钩子""冗余校验值"各自处在互不相交的消息空间里，
 * 避免某个用途下的合法 MAC 被搬到另一个用途下当合法值使用。
 */
function canonicalFor(purpose, value) {
    return `EMK2:${purpose}:${canonical(value)}`;
}

export { canonical, canonicalFor, CanonicalEncodeError, CANONICAL_VERSION, MAX_DEPTH, MAX_NODES };
