/**
 * 规范化编码的单射性。
 * v1 的 serializeForHash 在这些用例上全部产生碰撞 —— 不同语义、同一个哈希输入。
 */
import { canonical, canonicalFor, CanonicalEncodeError } from '../../src/core/canonical.js';

export const name = 'canonical：编码单射性（v1 的全部碰撞对必须消失）';

export default async function (t) {
    // v1 实测过的碰撞对
    const collisions = [
        [{ a: '1;b:2' }, { a: '1', b: '2' }, '分隔符注入'],
        [{ nested: { x: 1 } }, { 'nested:x': 1 }, '嵌套与扁平键'],
        [{ coins: 1 }, { coins: '1' }, '数字与字符串'],
        [{ f: ['a', 'b'] }, { f: 'a|b' }, '数组与竖线拼接'],
        [{ aNick: 'Bob;coins:9999' }, { aNick: 'Bob', coins: 9999 }, 'v1 可实战利用的那一对'],
        [{ a: '' }, { a: null }, '空串与 null'],
        [{ a: false }, { a: 0 }, 'false 与 0'],
        [{ a: 'b:c' }, { a: { b: 'c' } }, '冒号注入构造嵌套'],
    ];

    for (const [left, right, label] of collisions) {
        t.neq(canonical(left), canonical(right), `不再碰撞: ${label}`);
    }

    // 相同语义必须稳定得到相同编码（键序无关）
    t.eq(canonical({ a: 1, b: 2 }), canonical({ b: 2, a: 1 }), '键顺序不影响编码');
    t.eq(canonical([1, 2, 3]), canonical([1, 2, 3]), '数组编码稳定');
    t.eq(canonical({ x: { y: [1, { z: 'q' }] } }), canonical({ x: { y: [1, { z: 'q' }] } }), '深层结构编码稳定');
    t.eq(canonical({ a: -0 }), canonical({ a: 0 }), '-0 与 0 归一化（JSON 往返后不可区分）');

    // 用途标签做域分隔：同样的载荷在不同用途下消息不同
    t.neq(canonicalFor('record', { a: 1 }), canonicalFor('hook', { a: 1 }), '不同用途的消息空间互不相交');

    // 随机模糊测试：单射性
    const seen = new Map();
    let cases = 0;
    for (let i = 0; i < 4000; i++) {
        const value = randomValue(0);
        const encoded = canonical(value);
        const json = stableJson(value);
        if (seen.has(encoded)) {
            t.eq(seen.get(encoded), json, `模糊测试第 ${i} 例：相同编码必须来自相同语义`);
        } else {
            seen.set(encoded, json);
        }
        cases++;
    }
    t.ok(cases === 4000, `模糊测试跑完 ${cases} 例，未发现编码碰撞`);

    // 显式拒绝会被 v1 静默 String() 兜底的类型
    let rejected = 0;
    for (const bad of [new Date(), new Map(), new Set(), () => {}, 10n, Symbol('s'), NaN, Infinity]) {
        try { canonical({ v: bad }); } catch (error) {
            if (error instanceof CanonicalEncodeError) rejected++;
        }
    }
    t.eq(rejected, 8, '不可靠的类型全部显式拒绝，而不是静默变成 [object Object]');

    // 深度与节点数上限（防恶意存档在加载期打爆栈）
    let deep = { v: 1 };
    for (let i = 0; i < 200; i++) deep = { v: deep };
    await t.rejects(Promise.resolve().then(() => canonical(deep)), '嵌套深度', '超深嵌套被拒绝');
}

const KEYS = ['a', 'b', 'c', 'a:b', 'a;b', '1', 'x|y', ''];
const SCALARS = [0, 1, -1, 1.5, '', '0', '1', 'a', 'a;b', 'a:b', 'a|b', true, false, null];

function randomValue(depth) {
    const roll = Math.random();
    if (depth > 3 || roll < 0.5) return SCALARS[Math.floor(Math.random() * SCALARS.length)];
    if (roll < 0.75) {
        const n = Math.floor(Math.random() * 3);
        return Array.from({ length: n }, () => randomValue(depth + 1));
    }
    const n = Math.floor(Math.random() * 3) + 1;
    const out = {};
    for (let i = 0; i < n; i++) out[KEYS[Math.floor(Math.random() * KEYS.length)]] = randomValue(depth + 1);
    return out;
}

/** 带类型信息的稳定 JSON，用来判断"语义是否相同"。 */
function stableJson(value) {
    if (value === null) return 'null';
    if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
    if (typeof value === 'object') {
        return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableJson(value[k])}`).join(',')}}`;
    }
    return `${typeof value}:${JSON.stringify(value)}`;
}
