/** 极简测试骨架 */

let currentSuite = null;
const results = [];

export function makeContext(suiteName) {
    currentSuite = suiteName;
    const checks = [];
    return {
        ok(condition, message) {
            checks.push({ pass: !!condition, message });
            if (!condition) throw new AssertionError(`${message} —— 断言为假`);
        },
        eq(actual, expected, message) {
            const pass = Object.is(actual, expected);
            checks.push({ pass, message });
            if (!pass) throw new AssertionError(`${message}\n      期望: ${format(expected)}\n      实际: ${format(actual)}`);
        },
        neq(actual, unexpected, message) {
            const pass = !Object.is(actual, unexpected);
            checks.push({ pass, message });
            if (!pass) throw new AssertionError(`${message}\n      不应等于: ${format(unexpected)}`);
        },
        /** 校验结果应为无效，且原因里包含某个关键字。 */
        invalid(result, needle, message) {
            const detail = result?.details ?? result?.error ?? '';
            const pass = result && result.valid === false && String(detail).includes(needle);
            checks.push({ pass, message });
            if (!pass) {
                throw new AssertionError(
                    `${message}\n      期望无效且原因含「${needle}」\n      实际: ${format(result)}`);
            }
        },
        /**
         * 期望抛错或拒绝。
         * 接受 Promise 或函数——传函数才能捕获"同步抛出"的情况
         * （例如安全代理在方法被调用时立刻 throw，此时还没有 Promise 可 await）。
         */
        async rejects(target, needle, message) {
            let threw = null;
            try {
                await (typeof target === 'function' ? target() : target);
            } catch (error) { threw = error; }
            const pass = threw !== null && (!needle || String(threw.message).includes(needle));
            checks.push({ pass, message });
            if (!pass) {
                throw new AssertionError(
                    `${message}\n      期望抛错${needle ? `且含「${needle}」` : ''}\n      实际: ${threw ? threw.message : '未抛错'}`);
            }
        },
        note(message) { checks.push({ pass: true, message, note: true }); },
        checks,
    };
}

export class AssertionError extends Error {
    constructor(message) { super(message); this.name = 'AssertionError'; }
}

function format(value) {
    if (typeof value === 'string') return JSON.stringify(value);
    try { return JSON.stringify(value); } catch { return String(value); }
}

export function recordResult(result) { results.push(result); }
export function allResults() { return results; }
export { currentSuite };
