/**
 * 回归套件入口：node tests/run.mjs
 */

import './env.mjs';
import { makeContext, AssertionError } from './harness.mjs';

const SUITES = [
    './suites/canonical.mjs',
    './suites/chain.mjs',
    './suites/forgery.mjs',
    './suites/concurrency.mjs',
    './suites/readonly.mjs',
    './suites/persistence.mjs',
    './suites/rollback.mjs',
    './suites/storage.mjs',
    './suites/security.mjs',
    './suites/antidebug.mjs',
    './suites/migrate.mjs',
    './suites/bundle.mjs',
];

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

let passed = 0;
let failed = 0;
const failures = [];

for (const path of SUITES) {
    const module = await import(path);
    const name = module.name || path;
    const context = makeContext(name);
    const started = Date.now();

    try {
        await module.default(context);
        const count = context.checks.filter((c) => !c.note).length;
        passed++;
        console.log(`${GREEN}✓${RESET} ${name} ${DIM}(${count} 项断言, ${Date.now() - started}ms)${RESET}`);
        for (const check of context.checks) {
            if (check.note) console.log(`  ${DIM}· ${check.message}${RESET}`);
        }
    } catch (error) {
        failed++;
        const done = context.checks.filter((c) => !c.note && c.pass).length;
        console.log(`${RED}✗${RESET} ${name} ${DIM}(前 ${done} 项通过, ${Date.now() - started}ms)${RESET}`);
        const label = error instanceof AssertionError ? '断言失败' : `意外错误 ${error.name}`;
        console.log(`  ${RED}${label}: ${error.message}${RESET}`);
        if (!(error instanceof AssertionError)) console.log(`  ${DIM}${error.stack?.split('\n').slice(1, 4).join('\n')}${RESET}`);
        failures.push({ name, error });
    }
}

console.log('');
console.log(`${failed === 0 ? GREEN : RED}套件: ${passed} 通过 / ${failed} 失败${RESET}`);

// 反调试探针与指纹监控都是自续期定时器，不主动退出进程会一直挂着
process.exit(failed === 0 ? 0 : 1);
