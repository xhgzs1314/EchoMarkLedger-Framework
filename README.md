# EchoMarkLedger-Framework

> **为 Web 应用与网页游戏设计的防篡改操作账本 + 运行时防护框架**
> 纯前端 · 零运行时依赖 · IndexedDB 持久化 · 设备绑定密钥的 HMAC 哈希链

> **选型前先读**：本框架提供的是**篡改可检测**与**作弊成本抬升**，不是绝对防作弊。
> 纯客户端安全存在理论天花板（详见 [§8 威胁模型](#8-威胁模型实事求是)），请在理解边界后再决定是否适用你的场景。
> 升级原因与 v1 的实测缺陷见 [§14 v1 → v2](#14-v1--v2为什么必须升级)。

---

## 目录
- [1. 背景](#1-背景为什么会有这个项目)
- [2. 定位：它是什么，不是什么](#2-定位它是什么不是什么)
- [3. 功能总览](#3-功能总览)
- [4. 工作原理](#4-工作原理)
- [5. 项目结构](#5-项目结构)
- [6. 构建与引入](#6-构建与引入)
- [7. 使用方法](#7-使用方法)
- [8. 威胁模型](#8-威胁模型)
- [9. 如何提高上限](#9-如何提高上限)
- [10. 二次开发指南](#10-二次开发指南)
- [11. 性能与兼容性](#11-性能与兼容性)
- [12. 测试](#12-测试)
- [13. FAQ](#13-faq)
- [15. 许可证](#15-许可证)

---

## 1. 背景：为什么会有这个项目

这个项目来自一个很具体的痛点：**网页解谜 / 解密类游戏的存档安全**。

绝大多数网页游戏的存档长这样：

```js
localStorage.setItem('save', JSON.stringify({ level: 3, coins: 999, unlocked: [...] }));
```

打开 DevTools，30 秒就能把 `coins` 改成九个九，跳过全部谜题直接通关。对一个以"解出谜题"为核心体验的游戏来说，这等于把游戏性连根拔起；如果再叠加排行榜和成就系统，公平性彻底归零。

EchoMarkLedger 要解决的就是这件事：**让存档在被修改后必然留下可检测的痕迹，并把"随手作弊"的成本抬升到"需要定向逆向"**。

它不发明新密码学，而是把"区块链式哈希链账本"这一经过验证的思想裁剪到浏览器可用的形态：每次游戏操作是一条记录，记录之间以哈希前后勾连、交叉织网，配合冗余存储与运行时防护，构成一个轻量的客户端存证系统。

**v2 的关键补强**：整套体系现在建立在一把**设备绑定的不可导出密钥**之上。v1 的所有校验值都是公开可重算的 SHA-256，任何拿到源码的人都能离线造出一份"合法"存档——那等于账本只防"手改"，不防"重造"。详见 [§14](#14-v1--v2为什么必须升级)。

## 2. 定位：它是什么，不是什么

**它是——**

- 一个**防篡改账本**：像封蜡 / 铅封，不能阻止拆信，但拆过一定留痕；
- 一个**操作审计系统**：什么时间发生了什么操作，链条完整、可逐条验证、可定位到第一条被破坏的记录；
- 一套**运行时加固扩展**（可选）：冻结、函数指纹、反 Hook、事件总线与自毁响应，抬高运行时篡改的成本。

**它不是——**

- **不是区块链**：没有共识、没有分布式账本，纯客户端本地存证；
- **不是反外挂系统**：拥有完整执行权与足够时间的攻击者，终能绕过客户端的一切校验；
- **不是加密系统**：防篡改 ≠ 防偷看，存档内容默认明文，需要保密请自行加密或配合服务端。

一句话总结：**账本证明的是"记录未被改动"，而不是"操作真实发生过"**。弥补后者的缺口，正是 [§9](#9-如何提高上限) 的主题。

## 3. 功能总览

| 能力 | 说明 |
|---|---|
| 设备绑定密钥 | `extractable: false` 的 HMAC-SHA-256 密钥，页面代码读不到明文；无密钥算不出任何校验值 |
| HMAC 哈希链 | 每条记录的 `H` 由前一条派生并用设备密钥签名，改一处、断全链 |
| 钩子链 | `recordOperation` 必须持有上一次返回的钩子，拦截盲调 / 乱序 / 重放 |
| 写入串行化 | 所有改动状态的操作进同一队列，并发调用不会写坏链条 |
| 双向验证网络 | 相邻 ±3 条记录交叉签名织网，单点篡改同时破坏最多 7 条记录的校验 |
| 整链 MAC | `checkpoint.chainMac` 覆盖全部记录哈希，截断 / 拼接 / 换设备一次抓出 |
| 规范化编码 | 带类型标签与长度前缀的单射编码，杜绝"不同语义、同一个哈希" |
| 四表散射存储 | IndexedDB 四张表，每行带 MAC，并与记录链交叉校验 |
| 自校验存档 | 导出的存档自带全部验证材料，`verifySave` 逐条复核（**只读，无副作用**） |
| 反回滚 | 密钥签名的进度高水位，旧备份不能无声覆盖新进度 |
| 业务语义钩子 | `validateOperation` 在写入与校验两侧对称生效 |
| 运行时防护（可选） | L1–L6：模块封印 / 原型守卫 / 函数指纹 / 反 Hook / 状态监控 / 事件总线与自毁 |
| 篡改定位 | 校验失败返回 `corruptedIndex` 与机器可判别的 `reason` |

## 4. 工作原理

### 4.1 设备绑定密钥（v2 的基石）

首次运行时用 WebCrypto 生成一把 HMAC-SHA-256 密钥：

```js
crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256', length: 256 },
                          /* extractable */ false, ['sign'])
```

`extractable: false` 意味着**浏览器不提供任何导出密钥明文的通道**。密钥以 CryptoKey 句柄形式存进一个独立的 IndexedDB（库名由 origin + gameId 派生，不使用显眼名称），运行期只存在于模块级 `WeakMap` 中——引擎实例上没有任何属性指向它，控制台里翻不到。

这把密钥买到的是两件事：

1. **离线伪造不可行**：攻击者把框架源码拷到 Node 里，算不出任何一个合法的 `H`；
2. **跨设备分享不可行**：伪造档在别人的浏览器上校验必然失败（`reason: 'foreign-device'`）。

边界见 [§8.2](#82-它明确防不住的诚实清单)。

### 4.2 HMAC 哈希链（主干）

```
H(n) = HMAC(deviceKey, canonical{ index, prevHash, operation, timestamp, nonce, runtimeContext, customData })
```

创世记录的 `prevHash` 为 64 个 `0`。任何一条记录的任何字段被改动，其 `H` 与重算值对不上，且后续所有记录的前序哈希全部断裂。

每个用途（`record` / `hook` / `dynamic` / `composite` / `link` / `chain` …）都带独立的域标签，使各用途的消息空间互不相交——某个用途下的合法值不能被搬到另一个用途下使用。

### 4.3 规范化编码

`H` 的输入先经过单射编码，每个值带类型标签、每个变长值带长度前缀：

```
null 'n' · bool 'b0'/'b1' · number 'd<len>:<repr>' · string 's<len>:<原文>'
array 'a<count>:' + 元素…  · object 'o<count>:' + 排序后的键值对…
```

有了长度前缀，"边界歧义"在数学上不可能出现。这修掉了 v1 的一类实战可利用缺陷：v1 用 `:`/`;`/`|` 拼接且不转义，`{aNick:'Bob;coins:9999'}` 与 `{aNick:'Bob', coins:9999}` 编码完全相同——只要游戏把玩家昵称之类的自由文本写进账本，攻击者就能事后"长"出一个 `coins` 字段而不破坏哈希链。

### 4.4 钩子链与写入串行化

```
hook(n) = HMAC(deviceKey, canonical{ H(n), nonce(n), timestamp(n) })
```

- 每次记录操作必须提交上一次返回的 `currentHook`，与引擎内部状态严格比对；
- 钩子由**新记录自身**的哈希、随机 nonce、时间戳派生——不可预计算、不可复用。

**并发**：所有会改动状态的操作（`init` / `recordOperation` / `loadSave` / `rekey`）进入同一个 Promise 队列串行执行。50 个共用同一钩子的并发调用，恰好 1 个成功、49 个被钩子链拒绝，链条保持严格连续。

> v1 在这里是坏的：钩子校验与状态更新之间隔着十次 `await`，三个并发调用会全部成功并写出索引 `[0,1,1,1]` 的坏链，引擎把自己的存档写到 `valid: false`。

### 4.5 双向验证网络

每条记录除了链接前一条，还与**前 3 条和后 3 条**记录建立交叉校验：

```
salt = HMAC(deviceKey, canonical{ a, b, offset })
V    = HMAC(deviceKey, canonical{ a, b, salt, offset })
```

后向链接在记录创建时计算；前向链接以 `pending` 占位，由后续记录回填。校验时除了重算比对，还会检查 `pending` 是否出现在不该出现的位置——防止攻击者把已算好的交叉验证抹成占位符来掩盖篡改。

`verificationWindow: 0` 可关闭织网，换取约 1.6× 的写入速度。

### 4.6 四表散射存储

```
┌──────────── IndexedDB ────────────┐
record #N ───►│ storeA     数据本体（槽位 = f(种子A, N)，10 万槽位空间按状态哈希散射）
              │ storeA'    数据备份（不同种子 → 不同散射位置）
              │ storeB     影子映射（逻辑索引 ↔ 四表槽位 + 记录 MAC）
              │ storeB'    影子映射备份
              └────────────────────────────────────┘
```

**每一行都带设备密钥签发的 MAC**，且四表快照与记录链逐条交叉校验。所以：

- 改任意一行 → 行 MAC 对不上；
- 同时改穿 A 与 A' → 依然对不上（v1 只比对两者是否一致，改穿即可）；
- 删一行 → 计数失衡；
- 剥掉 `_storageData` → 默认直接拒绝（`reason: 'missing-witness'`）。

四表写入合并在**单个事务**中完成，崩溃不会留下计数失衡的半成品；`recordIndex` 索引为 `unique`，从存储层杜绝重复索引注入。

### 4.7 运行时防护 L1–L6（`src/extend/security.js`，可选）

| 层 | 名称 | 机制 |
|---|---|---|
| L1 | 模块封印 | 导出对象冻结 + 不可配置 |
| L2 | 原型守卫 | 冻结 `EchoMarkLedger` / `QuadStorage` 原型（`destroy` 保留可调用） |
| L3 | 指纹校验 | 对函数源码取**真 SHA-256**注册，每 8s + 随机抖动复核 |
| L4 | 反 Hook | 与模块加载期捕获的原生 `Function.prototype.toString` 比对 |
| L5 | 状态监控 | `SecureEngineProxy` 包装实例：访问日志 + 写入拒绝 + 阻断闸门 |
| L6 | 安全事件总线 | 分级响应（**60 秒滑动窗口**计数）：≥5 次或单次 critical 阻断操作、≥8 次或 fatal 自毁 |

安全级别：`STANDARD`（L1+L2）→ `ENHANCED`（L1–L4）→ `MAXIMUM`（L1–L6）。

> **L5 不是安全边界，是可观测性。** v2 的引擎状态已改为 `#私有字段`，外部根本无从赋值；代理的价值在于产出可上报的事件与提供统一的阻断闸门。
> v1 曾用 `stack.includes('EchoMarkLedger')` 这类子串匹配调用栈来做"授权判断"——把攻击函数改名即可绕过，而且当项目目录名恰好含该关键字时，连直接赋值都拦不住。这类判据已全部删除。

### 4.8 一条记录与一份存档长什么样

**一条记录：**

```jsonc
{
  "index": 3,
  "H": "a3f0…",                              // 本条状态 MAC（链主干）
  "params": {
    "operation": { "type": "PUZZLE_SOLVED", "puzzleId": 7 },
    "prevHash": "…上一条记录的 H…",
    "timestamp": 1730000000000,
    "nonce": "随机 16 字节 hex",
    "runtimeContext": { "userAgentHash": "…", "screenSize": "…", "timeZone": "…" },
    "customData": { "hintsUsed": 0 }         // 业务附加数据，一并入链
  },
  "verify": {
    "dynamic":   "HMAC(key, {H, nonce, index})",
    "hook":      "HMAC(key, {H, nonce, timestamp})",
    "composite": "HMAC(key, {dynamic, prevHook, hook})"
  },
  "linkedVerifications": [                    // 双向验证网络
    { "targetIndex": 0, "offset": -3, "salt": "…", "V": "…" },
    { "targetIndex": 6, "offset":  3, "salt": "pending", "V": "pending" }
  ]
}
```

**一份存档（`exportSave()` 产出）：**

```jsonc
{
  "formatVersion": 2,
  "version": "1.0.0",
  "genesisHash": "…创世哈希…",
  "installId": "…本设备身份标识…",
  "records": [ /* 完整记录链 */ ],
  "metadata": { "gameId": "…", "createTime": 0, "lastPlayTime": 0, "totalOperations": 0 },
  "checkpoint": {
    "index": 42,
    "verifyHash": "HMAC(key, {H, genesisHash, index})",
    "chainMac":   "HMAC(key, {gameId, version, installId, genesisHash, lastIndex, hashes[]})"
  },
  "_storageData": { "storeA": [], "storeAPrime": [], "storeB": [], "storeBPrime": [] }
}
```

## 5. 项目结构

```
├── build.bat                    # 转发到 npm run build
├── package.json
├── scripts/build.mjs            # esbuild 构建 + 自由全局引用体检
├── dist/
│   ├── EchoMarkLedger.js        # 核心版产物
│   └── EchoMarkLedger-secure.js # 完整版产物（额外包含 L1–L6）
├── src/
│   ├── entry.js                 # 核心版入口
│   ├── entry-full.js            # 完整版入口
│   ├── migrate.js               # v1 → v2 迁移
│   ├── core/
│   │   ├── engine.js            # EchoMarkLedger：链条、钩子、校验、导入导出
│   │   ├── storage.js           # QuadStorage：四表散射存储与完整性校验
│   │   ├── crypto.js            # 原生引用捕获、SHA-256 / HMAC、fastHash
│   │   ├── canonical.js         # 单射的规范化编码
│   │   ├── keystore.js          # 设备密钥与反回滚高水位
│   │   └── utils.js             # 环境采集、冻结、反调试启发式
│   └── extend/
│       └── security.js          # L1–L6 运行时防护
└── tests/                       # 回归套件（node tests/run.mjs）
```

```
┌─────────────────────────────────────────────┐
│          游戏业务层（你写的代码）              │
└──────────────────┬──────────────────────────┘
                   │ recordOperation / exportSave / loadSave
┌──────────────────▼──────────────────────────┐
│           EchoMarkLedger（核心引擎）           │
│    HMAC 链 · 钩子链 · 双向验证 · 整链 MAC      │
└───┬───────────────┬──────────────┬──────────┘
┌───▼──────────┐ ┌──▼───────────┐ ┌▼──────────────────┐
│ QuadStorage  │ │ keystore     │ │ Security 扩展（可选）│
│ A/A'/B/B'    │ │ 设备密钥      │ │ L1–L6 运行时防护    │
│ 每行带 MAC    │ │ 反回滚高水位  │ │ 指纹 / 反Hook / 自毁│
└──────────────┘ └──────────────┘ └───────────────────┘
```

## 6. 构建与引入

```bash
npm install
npm run build     # 或 Windows 下直接运行 build.bat
npm test          # 回归套件
```

| 产物 | 内容 | 适用 |
|---|---|---|
| `EchoMarkLedger.js` | 引擎 + 存储 + 密钥库 | 只要存档防篡改，不要运行时防护 |
| `EchoMarkLedger-secure.js` | 以上 + L1–L6 安全扩展 | 需要运行时反篡改 / 反调试 |

构建脚本除了打包，还会做一次**自由全局引用体检**：在"全局读取会被记录"的沙箱里求值产物，确认它没有从 `window` 解析任何内部助手。这是把 v1 那个致命缺陷（见 [§14](#14-v1--v2为什么必须升级)）钉死在构建期的回归。

```html
<!-- Script 标签：全局只暴露一个冻结的 EchoMarkSys -->
<script src="dist/EchoMarkLedger.js"></script>
```

```js
// 或 ESM 直接使用源码
import { EchoMarkLedger } from './src/entry.js';
import { sealZeroTrustSystem, SecurityLevel } from './src/entry-full.js';
```

> `window.EchoMarkSys` 以 `writable: false, configurable: false` 定义，且不导出任何内部密码学实现。
> 生产环境如需更强的混淆效果，可设 `EMK_KEEP_NAMES=0` 去掉函数名保留，见 [§9.3](#93-构建期混淆与分发加固)。

## 7. 使用方法

### 7.1 基础版：核心引擎

```js
const engine = new EchoMarkLedger({
  gameId: 'puzzle-box',
  version: '1.0.0',
  autoSaveInterval: 30_000,   // 毫秒；> 0 开启定时保存
  saveDebounceMs: 0,          // > 0 可合并连续写入，见 §11
  onLoad: async () => JSON.parse(localStorage.getItem('puzzle-box-save') ?? 'null'),
  onSave: async (save) => localStorage.setItem('puzzle-box-save', JSON.stringify(save)),
  onDebug: (signals) => { console.warn('疑似调试', signals); }
});

const init = await engine.init();   // { H, currentHook, restored, lastIndex? }
if (init.restored) console.log('存档已恢复，当前进度 #' + init.lastIndex);

// —— 游戏内每次"值得记录"的事件 ——
async function onPuzzleSolved(puzzleId, timeMs) {
  const state = engine.getCurrentState();        // { index, H, hook, lastOperation }
  const res = await engine.recordOperation(
    { type: 'PUZZLE_SOLVED', puzzleId, timeMs }, // 业务操作（必须含 type 字段）
    state.hook,                                  // 钩子链"门票"：上一次返回的 currentHook
    { hintsUsed: 0 }                             // customData：随记录一并入链（可选）
  );
  // res: { index, H, currentHook, timestamp }
}
```

导出 / 校验 / 恢复：

```js
const save = await engine.exportSave();     // 自校验存档（深拷贝，不会随后续操作变化）
const ok   = await engine.verifySave(save); // 只读校验 → { valid, details, corruptedIndex?, reason? }
const rst  = await engine.loadSave(save);   // 验证通过后替换当前状态（破坏性）
```

校验失败时 `reason` 是机器可判别的：

| `reason` | 含义 |
|---|---|
| `format` | 不是 v2 存档（多半是 v1，需迁移） |
| `foreign-device` | 来自另一台设备 / 另一个浏览器配置 |
| `rollback` | 进度低于本机高水位（疑似回滚） |
| `missing-witness` | 缺少 `_storageData` 四表快照 |
| `semantic` | 未通过 `validateOperation` 业务校验 |
| *(无)* | 结构 / 哈希 / 链条完整性问题，看 `corruptedIndex` |

### 7.2 亲手试试篡改检测

```js
const save = await engine.exportSave();
save.records[2].params.customData.hintsUsed = 99;   // 模拟玩家篡改
const r = await engine.verifySave(save);
// → { valid: false, corruptedIndex: 2, details: '状态哈希验证失败' }
```

删除中间一条记录 → 双向验证或前序哈希报错；调换顺序 → 索引 / 链条校验报错；改 IndexedDB → 行 MAC 报错；剥掉四表 → `missing-witness`。每种篡改都有对应的失败原因与定位。

**更值得一试的**：把框架源码拷到 Node 里，用它自己的算法造一份存档——在 v1 上这会返回 `valid: true`，在 v2 上算不出来。这正是 `tests/suites/forgery.mjs` 干的事。

### 7.3 从 v1 迁移

```js
import { migrateV1ToV2 } from './src/entry.js';

const v1Save = JSON.parse(localStorage.getItem('old-save'));
const engine = new EchoMarkLedger({ gameId: 'puzzle-box', version: '1.0.0', onSave });
await engine.init();

const result = await migrateV1ToV2(v1Save, engine);
if (result.migrated) {
  // 链上留下一条 MIGRATED_V1 记录，含原链摘要作为审计证据
  console.log('迁移完成', result.v1Verification);
} else {
  // 老存档没通过 v1 校验；确认仍要迁移可传 { acceptUnverified: true }
  console.warn(result.error);
}
```

> 迁移只能**尽力确认**老存档没被手改——v1 本来就挡不住整链重伪造，所以这个结论仅供参考，会如实记在链上的 `v1Verified` 字段里。

### 7.4 换设备 / 云存档

存档绑定设备密钥，直接把文件拷到另一台设备会被拒绝（`reason: 'foreign-device'`）。需要迁移时：

```js
// 在新设备上：先导入链条（跳过设备校验由你的服务端授权），再重新签名
const result = await engine.rekey();
// 会更换设备密钥、以新密钥重签当前链条，并追加一条 REKEY 记录留痕
```

严肃场景下，跨设备迁移应当由服务端授权（见 [§9.1](#91-服务端配合性价比最高)）——否则"允许换设备"本身就是一条绕过设备绑定的通道。

### 7.5 安全版：L1–L6 运行时防护

```js
const secure = await sealZeroTrustSystem({
  level: SecurityLevel.MAXIMUM,            // STANDARD / ENHANCED / MAXIMUM
  onSecurityEvent: (e) => {                // { timestamp, severity, category, message, detail }
    if (e.severity !== 'warn') {           // critical / fatal 建议上报服务端
      fetch('/api/security-event', { method: 'POST', body: JSON.stringify(e) });
    }
  },
  hardenStorage: true,
  enableDebugCountermeasures: true
});

// 创建受保护引擎：MAXIMUM 级别返回 SecureEngineProxy 包装，对游戏代码透明
const engine = secure.createSecureEngine({
  gameId: 'puzzle-box',
  onLoad, onSave
});
await engine.init();

// 按事件类别订阅（tamper | hook | integrity | state | debug | system）
secure.securityBus.on('tamper', (e) => console.warn('篡改事件', e));

// 随时获取安全报告
console.log(await secure.getSecurityReport());
```

> `sealZeroTrustSystem` 是 **async** 的（指纹计算用真 SHA-256，异步）。
> 快捷方式：`quickSeal(onEvent)`（ENHANCED + 存储加固）、`maximumSeal(onEvent)`（全开）。

### 7.6 API 速查

| API | 说明 |
|---|---|
| `new EchoMarkLedger(options)` | 见下方选项表 |
| `await engine.init()` | 初始化或恢复存档，返回 `{ H, currentHook, restored, lastIndex? }` |
| `await engine.recordOperation(op, prevHook, customData?)` | 追加记录，返回 `{ index, H, currentHook, timestamp }` |
| `await engine.exportSave()` | 导出自校验存档（深拷贝） |
| `await engine.verifySave(save, opts?)` | **只读**校验，返回 `{ valid, details, corruptedIndex?, reason? }` |
| `await engine.loadSave(save, opts?)` | 验证并**替换**当前状态（破坏性） |
| `await engine.flush()` | 立即落盘（配合 `saveDebounceMs`） |
| `await engine.rekey()` | 更换设备密钥并重签链条 |
| `engine.getCurrentState()` | 冻结的当前状态 `{ index, H, hook, lastOperation }` |
| `engine.getHistory()` | 冻结的只读历史摘要 |
| `engine.stopAutoSave()` / `engine.destroy()` | 停止定时保存 / 销毁引擎（清理全部定时器） |
| `await sealZeroTrustSystem(options)` | 封印系统（async） |
| `await migrateV1ToV2(v1Save, engine, opts?)` | v1 存档迁移 |
| `await destroyIdentity(gameId)` | 抹掉设备身份与高水位（**会使现有存档永久失效**） |

**构造选项：**

| 选项 | 默认 | 说明 |
|---|---|---|
| `gameId` / `version` | `'default-game'` / `'1.0.0'` | 参与创世哈希；不同存档槽用不同 `gameId` |
| `onLoad` / `onSave` / `onDebug` | `null` | 持久化与调试回调 |
| `autoSaveInterval` | `0` | 定时保存间隔（毫秒） |
| `saveDebounceMs` | `0` | 合并连续写入的窗口，见 [§11](#11-性能与兼容性) |
| `verificationWindow` | `3` | 双向织网半径；`0` 关闭 |
| `requireStorageWitness` | `true` | 是否要求存档带 `_storageData` |
| `allowRollback` | `false` | 是否允许加载低于高水位的存档 |
| `validateOperation` | `null` | 业务语义校验，写入与校验两侧对称生效 |
| `blockOnDebug` | `false` | 认定调试后是否阻断写入（默认只留痕） |
| `enableDebugProbe` | `true` | 是否启用后台调试探针 |
| `maxRecords` | `100000` | 记录数上限，防加载期 DoS |
| `clockToleranceMs` | `300000` | 时间戳回退容差 |

### 7.7 使用须知

1. `recordOperation` 的 `prevHook` 必须与引擎内部状态严格相等——从上一次调用的返回值或 `getCurrentState().hook` 获取；
2. `loadSave` 是**破坏性**操作；只读校验一律用 `verifySave`；
3. 引擎在 `init` 与每次 `recordOperation` 成功后都会触发 `onSave`；连续大量写入时请开启 `saveDebounceMs` 并在关键时刻 `flush()`；
4. 存档内嵌完整链与四表快照，体积随操作数**线性增长**，长局建议规划存档策略；
5. `recordOperation` 适合"操作级"事件（过关、购买、成就、抽卡），不适合逐帧调用，见 [§11](#11-性能与兼容性)；
6. **存档绑定设备**：浏览器"清除站点数据"会一并清掉密钥，导致现有存档永久失效。请在游戏内提示玩家，或配合服务端备份。

## 8. 威胁模型

### 8.1 能检测 / 阻止的

| 攻击方式 | 检测 / 阻止机制 | 效果 |
|---|---|---|
| DevTools 直接编辑存档 JSON | HMAC 链 + 冗余校验值 + 整链 MAC，定位到 `corruptedIndex` | 必然检出 |
| 删除、重排、截断、拼接记录 | 索引连续性 + prevHash 链 + 双向验证 + `chainMac` | 必然检出 |
| **离线整链重伪造** | 设备绑定密钥：无密钥算不出任何校验值 | **不可行** |
| **把伪造档分享给他人** | `installId` + 密钥绑定，异机校验必失败 | **不可行** |
| 复制他人存档 | 同上，`reason: 'foreign-device'` | 必然检出 |
| 直接改 IndexedDB | 每行 MAC + 四表与链条交叉校验 | 必然检出 |
| 剥掉四表快照 | `requireStorageWitness` 默认开启 | 必然检出 |
| 回滚到旧备份 | 密钥签名的进度高水位（双存储位置） | 默认拒绝 |
| 利用序列化歧义"长"出字段 | 带类型标签与长度前缀的单射编码 | 不可行 |
| 并发写入制造坏链 | 写入串行化队列 | 必然拒绝 |
| 运行时替换引擎方法 | 实例方法不可写 + 原型冻结 + 指纹校验 + 内部状态私有 | 大幅抬高门槛 |
| 无钩子盲调 `recordOperation` | 钩子链：必须持有并依序传递 `currentHook` | 抬高门槛 |
| 挂调试器分析逻辑 | 反调试启发式（webdriver / 时间侧信道） | 吓退随手作弊，骗不过定向攻击者 |

### 8.2 它明确防不住的

1. **同源页面内的代码取出密钥句柄自己签名。** 这是 v2 的**新天花板**。密钥明文导不出来，但页面里的代码可以从 IndexedDB 拿到 `CryptoKey` 句柄，再调 `crypto.subtle.sign` 用它重签整条链。挡不住。但要做到这一步，攻击者得先读懂密钥存放位置与派生规则、canonical 编码、以及每个用途的域标签与签名结构——这是一份开发者级的工作量，而不是"控制台敲一行"。

2. **在框架加载之前就替换 crypto。** 浏览器扩展 / 用户脚本（Tampermonkey 运行在隔离世界，可以早于你的代码加载）、被篡改的 service worker、本地代理、静态资源替换。运行时自检根本没有执行机会——"谁来监督监督者"。`crypto.js` 在模块加载期捕获原生引用，只能挡住**加载之后**的替换。

3. **清库自残。** 清空 IndexedDB 会一并清掉设备密钥，存档永久失效。这破坏连续性但无法伪造数据，是否算损失取决于业务。

4. **反回滚可被绕过。** 高水位存在 keystore 库与 localStorage 两处，两处都清掉即可绕过。它抬的是成本，不是密码学保证。

5. **`fastHash` 不是密码学哈希。** 它只用于四表槽位散射（只需分布均匀，不需抗碰撞），不构成任何安全边界。账本主链与函数指纹使用的都是 WebCrypto 的真 SHA-256 / HMAC。

6. **账本证明"记录未被改动"，不证明"操作真实发生过"。** 一个能调用你 API 的脚本可以"合法地"记录一次它想要的操作。补这个缺口必须靠 [§9](#9-如何提高上限)。

**结论**：v1 把作弊门槛停在"会开控制台"；v2 把它抬到"会逆向 + 在受害者自己的浏览器里操作"，并彻底消灭了离线伪造与跨设备分享这两条最省事的路。对单机 / 休闲 / 轻竞技场景，这已经覆盖绝大多数潜在作弊者；对严肃竞技场景，客户端方案只能作为证据链的一环，裁决权必须交给服务端。

## 9. 如何提高上限

框架提供的是"下限保证"（篡改必留痕 + 离线不可伪造）。以下手段用于继续抬升上限，按性价比排序。

### 9.1 服务端配合（性价比最高）

核心思路：把"自证"升级为"他证"——账本负责结构完整，服务端负责最终裁决。

1. **逐条上报 + 独立重算**：`recordOperation` 成功后，将 `{index, H, hook, dynamic, composite}` 上报服务端；服务端独立维护每个玩家的链头，客户端账本退化为"证据副本"。
2. **单调性检查（反回滚）**：服务端为每个玩家记录 `最高 index → H`。加载存档前先对账——这是客户端高水位的权威版本。
3. **服务端签名存档**：`exportSave` 后由服务端对 checkpoint 做 HMAC / Ed25519 签名，`loadSave` 前强制验签。客户端没有服务端私钥，离线伪造整份存档不可行。
4. **语义校验**：服务端按 `operation.type` 校验业务合法性——金额上限、关卡依赖、频率限制。这一步把 [§8.2](#82-它明确防不住的诚实清单) 第 6 条的根本缺口补上一大半。客户端侧可用 `validateOperation` 做同构的前置校验。
5. **风控统计**：基于账本数据做规则 / 模型——操作速率、时间戳间隔、`runtimeContext` 环境漂移。
6. **跨设备迁移授权**：`rekey` 必须由服务端授权，否则它本身就是绕过设备绑定的通道。
7. **终极形态**：竞技性内容直接服务端权威结算，客户端账本降级为审计日志与离线模式的凭证。

### 9.2 核心逻辑下沉 WASM

- **做什么**：把链条推进与校验循环移入 Rust / C 编译的 WASM，`engine.js` 只保留一层薄 API。
- **得到什么**：内部函数不在 JS 可 Hook 的世界里；状态存放于 WASM 线性内存，控制台无法直接遍历；密钥句柄的取用路径也更难被观察。
- **边界**：WASM 同样可被逆向、内存同样可 dump——它只是把门槛从"会读 JS"抬到"会逆向"。
- **推荐组合**：WASM（逻辑黑盒化）+ 服务端（最终裁决）。

### 9.3 构建期混淆与分发加固

- **javascript-obfuscator**：控制流扁平化、字符串数组编码、self-defending。注意混淆在打包**之后**执行；`self-defending` 与二次压缩互斥。
- **去掉函数名保留**：`EMK_KEEP_NAMES=0 npm run build`，并私有保管 source map。
- **CSP + SRI**：`Content-Security-Policy: script-src 'self'` 限制脚本来源，并给 `<script>` 加 `integrity` 子资源哈希，提高静态替换成本——这直接针对 [§8.2](#82-它明确防不住的诚实清单) 第 2 条。
- **清醒剂**：混淆只买时间，不构成安全边界，请永远与 9.1 / 9.2 搭配使用。

### 9.4 其他叠加手段

- **一次性操作令牌**：服务端签发，`recordOperation` 前必须持有、用后作废——钩子链的服务端加强版；
- **多端环境一致性比对**：`runtimeContext` 的跨记录漂移分析放在服务端做，成本低、信号准；
- **敏感计算服务端化**：抽卡、掉落等关键数值的计算本身放服务端——账本管"留痕"，不管"真相"。

## 10. 二次开发指南

### 10.1 一次 `recordOperation` 的完整数据流

```
recordOperation(operation, prevHook, customData)
├─ 进入串行队列（保证同一时刻只有一个写入者）
├─ 前置校验：已初始化 / prevHook 匹配 / operation.type 存在 / 未超 maxRecords
├─ 业务校验：validateOperation(operation, customData, history)
├─ 采集：timestamp + nonce(16B) + runtimeContext
├─ 计算：H = HMAC(key, canonical{index, prevHash, operation, timestamp, nonce, ctx, customData})
├─ 计算：hook = HMAC(key, canonical{H, nonce, timestamp})   ← 下一次调用的"门票"
├─ 计算：dynamic / composite 冗余校验值
├─ 构建：双向验证链接（回看 3 条 + 预留 3 条 pending）
├─ 回填：前面 3 条记录的 pending 链接
├─ 写入：QuadStorage 四表（单事务，每行带 MAC）；失败则回滚内存
├─ 冻结：frozenState 快照
├─ 推进：反回滚高水位
└─ 触发：onSave(exportSave()) → 返回 { index, H, currentHook, timestamp }
```

### 10.2 常见二开场景

**a. 调整验证窗口**：构造选项 `verificationWindow`（默认 3，`0` 关闭）。窗口越大，交叉织网越密，代价是更多 HMAC 计算。修改后新旧存档结构不同，做好版本迁移。

**b. 更换存储后端**：实现与 `QuadStorage` 同名的方法集合即可替换，并通过构造选项 `storage` 注入：

```js
class RemoteQuadStorage extends QuadStorage {
  async writeToStore(storeName, data) { /* 走你的后端 */ }
  async readFromStoreByIndex(storeName, idx) { /* ... */ }
  async getAllFromStore(storeName) { /* ... */ }
}
const engine = new EchoMarkLedger({ gameId, storage: new RemoteQuadStorage(...) });
```

注意存储层通过 `setMacFn` 拿到的是"签名能力"而非密钥本体——自定义实现同样拿不到密钥。

**c. 订阅安全事件、自定义响应**：

```js
import { securityBus } from './src/extend/security.js';
securityBus.on('tamper', (e) => uploadEvent(e));
securityBus.on('integrity', (e) => enterSafeMode());
// 分级阈值在 SecurityEventBus 构造器中：{ warn: 3, block: 5, destroy: 8 }，60 秒滑动窗口
```

**d. 给记录增加业务校验**：**用 `validateOperation` 构造选项**，它在写入与校验两侧对称调用，不需要改两处代码。业务数据优先使用现成的 `customData` 通道（已自动入链）。

```js
new EchoMarkLedger({
  validateOperation: (op, customData, history) => {
    if (op.type === 'BUY' && op.amount > 100) return { valid: false, reason: '单次金额超限' };
    return true;
  }
});
```

**e. 新增反调试检测器**：在 `DebugCountermeasures` 中新增方法并在 `startAll()` 注册。新增判据前请先评估误报率——见 [§14](#14-v1--v2为什么必须升级) 第 8 条。

**f. 自定义封印范围**：`SealingSystem.sealClassPrototype(Class, { exclude, includeOnly })`。

> **重要**：`sealZeroTrustSystem` 会冻结类原型，且阻断 / 自毁在当前页面会话内不可逆。任何继承、扩展、原型修改都必须在**封印之前**完成。

## 11. 性能与兼容性

实测数据（Node 20 + fake-indexeddb，200 条连续写入；浏览器上 IndexedDB 更快，量级可参考）：

| 配置 | 写入 | 校验 201 条 |
|---|---|---|
| 默认（每条都触发 `onSave`） | ≈15.5 ms/条 | ≈600 ms |
| `saveDebounceMs: 50` | ≈4.7 ms/条 | ≈575 ms |
| `saveDebounceMs: 50` + `verificationWindow: 0` | ≈2.9 ms/条 | ≈305 ms |

**关键点**：每次 `recordOperation` 成功后都会触发 `onSave`，而 `onSave` 拿到的是**完整存档**，所以单条写入的固定开销与链长成正比——连续写入 N 条整体是 O(N²)。连续大量写入时请开启 `saveDebounceMs`：

```js
const engine = new EchoMarkLedger({ saveDebounceMs: 50, /* … */ });
// 在关卡结束 / 页面隐藏时确保落盘
addEventListener('visibilitychange', () => { if (document.hidden) engine.flush(); });
addEventListener('pagehide', () => engine.flush());
```

- **单条记录开销**：约十次 HMAC-SHA-256 + 1 个跨四表的 IndexedDB 事务 + 双向链接回填。适合操作级记录，**不适合逐帧调用**；
- **安全版额外开销**：每 8s（+随机抖动）一次全量指纹复核；反调试检测器 3–4s 间隔；
- **存档体积**：随操作数线性增长（201 条约 866 KB，关闭织网约 661 KB）。长局 / 高频记录场景请规划裁剪或服务端归档；
- **兼容性**：需要 WebCrypto（含 `extractable: false` 的 HMAC 密钥与 IndexedDB 结构化克隆）、IndexedDB、Proxy、私有类字段（ES2022）——即所有常青浏览器。**必须在 HTTPS 或 localhost 下运行**（`crypto.subtle` 要求安全上下文）。Node 环境需 `fake-indexeddb` 等 shim。

## 12. 测试

```bash
npm test
```

12 个套件、约 2900 项断言，全部来自对 v1 的实测对抗审计——每一条"攻击类"用例在 v1 上都是**成功**的，在 v2 上必须失败：

| 套件 | 覆盖 |
|---|---|
| `canonical` | 编码单射性；v1 的全部碰撞对；4000 例随机模糊测试 |
| `chain` | 正常流程、恢复、各类篡改定位、钩子链重放 |
| `forgery` | **无密钥全链伪造**、常量塌缩、crypto 劫持、设备绑定 |
| `concurrency` | 50 个并发写入串行化，链条保持连续 |
| `readonly` | `verifySave` 零副作用、导出无别名、TOCTOU |
| `persistence` | 合并写入不丢进度、`flush` 幂等 |
| `rollback` | 旧备份被拒、显式放行、伪造高水位不锁死玩家 |
| `storage` | 行 MAC、改穿 A/A'、计数失衡、剥掉四表、直改 IndexedDB |
| `security` | fatal 不递归、滑动窗口、加固后可用、L5 写保护 |
| `antidebug` | 模拟 Firefox 不误报、游戏保持可玩 |
| `migrate` | v1 校验、迁移留痕、拒绝篡改过的老存档 |
| `bundle` | 真实产物不依赖可写全局、劫持旧全局名无效 |

## 13. FAQ

**Q：这是区块链吗？**
不是。只借鉴了哈希链思想，没有共识、没有分布式账本，纯客户端本地存证。

**Q：能 100% 防改档吗？**
不能，也不存在能做到的纯客户端方案。v2 的定位是：**离线与跨设备伪造不可行** + 篡改必留痕 + 本机伪造需要开发者级工作量。请配合 [§9](#9-如何提高上限) 提升整体强度。

**Q：玩家换了电脑 / 清了浏览器数据，存档怎么办？**
会失效——这是设备绑定换来强度的代价。应对：(1) 游戏内明确提示；(2) 用 `rekey` 支持迁移（严肃场景需服务端授权）；(3) 云存档由服务端保管并重新签发。

**Q：反调试会不会误伤正常玩家？**
v2 大幅收敛了判据。v1 用 `navigator.plugins.length === 0`（Firefox 与多数移动浏览器普遍命中）和已废弃的 `chrome.loadTimes`，命中即永久阻断写入——正常玩家直接玩不了。v2 只保留 `navigator.webdriver` 与宽阈值时间侧信道，需**连续 3 次**命中才认定，且**默认只留痕不阻断**（要阻断需显式 `blockOnDebug: true`）。每 2 秒执行一次 `debugger` 的陷阱已移除。

**Q：能防加速器、宏、内存修改器吗？**
客户端层最多提供时间戳与速率等证据线索，真正判定需要服务端参与。内存修改客户端无法防御。

**Q：存档为什么这么大？**
完整记录链 + 四表快照都内嵌在存档里，这是"自带全部验证材料"的代价。可按业务裁剪（`requireStorageWitness: false`）或在服务端归档历史。

**Q：单机游戏值得用吗？**
值得。它挡住了"随手改 JSON"和"下载别人的通关档"的绝大多数潜在作弊者，让成就与本地排行榜有了可信依据，且零服务端成本。

**Q：支持多存档槽 / 云存档吗？**
持久化位置完全由你通过 `onLoad / onSave` 决定，每个存档槽用独立的 `gameId` 区分。云存档需注意设备绑定，见上文。

## 14. 许可证

本项目基于 [LICENSE](./LICENSE) 所述许可证发布