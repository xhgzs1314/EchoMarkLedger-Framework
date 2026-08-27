# EchoMarkLedger-FrameWork
> **为 Web 应用与网页游戏设计的防篡改操作账本 + 运行时防护框架**
> 纯前端 · 零运行时依赖 · IndexedDB 持久化 · 哈希链存证
>  **选型前先读**：本框架提供的是**篡改可检测**与**作弊成本抬升**，不是绝对防作弊。
> 纯客户端安全存在理论天花板（详见 [§8 威胁模型](#8-威胁模型实事求是)），请在理解边界后再决定是否适用你的场景。
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
- [12. FAQ](#12-faq)
- [13. 许可证](#13-许可证)
---
## 1. 背景：为什么会有这个项目
这个项目来自一个很具体的痛点：**网页解谜 / 解密类游戏的存档安全**。
绝大多数网页游戏的存档长这样：
```js
localStorage.setItem('save', JSON.stringify({ level: 3, coins: 999, unlocked: [...] }));
```
打开 DevTools，30 秒就能把 `coins` 改成九个九，跳过全部谜题直接通关。对一个以"解出谜题"为核心体验的游戏来说，这等于把游戏性连根拔起；如果再叠加排行榜和成就系统，公平性彻底归零
EchoMarkLedger 要解决的就是这件事：**让存档在被修改后必然留下可检测的痕迹，并把"随手作弊"的成本抬升到"需要定向逆向"**
它不发明新密码学，而是把"区块链式哈希链账本"这一经过验证的思想裁剪到浏览器可用的形态：每次游戏操作是一条记录，记录之间以哈希前后勾连、交叉织网，配合冗余存储与运行时防护，构成一个轻量的客户端存证系统
## 2. 定位：它是什么，不是什么
**它是——**
- 一个**防篡改账本**：像封蜡 / 铅封，不能阻止拆信，但拆过一定留痕，且任何持有代码的人都能复核；
- 一个**操作审计系统**：什么时间发生了什么操作，链条完整、可逐条验证、可定位到第一条被破坏的记录；
- 一套**运行时加固扩展**（可选）：冻结、函数指纹、反 Hook、反调试、事件总线与自毁响应，抬高运行时篡改的成本
**它不是——**
- **不是区块链**：没有共识、没有分布式账本，纯客户端本地存证；
- **不是反外挂系统**：拥有完整执行权与足够时间的攻击者，终能绕过客户端的一切校验；
- **不是加密系统**：防篡改 ≠ 防偷看，存档内容默认明文，需要保密请自行加密或配合服务端。
一句话总结：**账本证明的是"记录未被改动"，而不是"操作真实发生过"**。弥补后者的缺口，正是 [§9](#9-如何提高上限) 的主题
## 3. 功能总览
| 能力 | 说明 |
|---|---|
| 哈希链记录 | 每条记录的哈希由前一条派生，改一处、断全链 |
| 钩子链 | `recordOperation` 必须持有上一次返回的钩子，拦截盲调 / 乱序 / 并发写入 |
| 双向验证网络 | 相邻 ±3 条记录交叉哈希织网，单点篡改同时破坏最多 7 条记录的校验 |
| 冗余校验值 | dynamic / composite / checkpoint 多层冗余，不存在"局部修补"空间 |
| 四表散射存储 | IndexedDB 四张表（数据 / 数据备份 / 影子映射 / 影子备份），槽位按状态哈希散射 |
| 自校验存档 | 导出的存档自带全部验证材料，`verifySave` 逐条复核 |
| 运行时防护（可选） | L1–L6：模块封印 / 原型守卫 / 函数指纹 / 反 Hook / 状态监控 / 事件总线与自毁 |
| 反调试（可选） | 时间侧信道、DevTools 特征、debugger 陷阱等启发式检测 |
| 篡改定位 | 校验失败返回 `corruptedIndex`，精确到第一条损坏记录 |
## 4. 工作原理
### 4.1 哈希链（主干）
```
H(n) = SHA-256( H(n-1) | operation | timestamp | nonce | runtimeContext | customData )
```
创世记录的 `prevHash` 为 64 个 `0`。任何一条记录的任何字段被改动，其 `H` 与重算值对不上，且后续所有记录的前序哈希全部断裂。
### 4.2 钩子链
```
hook(n) = SHA-256( H(n) : hook : nonce(n) : timestamp(n) )
```
- 每次记录操作必须提交上一次返回的 `currentHook`，与引擎内部 `lastHook` 严格比对；
- 钩子由**新记录自身**的哈希、随机 nonce、时间戳派生——不可预计算、不可复用；
- 效果：绕过引擎直接写库、脚本盲调 `recordOperation`、乱序 / 并发写入，都会在第一道校验被拦下。
（注意：这拦的是"不懂协议的人"，不是"能读代码的人"，见 [§8.2](#82-它明确防不住的诚实清单)。）
### 4.3 双向验证网络
每条记录除了链接前一条，还与**前 3 条和后 3 条**记录建立交叉校验：
```
salt = SHA-256( hashA : hashB : offset : v1 )
V    = SHA-256( hashA : hashB : salt : offset )
```
后向链接在记录创建时计算；前向链接以 `pending` 占位，由后续记录回填；校验存档时全部重算比对。
结果：篡改第 N 条记录，至少同时破坏它自身与最多 6 个邻居的校验值——不存在"只改一处就能对上"的修补方式。
### 4.4 四表散射存储
```
┌──────────── IndexedDB ────────────┐
record #N ───►│ storeA     数据本体（槽位 = f(种子A,  N)，10 万槽位空间按状态哈希散射）
│ storeA'    数据备份（不同种子 → 不同散射位置）
│ storeB     影子映射（逻辑索引 ↔ 四表槽位 + 记录哈希）
│ storeB'    影子映射备份
└────────────────────────────────────┘
```
读取一条记录时要求同时满足：A ≡ A'（内容一致）、B ≡ B'（映射一致）、四个槽位与按种子重算的期望位置一致、记录哈希与影子映射中留存的一致。直接改库需要同时骗过四张表与重算逻辑；删除一条记录则四表计数立刻失衡。
### 4.5 运行时防护 L1–L6（`src/extend/security.js`，可选）
| 层 | 名称 | 机制 |
|---|---|---|
| L1 | 模块封印 | 工具函数导出对象冻结 + 不可配置，防覆盖替换 |
| L2 | 原型守卫 | 冻结 `EchoMarkLedger` / `QuadStorage` 原型（`destroy` 保留可调用），防原型链污染 |
| L3 | 指纹校验 | 对函数源码（去注释 / 空白归一化后）取哈希注册，每 8s + 随机抖动复核，不一致即触发 critical |
| L4 | 反 Hook | 对比基线 `Function.prototype.toString` 检测篡改；启发式检测 Proxy 包装；检查关键原型冻结状态 |
| L5 | 状态监控 | `SecureEngineProxy` 包装引擎实例：关键属性哈希快照 + 读取时复核；拦截写 / 删 / 重定义属性并做调用栈白名单判断；关键方法调用前二次指纹校验 |
| L6 | 安全事件总线 | 统一事件（severity × category），分级响应：累计计数 ≥3 警告、≥5 或单次 critical **立即阻断全部操作**、≥8 或 fatal **自毁**（销毁引擎并抛错）。阻断与自毁在当前页面会话内不可逆 |
安全级别：`STANDARD`（L1+L2）→ `ENHANCED`（L1–L4）→ `MAXIMUM`（L1–L6，含状态监控与反调试）。
### 4.6 一条记录与一份存档长什么样
**一条记录：**
```jsonc
{
"index": 3,
"H": "a3f0…",                              // 本条状态哈希（链主干）
"params": {
"operation": { "type": "PUZZLE_SOLVED", "puzzleId": 7 },
"prevHash": "…上一条记录的 H…",
"timestamp": 1730000000000,
"nonce": "随机 16 字节 hex",
"runtimeContext": { "userAgentHash": "…", "screenSize": "…", "timeZone": "…", "…": "…" },
"customData": { "hintsUsed": 0 }          // 业务附加数据，一并入链
},
"verify": {
"dynamic":   "SHA-256(H:dynamic:nonce:index)",
"hook":      "SHA-256(H:hook:nonce:timestamp)",
"composite": "SHA-256(dynamic:prevHook:hook)"
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
"version": "1.0.0",
"genesisHash": "…创世哈希…",
"records": [ /* 完整记录链 */ ],
"metadata": { "gameId": "…", "createTime": 0, "lastPlayTime": 0, "totalOperations": 0 },
"checkpoint": { "index": 42, "verifyHash": "SHA-256(currentHash:genesisHash:index)" },
"_storageData": { "storeA": [], "storeAPrime": [], "storeB": [], "storeBPrime": [] }
}
```
## 5. 项目结构
```
├── build.bat                  # esbuild 构建脚本
├── LICENSE
├── dist/
│   ├── EchoMarkLedger.js        # 核心版产物（引擎 + 存储 + 工具）
│   └── EchoMarkLedger-secure.js # 完整版产物（额外包含 L1–L6 安全扩展）
└── src/
├── entry.js                 # 核心版入口
├── entry-full.js            # 完整版入口（注意：security.js 必须晚于核心加载，入口文件已保证顺序）
├── core/
│   ├── engine.js            # EchoMarkLedger：哈希链、钩子链、双向验证、存档导入导出
│   ├── storage.js           # QuadStorage：IndexedDB 四表散射存储与完整性校验
│   └── utils.js             # SHA-256(WebCrypto) / 同步哈希、nonce、序列化、反调试、deepFreeze
└── extend/
└── security.js          # L1–L6 运行时防护
```
```
┌─────────────────────────────────────────────┐
│          游戏业务层（你写的代码）              │
└──────────────────┬──────────────────────────┘
│ recordOperation / exportSave / loadSave
┌──────────────────▼──────────────────────────┐
│           EchoMarkLedger（核心引擎）           │
│     哈希链 · 钩子链 · 双向验证网络 · 校验点     │
└─────────┬─────────────────────┬─────────────┘
┌─────────▼──────────┐  ┌───────▼─────────────┐
│ QuadStorage        │  │ Security 扩展（可选） │
│ A / A' / B / B'    │  │ L1–L6 运行时防护      │
│ (IndexedDB 四表)    │  │ 指纹 / 反Hook / 自毁  │
└────────────────────┘  └─────────────────────┘
```
## 6. 构建与引入
```bash
npm install -D esbuild
# Windows 直接运行 build.bat，或手动执行：
esbuild src/entry.js      --bundle --outfile=dist/EchoMarkLedger.js        --format=iife --global-name=EchoMarkSys --minify --keep-names
esbuild src/entry-full.js --bundle --outfile=dist/EchoMarkLedger-secure.js --format=iife --global-name=EchoMarkSys --minify --keep-names
```
| 产物 | 内容 | 适用 |
|---|---|---|
| `EchoMarkLedger.js` | 引擎 + 存储 + 工具 | 只要存档防篡改，不要运行时防护 |
| `EchoMarkLedger-secure.js` | 以上 + L1–L6 安全扩展 | 需要运行时反篡改 / 反调试 |
> `--keep-names` 保留函数名（便于排错），生产环境如需更强的混淆效果可移除，见 [§9.3](#93-构建期混淆与分发加固)。
引入方式：
```html
<!-- Script 标签（全局变量 EchoMarkSys） -->
<script src="dist/EchoMarkLedger.js"></script>
<script src="dist/EchoMarkLedger-secure.js"></script>
```
```js
// 或 ESM 直接使用源码
import { EchoMarkLedger } from './src/entry.js';
import { sealZeroTrustSystem, SecurityLevel } from './src/entry-full.js';
```
## 7. 使用方法
### 7.1 基础版：核心引擎
```js
const engine = new EchoMarkLedger({
gameId: 'puzzle-box',
version: '1.0.0',
autoSaveInterval: 30_000,   // 毫秒；> 0 开启自动保存
onLoad: async () => JSON.parse(localStorage.getItem('puzzle-box-save') ?? 'null'),
onSave: async (save) => localStorage.setItem('puzzle-box-save', JSON.stringify(save)),
onDebug: () => { achievementSystem.disable(); }   // 检测到调试行为时的回调
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
const save = await engine.exportSave();     // 自校验存档（含完整链 + 四表快照 + 校验点）
const ok   = await engine.verifySave(save); // 非破坏性校验 → { valid: true, details: '存档有效，共 N 条记录' }
const rst  = await engine.loadSave(save);   // 验证通过后替换当前状态（破坏性，见 7.5 使用须知）
```
### 7.2 亲手试试篡改检测
```js
const save = await engine.exportSave();
save.records[2].params.customData.hintsUsed = 0;   // 模拟玩家篡改
const r = await engine.verifySave(save);
// → { valid: false, corruptedIndex: 2, details: '状态哈希验证失败' }
```
删除中间一条记录 → `索引不连续` 或 `前序哈希不匹配`；调换顺序 → 索引校验报错；改 IndexedDB → 四表校验报错。每种篡改都有对应的失败原因与定位。
### 7.3 安全版：L1–L6 运行时防护
```js
const secure = sealZeroTrustSystem({
level: SecurityLevel.MAXIMUM,            // STANDARD / ENHANCED / MAXIMUM
onSecurityEvent: (e) => {                // { timestamp, severity, category, message, detail }
if (e.severity !== 'warn') {           // critical / fatal 建议上报服务端
fetch('/api/security-event', { method: 'POST', body: JSON.stringify(e) });
}
},
hardenStorage: true,                     // 加固 QuadStorage（调用栈白名单 + 实例属性封印）
enableDebugCountermeasures: true         // 反调试（启发式，有误报风险，见 FAQ）
});
// 创建受保护引擎：MAXIMUM 级别返回 SecureEngineProxy 包装，对游戏代码完全透明
const raw_engine = secure.EchoMarkLedger({
gameId: 'puzzle-box',
onLoad: ..., onSave: ...
});
const engine = protectEngineInstance(raw_engine);
await engine.init();
// 也可按事件类别订阅（tamper | hook | integrity | state | debug | system）
secure.securityBus.on('tamper', (e) => console.warn('篡改事件', e));
// 随时获取安全报告
console.log(getSecurityReport());
// { sealed, level, sealedAt, operationsBlocked, selfDestructed, fingerprintStatus, recentEvents }
```
快捷方式与工具函数：
```js
const { quickSeal, maximumSeal, protectEngineInstance } = EchoMarkSys;
quickSeal(onEvent);    // ENHANCED + 存储加固，不开反调试
maximumSeal(onEvent);  // MAXIMUM 全开
// 包装一个已存在的引擎实例（自定义监控属性）
const wrapped = protectEngineInstance(existingEngine, {
monitorProperties: ['records', 'currentIndex', 'currentHash', 'lastHook', 'genesisHash'],
blockOnTamper: true
});
```
### 7.4 API 速查
| API | 说明 |
|---|---|
| `new EchoMarkLedger(options)` | `gameId` / `version` / `onLoad` / `onSave` / `onDebug` / `autoSaveInterval` |
| `await engine.init()` | 初始化或恢复存档，返回 `{ H, currentHook, restored, lastIndex? }` |
| `await engine.recordOperation(op, prevHook, customData?)` | 追加记录，返回 `{ index, H, currentHook, timestamp }` |
| `await engine.exportSave()` | 导出自校验存档 |
| `await engine.verifySave(save)` | **非破坏性**校验，返回 `{ valid, details, corruptedIndex? }` |
| `await engine.loadSave(save)` | 验证并**替换**当前状态（破坏性） |
| `engine.getCurrentState()` | 冻结的当前状态 `{ index, H, hook, lastOperation }` |
| `engine.getHistory()` | 冻结的只读历史摘要 |
| `engine.stopAutoSave()` / `engine.destroy()` | 停止自动保存 / 销毁引擎 |
| `sealZeroTrustSystem(options)` | 封印系统（level / onSecurityEvent / hardenStorage / enableDebugCountermeasures） |
| `getSecurityReport()` | 安全状态总览 |
| `securityBus.on(category, cb)` | 订阅安全事件 |
### 7.5 使用须知
1. `recordOperation` 的 `prevHook` 必须与引擎内部 `lastHook` 严格相等——从上一次调用的返回值或 `getCurrentState().hook` 获取；
2. `loadSave` 是**破坏性**操作，应用失败会把引擎重置为空状态；只读校验一律用 `verifySave`；
3. 引擎在 `init` 与每次 `recordOperation` 成功后都会自动触发 `onSave`；
4. 存档内嵌完整链与四表快照（`_storageData`），体积随操作数**线性增长**，长局建议规划存档策略；
5. `recordOperation` 适合"操作级"事件（过关、购买、成就、抽卡），不适合逐帧调用，见 §11；
6. 反调试特征在不同浏览器上可能误报，上线前务必实测（见 FAQ）。
## 8. 威胁模型（实事求是）
### 8.1 能检测 / 阻止的
| 攻击方式 | 检测 / 阻止机制 | 效果 |
|---|---|---|
| DevTools 直接编辑 localStorage / 存档 JSON | 哈希链 + 冗余校验值 + 校验点，定位到 `corruptedIndex` |  必然检出 |
| 删除、重排、拼接记录 | 索引连续性 + prevHash 链 + 双向验证网络 |  必然检出 |
| 复制他人存档 / 拼接他人记录 | 创世记录绑定 gameId / version / runtimeContext，链式哈希不匹配 |  必然检出 |
| 直接改 IndexedDB 数据 | 四表冗余 + 槽位散射 + 影子映射哈希校验 |  必然检出（需同时改穿 4 张表） |
| 运行时替换引擎方法 | 实例关键方法不可写 + 原型冻结 + 函数指纹周期校验 + 反 Hook 扫描 |  大幅抬高门槛 |
| 覆盖 / 替换模块导出与工具函数 | 模块封印（freeze + 不可配置） |  抬高门槛 |
| 无钩子盲调 `recordOperation` 伪造 | 钩子链：必须持有并依序传递 currentHook |  抬高门槛 |
| 挂调试器分析逻辑 | 反调试启发式（时间侧信道 / 窗口特征 / debugger 陷阱） |  吓退随手作弊，骗不过定向攻击者 |
### 8.2 它明确防不住的
1. **浏览器扩展 / 用户脚本**：Tampermonkey 之类运行在隔离世界，可以早于你的代码加载、包装 fetch / crypto / IndexedDB、甚至替攻击者"合法"调用你的 API。页面内的任何检测都看不到它们。
2. **加载前替换脚本**：本地代理、被篡改的 service worker 或静态资源替换——运行时自检根本没有执行机会（"谁来监督监督者"问题）。
3. **直接删库**：清空 IndexedDB 属于"自残"，破坏连续性但无法伪造数据，是否算损失取决于业务。
4. **设计权衡**：工具集中的 `sha256Sync` 是自定义轻量哈希（非加密强度），仅用于指纹与槽位散射，不构成密码学边界；账本主链使用 WebCrypto 的真 SHA-256，但若攻击者连 `crypto.subtle` 都能替换，则一切校验皆可伪造。
**结论**：本框架把作弊门槛从"会开控制台"抬到"会逆向"，并保证任何事后篡改必然留痕。对单机 / 休闲 / 轻竞技场景，这已经覆盖绝大多数潜在作弊者；对严肃竞技场景，客户端方案只能作为证据链的一环，裁决权必须交给服务端。
## 9. 如何提高上限
框架提供的是"下限保证"（篡改必留痕）。以下手段用于在它之上继续抬升上限，按性价比排序。
### 9.1 服务端配合（性价比最高）
核心思路：把"自证"升级为"他证"——账本负责结构完整，服务端负责最终裁决。
1. **逐条上报 + 独立重算**：`recordOperation` 成功后，将 `{index, H, hook, dynamic, composite}` 上报服务端；服务端独立维护每个玩家的链头，客户端账本退化为"证据副本"。
2. **单调性检查（反回滚）**：服务端为每个玩家记录 `最高 index → H`。加载存档前先对账：客户端 index < 服务端 index，即为回滚攻击，直接拒绝。
3. **服务端签名存档（反整体伪造）**：`exportSave` 后由服务端对 checkpoint 做 HMAC / Ed25519 签名，`loadSave` 前强制验签。客户端没有签名能力，离线伪造整份存档不可行。
4. **语义校验（补上"操作真实"的缺口）**：服务端按 `operation.type` 校验业务合法性——金额上限、关卡依赖、频率限制。这一步把 §8.2 第 1 条的根本缺口补上一大半。
5. **风控统计**：基于账本数据在服务端做规则 / 模型——操作速率、时间戳间隔、`runtimeContext` 环境漂移（换设备、疑似自动化）。
6. **终极形态**：竞技性内容直接服务端权威结算，客户端账本降级为审计日志与离线模式的凭证。
### 9.2 核心逻辑下沉 WASM
- **做什么**：把哈希计算、钩子链推进、`loadSave / verifySave` 的校验循环移入 Rust / C / C++ 编译出的 WASM，`engine.js` 只保留一层薄 API。
- **得到什么**：
- 内部函数不在 JS 可 Hook 的世界里，`toString` 篡改、Proxy 包装等手法对其无效；
- 状态存放于 WASM 线性内存，DevTools 控制台无法直接遍历；
- 顺手用 WASM 内的真 SHA-256 替换弱同步哈希，摆脱对可被替换的 `crypto.subtle` 的依赖。
- **边界**：WASM 同样可以被逆向、内存同样可以被 dump——它只是把门槛从"会开控制台"抬到"会逆向工程"。
- **推荐组合**：WASM（逻辑黑盒化）+ 服务端（最终裁决）。两者叠加后，单独攻破客户端的收益趋近于零。
### 9.3 构建期混淆与分发加固
- **javascript-obfuscator**：控制流扁平化、字符串数组编码、死代码注入、self-defending。注意：混淆在 esbuild 打包**之后**执行；`self-defending` 与二次压缩互斥，先小范围验证。
- **去掉 `--keep-names`**：当前构建保留函数名便于排错；生产可移除并私有保管 source map——代价是自己的排错成本上升，请自行权衡。
- **CSP + SRI**：`Content-Security-Policy: script-src 'self'` 限制脚本来源，并给 `<script>` 标签加 `integrity` 子资源哈希，提高静态替换成本。
- **代码分割与按需下发**：校验逻辑拆块懒加载，或由服务端下发带时效的挑战代码，使静态分析拿不到全貌。
- **清醒剂**：混淆只买时间（把 30 分钟的破解变成三天），不构成安全边界，请永远与 9.1 / 9.2 搭配使用。
### 9.4 其他叠加手段
- **一次性操作令牌**：服务端签发，`recordOperation` 前必须持有、用后作废——钩子链的服务端加强版；
- **WebCrypto 不可导出密钥**：做客户端签名作为纵深防御的一层（密钥不可读，但页面内代码仍可调用，故不能作为唯一防线）；
- **多端环境一致性比对**：`runtimeContext` 的跨记录漂移分析放在服务端做，成本低、信号准；
- **敏感计算服务端化**：抽卡、掉落等关键数值的计算本身放服务端——账本管"留痕"，不管"真相"。
## 10. 二次开发指南
### 10.1 一次 `recordOperation` 的完整数据流
```
recordOperation(operation, prevHook, customData)
├─ 前置校验：已初始化 / 未检测到调试 / prevHook === lastHook / operation.type 存在
├─ 采集：timestamp + nonce(16B) + runtimeContext
├─ 计算：H = SHA-256(prevHash|operation|timestamp|nonce|runtimeContext|customData)
├─ 计算：hook = SHA-256(H:hook:nonce:timestamp)          ← 下一次调用的"门票"
├─ 计算：dynamic / composite 冗余校验值
├─ 构建：双向验证链接（回看 3 条 + 预留 3 条 pending）
├─ 回填：前面 3 条记录的 pending 链接
├─ 写入：QuadStorage 四表（槽位散射）
├─ 冻结：frozenState 快照
└─ 触发：onSave(exportSave()) → 返回 { index, H, currentHook, timestamp }
```
### 10.2 常见二开场景
**a. 调整验证窗口**：`engine.js` 构造函数中 `this.verificationWindow = 3`。窗口越大，交叉织网越密、篡改越难"就地修补"，代价是更多哈希计算。注意修改后新旧存档的双向链接结构不同，做好版本迁移。
**b. 更换存储后端**：实现与 `QuadStorage` 同名的方法集合即可替换（`init / clearAll / clearStore / writeRecord / writeToStore / readFromStoreByIndex / readRecord / getAllFromStore / verifyIntegrity / exportAll / importAll / close`）：
```js
class RemoteQuadStorage extends QuadStorage {
async writeToStore(storeName, data) { /* 走你的后端 */ }
async readFromStoreByIndex(storeName, idx) { /* ... */ }
async getAllFromStore(storeName) { /* ... */ }
// 其余按需覆写，接口签名保持不变
}
// 然后在 engine.js 构造函数中替换 new QuadStorage(...)
```
**c. 订阅安全事件、自定义响应**：
```js
import { securityBus } from './src/extend/security.js';
securityBus.on('tamper', (e) => uploadEvent(e));
securityBus.on('integrity', (e) => enterSafeMode());
// 分级阈值在 SecurityEventBus 构造器中：{ warn: 3, block: 5, destroy: 8 }
```
**d. 给记录增加业务校验**：必须**对称修改** `recordOperation`（写入）与 `loadSave`（验证）两处逻辑，否则框架连自己导出的存档都无法通过校验。业务数据优先使用现成的 `customData` 通道（已自动入链），能不改结构就不改结构。
**e. 新增反调试检测器**：在 `DebugCountermeasures` 中新增方法并在 `startAll()` 注册；同样地，删减检测项也在这里操作。
**f. 自定义封印范围**：`SealingSystem.sealClassPrototype(Class, { exclude, includeOnly })` 可控制冻结哪些方法。
> **重要**：`sealZeroTrustSystem` 会冻结类原型，且阻断 / 自毁不可逆。任何继承、扩展、原型修改都必须在**封印之前**完成，或在源码层修改后重新构建。
### 10.3 构建与自测
```bash
npm install -D esbuild
build.bat    # Windows；其他平台直接执行文件内两条 esbuild 命令
```
改动后建议跑一遍自洽性测试：
1. `init → recordOperation × N → exportSave → verifySave` 应全部 `valid: true`；
2. 篡改任意记录的任意字段 → `verifySave` 应 `valid: false` 且 `corruptedIndex` 指向正确位置；
3. 删除中间记录 / 乱序排列 → 索引或前序哈希校验应报错；
4. 直接修改 IndexedDB → `storage.verifyIntegrity()` 应报错；
5. 注意 `loadSave` 应用失败会重置引擎状态，测试时留意副作用。
## 11. 性能与兼容性
- **单条记录开销**：约十余次 SHA-256（WebCrypto 异步）+ 4 次 IndexedDB 写事务 + 双向链接回填。适合操作级记录（过关、购买、成就），**不适合逐帧调用**；
- **安全版额外开销**：每 8s（+随机抖动）一次全量指纹复核；反调试检测器以 2–5s 间隔运行；
- **存档体积**：随操作数线性增长（完整链 + 四表快照内嵌），长局 / 高频记录场景请规划裁剪或服务端归档策略；
- **兼容性**：需要 WebCrypto、IndexedDB、Proxy、Symbol、WeakMap——即所有常青浏览器。Node 环境需 `fake-indexeddb` 等 shim。
## 12. FAQ
**Q：这是区块链吗？**
不是。只借鉴了哈希链思想，没有共识、没有分布式账本，纯客户端本地存证。
**Q：能 100% 防改档吗？**
不能，也不存在能做到的纯客户端方案。本框架的定位是：篡改必留痕 + 抬高门槛 + 留存证据。请配合 §9 提升整体强度。
**Q：反调试会不会误伤正常玩家？**
有可能。反调试依赖启发式特征（时间侧信道、窗口尺寸差、`navigator` 特征等），这些特征会随浏览器版本漂移产生误报。上线前请在目标浏览器实测校准，必要时关闭 `enableDebugCountermeasures` 或调整 `utils.js` 中 `antiDebugDetection` 的判定条件。
**Q：能防加速器、宏、内存修改器吗？**
客户端层最多提供时间戳与速率等证据线索（记录里都有），真正判定需要服务端参与（§9.1 第 5 条）。内存修改属于 §8.2 第 3 条，客户端无法防御。
**Q：存档为什么这么大？**
完整记录链 + 四表快照都内嵌在存档里，这是"自带全部验证材料"的代价。可按业务裁剪 `_storageData` 或在服务端归档历史。
**Q：单机游戏值得用吗？**
值得。它挡住了"随手改 JSON"的绝大多数潜在作弊者，让成就与本地排行榜有了可信依据，且零服务端成本。
**Q：支持多存档槽 / 云存档吗？**
存档的持久化位置完全由你通过 `onLoad / onSave` 决定（localStorage、云接口、文件均可），每个存档槽用独立的 `gameId` 或存储键区分即可。
## 13. 许可证
本项目基于 [LICENSE](./LICENSE) 所述许可证发布。