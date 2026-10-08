# Yank 管理端（syncd/web）

同步服务的自托管管理台：登录、看设备与同步历史、生成配对码、回退版本，并展示**服务端读得出的
那两份清单**（主机、片段）。

产品口径（不可协商）：**浏览器永远看不到 SSH 口令与私钥。**
- 服务端只存不透明信封。清单那一格（主机 + 片段）走的是**明文通道**（SPEC §5、§5.1，2026-10 拍板）：
  客户端只上传白名单字段——主机的名称、分组、地址、端口、登录用户、认证方式、备注、跳板，片段的
  名称、分组、正文、占位符名。认证方式只是"口令 / 私钥 / agent"这种**方法名**，不含任何凭据本体；
  备注与片段正文在离开 Mac 之前先过端侧嗅探，看着像口令的那一条整条换成说明文字。
- 启用「加密传输（通道口令）」只是让服务端**多解开一层**：那一层装的是上面这些白名单字段，解开它
  才能建主机索引。同步包本体（含凭据）是**端到端**那一层，口令由客户端自己从钥匙串取，服务端和
  这一页都拿不到，所以凭据永远读不出来。
- 管理端因此**不做任何本地解密**：没有口令输入框，没有 PBKDF2/AES-GCM，没有 WebCrypto，
  连信封的字节都不读进内存（`GET /api/blob` 只取 ETag 版本号，响应体直接 `body.cancel()`）。
  历史上那条「在网页里输入端到端口令、浏览器本地解开整包」的路已经整条删除——它等于把
  所有口令摊在浏览器里。

## 构建与自检

```bash
node --version      # 需要 Node 24；用 nvm 的话先 nvm use 24
cd syncd/web
npm install
npm run build          # 产出 dist/
npm run typecheck      # vue-tsc --noEmit
npm run test:dom       # SSR 渲染真组件：主机元数据渲染得出，口令/凭据 canary 渲染不出
npm run test:gate      # 负向门禁（脚本自带 build）：src/ 与 dist/ 里不许再有解密路径与口令控件
npm run test:e2e       # 打真 Go 服务的端到端（见下）
npm run test:channel-page  # 页面配置通道密钥（口令）的状态机（服务什么都不配地起，口令由脚本配）
```

`test:dom` / `test:gate` / `test:e2e` 是普通脚本而非测试框架。

## 负向门禁（`tests/gate.mjs`，`npm run test:gate` = `vite build` + 门禁）

证明被禁能力确实没了，四组断言：

- **A 解密路径不存在**：`src/` 全部文件与 `dist/` 产物里都不得出现
  `deriveKey` / `PBKDF2` / `pbkdf2` / `AES-GCM` / `aes-256-gcm` / `passphrase` / `Passphrase` /
  `secretMaterial` / `secretVault` 任一字符串。
- **B 没有口令输入控件**：`src/` 里每一个含 `<input>` 的 `<label>` 控件块都不得提到「口令」；
  `type="password"` 在 `src/` **恰好 5 处**（登录页 1 + 改管理端登录口令 3 + 通道密钥 1），`dist/`
  里编译后的 `type:"password"` 必须与这一数一一对上；界面文案里不得残留「在本地解密 / 本地解密」。
  全站没有端到端口令框，也没有任何把口令当查询参数/路径片段发出去的写法。
- **C 令牌与秘密卫生**：`src/` 里不得出现 `localStorage` / `sessionStorage` / `console.`；
  `authorization` 头只允许 `` `Bearer ${token.value}` `` 一种写法；`token` 标识符只允许活在
  `useApi.ts`；路径字面量里不得插值；`fetch(` 只出现在 `useApi.ts`；
  `/api/hosts`、`/api/blob/rollback` **只能**在 `useApi.ts` 里被调用。
- **D 旧写入路径断开**：`src/` 不得再有 `method: 'PUT'`、`if-match`、`/api/blob/at/`；
  产物里不得残留 `method:"PUT"`。回退只走 `POST /api/blob/rollback`。

`tests/render-check.mjs` 另走 SSR 通道，把 canary（同步口令、凭据材料字节及其 base64、
凭据库密文）**塞进组件入参的多余字段**里，断言主机元数据渲染得出来、canary 一个都渲染不出来，
并断言 503 场景的说明文案带上了服务端的中文原文。

## 接口口径（与 `syncd/SPEC.md` §6 对齐）

| 用法 | 接口 | 说明 |
| --- | --- | --- |
| 登录/注册/退出 | `POST /api/register\|login\|logout` | 会话令牌只在内存，刷新即失效 |
| 主机清单 | `GET /api/hosts` | **裸 JSON 数组** `[{name,group,hostname,port,username,authKind,notes,jump,revision}]`，空则是 `[]`；**永远 `200`**，不需要先启用通道口令 |
| 片段清单 | `GET /api/snippets` | 同样是**裸数组** `[{name,group,body,params,updatedAt,revision}]`，与 `/api/hosts` 同权（会话令牌或设备令牌均可）、同样**永远 `200`**、同样不需要先启用通道口令。`body` 是端侧嗅探过的那一份：命中疑似口令或过长时它是替换文本，不是原样命令 |
| 读不到清单 | 只可能是 `401`（未登录/会话过期）或网络失败 | 空数组是"真的还没有数据"，不是"功能没开"——用户 2026-10-03 改的口径；中文理由原样转达 |
| 同步历史 | `GET /api/blob/history` | `{items:[{revision,deviceId,createdAt,bytes}]}`，只有元数据 |
| 回退 | `POST /api/blob/rollback` `{"revision":N}` | → `200 {"revision":新版本}`；服务端把那一版密文原样前滚，不需要口令 |
| 当前版本 | `GET /api/blob` 的 `ETag` | 只读 header，body 不读 |
| 设备/配对 | `GET /api/devices`、`POST /api/devices/revoke`、`POST /api/pair` | 同旧版 |

`PUT /api/blob` 是设备令牌专用写入路径，**管理端不调**（e2e 脚本里出现它只是为了模拟 Mac 设备端）。
「主机清单**不论是否启用加密传输都能列出**（清单本来就走明文那一格，用户 2026-10-03 拍板）；
无论是否启用，凭据都永远不会在浏览器里显示」——这句话在 `HostsNotice.vue` 里，任何读取失败
（网络、`401`）都会显示它，**且绝不提供端到端口令框作为补救**。

## 已删除的能力与随之消失的测试

`src/crypto.ts`、`src/useVault.ts`、`tests/crypto.test.ts`、`tests/sealUtil.mjs` 已删除：
它们唯一的服务对象就是「浏览器输入端到端口令 + WebCrypto 本地解密」这条路。

随之**取消的是跨语言口令信封互操作向量测试**：`tests/crypto.test.ts` 原先直接解密
`syncd/testdata/envelope-vectors.json` 里由 Swift 端 `dropterm-selftest` 生成的向量，
用来证明浏览器↔Swift 的口令信封逐字节一致。现在浏览器不具备也不该具备解密能力，
这类向量不再属于本目录；同一份向量仍由 Go 侧
`syncd/server/envelope_test.go` 消费，Swift↔Go 的一致性没有丢，只是不再经过前端。
`tests/channelSeal.mjs` 只用于 e2e **模拟 Mac 设备端**产出 SPEC §5 的通道信封，不在 `src/`，
也不在任何页面代码路径上。

## 产物怎么进二进制

`npm run build` 产出 `syncd/web/dist/`（`index.html` + `assets/*`）。
把 **dist 的内容**复制到 `syncd/server/webdist/`（由仓库的构建步骤/父任务执行，本目录不代做）：

```bash
rm -rf ../server/webdist && mkdir -p ../server/webdist
cp -R dist/. ../server/webdist/
```

`syncd/server/main.go` 用 `//go:embed all:webdist` 把它嵌进单二进制，非 `/api` 路径一律回落
`index.html`。所以线上形态是**同一个端口同时给 API 和页面**，没有跨域、没有 CDN、离线可跑。

## 本地开发

```bash
# 终端 1：真服务端。它什么都不带地起——通道口令只能在页面上配（-channel-key 已删除）
cd syncd/server && go build -o /tmp/syncd . && \
  /tmp/syncd -listen 127.0.0.1:8899 -dsn sqlite:///tmp/s.db
# 终端 2：vite dev，/api 由 vite.config.ts 的 proxy 转发到 127.0.0.1:8899
cd syncd/web && npm run dev
```

`npm run preview` 是同一份 proxy，指向编译后的 `dist/`，用来验证产物本身。

跑 e2e（对着上面那个服务，或任意 `BASE=`）：

```bash
BASE=http://127.0.0.1:8899 npm run test:e2e
```

`roundtrip.mjs` 会**自己**用 `POST /api/channel` 把通道口令配下去（用的就是页面上那一路），
再断言清单能列出——所以它不依赖服务端是怎么被启动的。`DT_CHANNEL_KEY` 只用来换一句别的口令。
`npm run test:channel-page` 反过来：它演的是"服务什么都没配 → 页面配口令 → 存量信封当场建索引"
那台状态机。

## 页面

- **登录/注册**：账号在这里建；同步口令在 Mac 端「偏好设置 › 同步」里设，两者不是一回事，
  登录页写明了这里任何时候都不需要它。
- **概览**：`/api/healthz` 状态与方言、账号、当前信封版本号（取自 `GET /api/blob` 的 ETag）、
  生成配对码（大字显示 + 300 秒（5 分钟）倒计时 + 服务端 note）、
  **加密传输（通道密钥）**卡片（`GET/POST /api/channel`：状态徽章 + 指纹 + 保存/清除；
  口令是这一页唯一的入口，服务端不再有启动参数那一档）、设备列表（吊销）、
  同步历史（版本/时间/大小 + 「回退到这一版」）。
- **主机清单**：`GET /api/hosts` → 表格（名称/分组/主机:端口/登录用户/来源版本）+ 关键字筛选。
  读不到时显示固定说明，并把服务端中文理由原样带上。

## 「回退到这一版」的实测行为

`rollbackTo(revision)` 调 `POST /api/blob/rollback {"revision":N}`，返回
`200 {"revision":新版本}`（实测：第 2 版时回退到第 1 版 → 服务端变成第 3 版，
`GET /api/blob` 的 ETag 同步变成 3）。旧的 `PUT /api/blob` 写法已废弃——它只认设备令牌，
会话令牌会被拒成 `401 {"reason":"设备令牌无效或已吊销"}`，那正是之前那条路径的缺陷。

同一轮 e2e 还实测：会话令牌调 `GET /api/hosts` 得到裸数组且答复里不含写入时埋在
`profiles[].auth.password` 与 `secretVault` 里的 canary；匿名调 `/api/hosts` 得 401；
设备令牌调回退得 401（`请先登录`）；回退到不存在的版本得 404 `没有第 999 版`；
吊销设备后该设备写入得 401。

### 回退会把主机索引一起带回那一版（已实现）

`POST /api/blob/rollback` 落库后，如果那一版是通道信封且服务端当前有密钥，就顺手用它重建
`hosts` 表，所以 `GET /api/hosts` 跟着版本走，不会停在刚被撤销的那一版
（Go 侧 `TestRollbackReindexesHosts`、以及页面上「换一把打不开存量信封的密钥」那条路径都断言了：
索引一行不少，改对的那一刻立刻恢复）。

仍然**待实现**的只有一件事：展示「某一历史版本的主机清单」。服务端没有带 revision 的元数据接口
（例如 `GET /api/hosts/at/{revision}`），所以概览页对历史版本只给出元数据
（版本/时间/大小/写入设备）与回退入口，不再有把信封取回浏览器的「查看此版本」按钮。

## 安全约束（代码层面）

- 管理端不读信封内容：`getCurrentRevision()` 拿到 `200` 后立刻 `res.body?.cancel()`。
- 会话令牌只活在 `useApi.ts` 与 `sessionStore.ts`：不进 URL、不进 `console.*`。它会落
  `localStorage`（"刷新不掉登录"是拍板过的行为，带可用性探测、私密模式自动退回内存），
  `tests/gate.mjs` 的 C 组按这条红线断言，含新增的 `/api/hosts`、`/api/blob/rollback` 用法。
- 服务端返回的 `reason` 本来就是中文，UI 原样转达，不改写、不吞掉。
- 通道密钥（口令）**只进不出**：`ChannelState` 里没有任何密钥字段（服务端只回 `{enabled,source,fingerprint}`），
  `ChannelKeyCard.vue` 保存或清除之后立刻清空输入框，页面上不留副本；输入框是遮罩式的，因为它现在
  是一句人自己定的短密码。它是传输层密钥，**不是**端到端口令——这一页任何时候都不收集、也收集不到
  保护 SSH 凭据的那把口令（`type="password"` 全站恰好 4 处：登录 1 + 改登录口令 3 + 通道密钥 1，
  `tests/gate.mjs` 的 B 组按文件逐个钉死）。
- 占位/未实现的话统一说「待实现 / 尚未实现」。
