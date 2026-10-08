# Yank 同步协议 v1

三端（macOS 端 / Go 服务端 / Vue3 管理端）的唯一口径。任何一端改字段都要先改这份文件。

## 1. 威胁模型

- 服务端**只存不透明信封**：看不到主机名、用户名、口令、私钥。它能看到的是密文长度、时间、设备标识。
- 同步口令（passphrase）只在端侧和浏览器里出现，**永不上传、永不落库**。服务端连 KDF salt 都没有，无法离线爆破。
- 因此：口令丢失 = 数据不可恢复（服务端无法帮你重置内容，只能删）。UI 必须明说。
- 口令强度在端侧强制：≥ 12 字符或 ≥ 4 个词，否则不允许开启"口令随包同步"。

## 2. 信封（SyncEnvelope）

JSON，UTF-8，字段按字典序输出，日期 ISO8601（秒级精度），二进制字段是 base64（标准表、带 `=`）。

```json
{
  "cipher": "aes-256-gcm",
  "ciphertext": "<base64: ct || 16B tag>",
  "createdAt": "2026-10-01T09:00:00Z",
  "formatVersion": 1,
  "kdf": {
    "algorithm": "pbkdf2-sha512-cc",
    "keyLengthBytes": 32,
    "rounds": 1200000,
    "salt": "<base64: 16B>"
  },
  "nonce": "<base64: 12B>"
}
```

派生与加解密，逐字节规定：

1. `key = PBKDF2(PRF = HMAC-SHA-512, Password = UTF-8(passphrase) 不做任何归一化/trim,
   Salt = kdf.salt, c = kdf.rounds, dkLen = kdf.keyLengthBytes)`（RFC 8016 §5.2）。
2. `plaintext = AES-256-GCM(key, nonce, ct‖tag)`，AAD 为空；`ciphertext` 前段是 ct，**末 16 字节是 tag**。
3. 每次 seal 用新随机 salt + nonce；同一明文两次 seal 字节不同，属正常。
4. 校验顺序（先结构后算钱）：`formatVersion==1`、`cipher`/`kdf.algorithm` 字面匹配、
   `1000 ≤ rounds ≤ 5_000_000`、`keyLengthBytes==32`、`8 ≤ |salt| ≤ 128`、`|nonce|==12`、
   `|ciphertext| ≥ 16`、明文上限 8 MiB。全部通过后才允许派生密钥。
5. 解密失败**只返回一个错误**（"口令错误或数据被篡改"），不区分，避免在线探测口令的 oracle。

Go：`golang.org/x/crypto/pbkdf2.Key(pw, salt, c, 32, sha512.New)` + `crypto/cipher.NewGCM`。
浏览器：
```js
const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase),
                                           'PBKDF2', false, ['deriveKey']);
const key  = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: rounds,
                                             hash: 'SHA-512' }, base,
                                           { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
const pt   = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ctConcatTag);
```
WebCrypto 的 `decrypt` 入参正是 ct‖tag，与端侧 `ciphertext` 字段直接对齐。

## 3. 上传体（SyncUpload v2，2026-10-06 拍板）

**一行主机带一格自己的密文**：上传体不再是"一个不透明信封 ＋ 旁边挂两份明文数组"，而是主机与
片段各一个数组，每行**明文的只有服务端该看得见的那几格**，私有部分（口令、私钥、profileID、
端口转发规则……）作为该行自己的密文串内联在里面。

```json
{ "cipher": "aes-256-gcm",
  "createdAt": "2026-10-06T08:33:31Z",
  "formatVersion": 2,
  "kdf": { "algorithm": "pbkdf2-sha512-cc", "keyLengthBytes": 32,
           "rounds": 1200000, "salt": "<base64: 16B>" },
  "hosts": [ { "name": "生产库主", "group": "生产", "hostname": "10.0.0.2", "port": 22,
               "username": "dba", "authKind": "password", "notes": "周一凌晨备份", "jump": "",
               "secret": "<base64: 12B nonce ‖ ct ‖ 16B tag>" } ],
  "snippets": [ { "name": "清日志", "group": "", "body": "sudo journalctl --vacuum-size=50M",
                  "params": "", "updatedAt": "2026-10-06T08:33:30Z",
                  "secret": "<base64: 12B nonce ‖ ct ‖ 16B tag>" } ],
  "meta": "<base64: 12B nonce ‖ ct ‖ 16B tag>" }
```

- **一次上传只派生一次密钥**：顶层那一个 `kdf`（salt + rounds，端到端同步口令派生，参数与校验
  顺序完全照 §2）。每一格密文各自取新的 12 字节随机 nonce，拼接方式与 §2 逐字节一致
  （AES-256-GCM、AAD 为空、末 16 字节是 tag）。所以 20 台主机也只有 1 次 PBKDF2，而同一台主机的
  口令两次上传字节不同。
- 键序按字典序输出，日期 ISO8601 秒级，二进制一律标准 base64 带 `=`。
- `hosts[]` 明文只允许 §5.1 那 **8 个键 ＋ `secret`**；`snippets[]` 只允许那 **5 个键 ＋ `secret`**。
  多出来的键按 §5.1 同一份凭据词根表判：命中 → `400`，未知 → `400`，整次写入一起拒。
- 每一行的 `secret` 里是**这一行的私有部分**：口令本体 / 私钥正文 / 私钥口令，以及 `profileID`、
  `jump` 指向的那台主机的 UUID、端口转发规则（#83）、别名、颜色与背景设置、钥匙串账号名、
  私钥落盘路径。片段那一格的 `secret` 里是片段的 `id` 和**没被隐去的完整正文**。
- `meta` 里是**这一版的账本**：`revision`、`deviceID`、`updatedAt`、`aliases`、`tombstones`、
  `secretAccountsPending`。墓碑必须随这一包上行并被服务端原样存下（合并时取「本机账本 ∪
  两侧带出的墓碑」的并集），否则一侧删掉的条目会被另一侧的旧副本复活。老包没这个键按"没人删过"解。
- 关掉「口令随包同步」时，留在本机的那一行**没有 `secret` 键**（不是空串、不是空数组）；对端从
  `meta` 里的 pending 名单知道要重输一次。
- 服务端：只读那 8/5 个明文键建 `hosts` / `snippets` 索引；`secret` 与 `meta` 是**不透明串** ——
  不解析、不单独落列、不从任何 GET 回吐。整份原始字节照旧进 `blobs`，设备拉回去自己逐格解密。
  因此服务端读得到"你有哪些主机、用什么账号、走密码还是私钥"，读不到口令、私钥、UUID、转发规则、
  别名、墓碑 —— 后者从 v1 的"藏在整包信封里"变成 v2 的"藏在各行自己的密文里"，边界一寸没让。
- 私钥到端后写入 `~/Library/Application Support/Yank/Keys/<filename>`，权限 `0600`，
  `HostProfile.auth` 的 path 指向它；passphrase 进本机凭据库。目录不存在就先建，已存在同名文件
  且内容不同 → 不覆盖，报"该机器上已有一把同名私钥"。
- `revision` 是**该账号**的全局单调递增号，由服务端在 PUT 成功时返回并写回账本（在 `meta` 里）。
- **v1 只读不写**：`formatVersion` 缺席或为 1 的包（旧客户端）继续按 §5.1 的老形状解 —— 信封 ＋
  旁边挂的明文数组。新客户端一律只写 v2。同一服务上两代客户端可以并存，历史修订照旧可查、可回退。

## 4. 冲突口径

- 身份：`profile.id`（UUID）认"同一个对象"。
- 去重键：`hostname:port:username`（port 缺省 22，hostname 小写，username 原样）。两个不同 UUID 撞同一个键
  → 判为同一台服务器：逐字段取 `updatedAt` 新的一侧（相等取 `revision` 大的），**保留较早创建的 UUID** 作
  canonical，另一个写进 `aliases`。两端下次合并时按别名收敛，不产生重复条目。
- 删除优先：一侧删、一侧改 → 墓碑赢，但被改的一侧会在 UI 里留一条"你的修改被删除覆盖，可回退"。
- 任何自动合并都必须可回退：服务端保留历史信封，端侧合并前把本地清单落一份快照。

## 5. 传输层通道口令（可选，默认关）

目标：整包（含 §5.1 那两份明文清单）在网络上是一个不透明密文，服务端用**两端各自填的那句通道
口令**解开外层，把主机清单录入数据库（可按主机搜索、Web 控制台不输端到端口令就能看清单）；SSH 口令与私钥仍锁在端到端
信封里，服务端解不开。

`layer` 用来和第 3 节的上传体区分。**密文里装的是 §3 那一整包，外面一个明文字节都不许留**：
请求体只剩下面这几个通道自己的字段，`hosts` / `snippets` / `meta` 连同每行那格端侧密文全在
`ciphertext` 里面。（2026-10-06 修的就是这条：以前开了这一档，两份明文数组还挂在密文**外面**，
也就是这一档在网络上什么都没遮住。）

```json
{ "formatVersion": 1, "layer": "channel", "cipher": "AES-256-GCM",
  "kdf": { "algorithm": "pbkdf2-sha512-cc", "salt": "base64(16 随机字节)",
           "rounds": 210000, "keyLengthBytes": 32 },
  "iv": "base64(12 随机字节)", "ciphertext": "base64(明文 || 16 字节 tag)" }
```

- `kdf.algorithm = "pbkdf2-sha512-cc"`：密钥由口令经 PBKDF2-HMAC-SHA512 派生，**参数全是写死的**
  （21 万轮、32 字节、salt 16 字节）。salt 跟着信封走，所以对端不用问"你用了什么随机数"就能算出
  同一把；`rounds` 与 `keyLengthBytes` 必须等于这两个常量，否则按格式非法拒绝——不能让一个能连上
  端口的人决定服务端要派生多久。`ciphertext` 的拼接方式与第 3 节一致（密文‖tag，12B nonce，AAD 为空）。
- 这一版**不再写也不再读** `kdf.algorithm = "raw"`（两端各粘一把 32 字节的 hex/base64，64 个字符）。
  它既难抄又难核对，而且真实库里从没落过这种信封，所以直接删；同形状再来一律 `400`。
- 通道密文解开之后就是 §3 那一整包：**每一行主机自己带着那一格端侧密文**（同步口令派生，
  服务端没有这把密钥），所以服务端解得开外层、能列出主机，仍然读不出一个口令。v1 那套
  `secretVault` / `secretMaterial` 只读不写，v1 包里 `secretMaterial` 非空照旧 `400` 拒绝——
  这条不变量由两端共同守，不靠客户端自觉。
- 解开后服务端可读的字段与**不加密时完全同一份**：`hosts[]` 那 8 个明文键、`snippets[]` 那 5 个。
  这是要付的代价，写清楚：**服务端从此知道你有哪些主机、用什么账号登录、走密码还是私钥**，
  仍然不知道口令。profileID、别名、墓碑、端口转发规则在每行自己的密文格与 `meta` 里，读不到。
  `auth` 里判别名以外的东西（钥匙串账号名、私钥路径）服务端**读完即丢**：`hosts` 表只有
  `auth_kind` 这一列（`password` / `keyboard-interactive` / `private-key` / `agent`，认不出来
  就是空串、界面显示「未知」），`GET /api/hosts` 也绝不回吐账号名或路径。这条由
  `TestAuthKindNeverLeaksAccountPathOrSecret` 与 `TestChannelSecretBoundary` 双向守。
- **浏览器端同样看不到口令**：管理端不再有"在网页里输入端到端口令、本地解密整包"这条路（那等于
  把口令摊在浏览器里）。主机清单只从 `GET /api/hosts` 来，历史/回退只碰元数据。

服务端：

- 口令只有**一个**来源：管理页面按账号配的那一句（`settings` 表里 `channel:<userID>` 一行）。
  启动参数 `-channel-key` 与环境变量 `DROPTERM_CHANNEL_KEY` 已删除——"打开/关闭加密传输"不该是一次
  重新部署。每次写入都重新读这一行，所以页面改完立刻生效，不必重启服务端。
- 配了：解开外层 → **走和不加密传输一模一样的那条路**（同一份 §3 形状、同一套键名校验、同一张
  索引表，服务端不为这一档写第二份入库代码）→ `hosts` 表按 `(user_id, revision)` 整批覆盖 →
  原始外层字节照旧存 `blobs`。
  解不开（口令不符、格式非法）→ `400 通道密钥不匹配或未配置`，**不静默退回明文路径**。
- 没配：只当不透明密文存，行为与第 4 节之前完全一致；两种格式可在同一服务上共存。
- 页面上保存一句「打不开存量信封」的口令时，既有 `hosts` 索引一行都不动——写错口令不该毁掉清单；
  改对的那一刻服务端拿最新信封重建索引，用户不必重新推送。
- `GET /api/hosts` 返回库里那份主机清单（会话令牌或设备令牌均可），供控制台直接展示。它**不依赖
  第 5.1 节之外的任何开关**：没配通道口令时清单来自客户端明文上传的 `hosts` 数组，配了也一样
  （数组优先），响应头 `X-Inventory-Source` 说明这一份是从哪条路来的。
- 口令只进不出：`GET/POST /api/channel` 只认管理端会话令牌（设备令牌一律 `401`，App 无权改服务端），
  应答只有 `{enabled,source,fingerprint}`，任何时候都不回传口令本身；`source` 只会是 `page` 或 `none`。
- 指纹是 **SHA-256("yank-channel-v1|" + trim 之后的口令) 前 3 字节的大写十六进制**（6 个字符）。带域
  前缀是为了不和别的系统里同一句话撞值；三方（Go / Swift / 浏览器测试脚本）按同一口径各算一遍并互相对照，
  人工核对两端填的是不是同一句就靠它。注意指纹**不是**密钥的一部分，派生用的是口令原文 + 信封里的 salt。
- **代价写在明处**：页面配来的口令原样躺在 `settings` 表里，没有任何加盐或哈希。拿到库文件 = 拿到外层
  口令 = 读得出主机清单元数据（仍然读不出口令）。库文件的权限与备份就是这条链的边界。

客户端：偏好设置 → 同步 → 「加密传输（通道密钥）」开关 + 口令输入框（`NSSecureTextField`，星号回显）。
口令进钥匙串（`dropterm.sync.channel-key`），界面显示那 6 位指纹，用于人工核对两端一致；关掉开关只是
回到"服务端打不开信封"，第 5.1 节那份明文清单照旧上传、照旧可见——这是用户拍板的口径，不是这条链的漏洞。

机制空洞要说在前面：预共享密钥给的是机密性，不给前向保密，也不证明服务端身份；它不能替代
TLS——要防"中间人冒充你的同步服务"仍然要把服务地址放到 TLS 后面。它的实际收益是：即使有人
忘了上 TLS，即使服务端数据库被整库备份拿走，口令和私钥也不会跟着泄露。
## 5.1 明文清单元数据（常开，与通道密钥无关）

用户拍板（2026-10-03）：**不论是否启用第 5 节的通道加密**，服务端库里就该存着、界面上就该看得见
「名称 / 分组 / 主机:端口 / 登录用户 / 登录方式 / 备注 / 堡垒机」。2026-10-05 是同一句话的第二样：
管理端也要看得见**片段本身**，所以片段走同一条路、同一个白名单口径，只是换成另一个数组。

**这一节说的是"哪些键是明文"，不再是"明文挂在哪儿"**：v2 起 `hosts` 与 `snippets` 两个数组就是
§3 那个上传体本身，而启用 §5 的通道口令时它们连同每行的密文一起进通道密文 —— 明文只存在于
服务端解开外层之后、写库之前的那一步。没开通道口令，两个数组就是网络上看得见的样子。

```json
{ "formatVersion": 2, "cipher": "aes-256-gcm", "kdf": {…}, "createdAt": "…",
  "hosts":    [ { "name": "东京跳板", "group": "默认", "hostname": "10.0.0.9", "port": 22,
                  "username": "ops", "authKind": "password",
                  "notes": "（备注含疑似口令，已在本机隐去，未上传）", "jump": "",
                  "secret": "<端侧加密：口令/私钥/私钥口令 + profileID + 转发规则 + 账号名>" } ],
  "snippets": [ { "name": "重启 nginx", "group": "生产", "body": "systemctl restart nginx",
                  "params": "", "updatedAt": "2026-10-05T04:00:00Z",
                  "secret": "<端侧加密：片段 id + 未隐去的完整正文>" } ],
  "meta": "<端侧加密：revision / deviceID / 别名 / 墓碑 / pending 名单>" }
```

- `hosts` 行里明文只允许这 **8 个键**，另加一格 `secret`；`snippets` 行里明文只允许这 **5 个键**，
  另加一格 `secret`。出现别的键：命中凭据词根（`secret` 以外的那份词根表：`password` /
  `passphrase` / `vault` / `material` / `token` / `key` / `credential` / `privatekey`）→
  `400 主机清单里不得携带凭据字段`；其余未知键 → `400 清单数组形状不合法`。服务端是**整次写入
  拒绝**，不是"忽略那一格"：悄悄收下明文凭据是最糟的结局，它会让人以为口令还是加密的。
- `secret` 这一格服务端**只当不透明串**：不 base64 解码、不解析、不落单独的列、不从任何 GET
  回吐。它是 §2 那套 AES-256-GCM 的产物，密钥是端到端同步口令，服务端没有。
- `authKind` 是判别名（`password` / `keyboard-interactive` / `private-key` / `agent`），取值集合与
  §5 同一份；认不出来的一律折成空串，界面显示「未知」，服务端不猜。钥匙串账号名、私钥路径
  **不在明文键里**（它们在 `secret` 里，服务端读不到）。
- 缺席与清空是两件事：没有 `hosts` 键（老客户端）→ 库里清单保持原样，不当错误处理；
  `hosts: []` → 库里的行全部作废，否则"删掉最后一台主机"会在服务端永久留影。`snippets` 与
  `snippets: []` 各自同理，两张表互不牵连：清掉片段不会动主机行。
- `notes` 在人把口令写进备注时由**客户端本机**换成示例里那句隐去说明：命中"关键词＋值"
  （`password:` / `passphrase=` 这类形状且后面跟着 ≥4 字符实值）就整句替换，原备注只留在本机；
  不含值的（例如"口令在钥匙串"）原样上传——宁可少判，不做关键词大棒。
- `jump` 是堡垒机那一跳的目标（`user@host:port`），是地址不是凭据；直连传空串，界面显示「直连」。
- `body` 是**已经过端侧嗅探**的正文，服务端因此把它当普通字符串照原样存、不再判第二遍：命令行里
  的口令写法（`sshpass -p`、`--password `、`-p<字面量>` 这些）命中时整条正文换成
  「（正文含疑似口令，已在本机隐去，未上传）」，长过管理端那一格（端侧 `bodyLimit = 2040`）时换成
  「（正文过长，未在管理端展示；片段本身照常同步）」。两句都是端侧决定的，服务端那道
  `clampSnippetBody`（2048 rune）只是容量护栏。残留缺口写在明处：`mysql -p2222` 那种裸
  `-p<数字>` 谁都分不出是口令还是端口，不会被嗅探命中，别把真口令写成那个形状。
- `params` 是正文用到的占位符名（逗号分隔，如 `host,user`），是名字不是值；正文被隐去时它是管理端
  唯一还有信息量的一格。`updatedAt` 是 ISO8601 串，只用来排新旧（服务端不校验格式，只夹容量）。
- **v1 包只读**：`formatVersion` 为 1 或缺席时，仍是"信封对象 ＋ 旁边挂两个数组"的老形状，
  按同一份键名白名单与同一套 400 规则处理；两代客户端在同一服务上并存。老包里没有 `meta`，
  账本（含墓碑）在它自己的端到端信封里，照旧随原始字节存、由设备解。
- 代价写在明处：**这 13 格明文没有完整性保护**，开通道口令时它们在网络上是密文、在服务端库里
  仍是可读明文（服务端有通道口令，解得开外层）。拿到库文件的人读得出你有哪些主机、用什么账号、
  走密码还是私钥、存了哪些命令片段；拿到设备令牌的人可以伪造数组往清单里写任意内容（服务端只能
  校验键名，验不了真伪）。口令、私钥内容、profileID、别名、墓碑、转发规则仍锁在逐格密文里，
  这条边界一寸没让。要收紧就上 TLS、管住库文件权限与设备令牌。
- 谁来守：`syncd/server/inventory_test.go`（数组解析、凭据键 400、空数组清空、判别名不猜、
  `secret` 当不透明串、解析不碰密文，以及片段数组的同一组解析层断言）、
  `inventory_wire_test.go` 与 `snippet_inventory_test.go`（直接读 Swift 源对键名与字段集合，
  两端改名忘另一边时在 `go test` 就红）、`snippet_inventory_test.go`（端到端：没配通道口令也
  列得出片段、口令字面值搜不到、空数组清表、回退带着片段索引一起回）、
  `channel_inventory_test.go`（开通道口令时**外层没有任何明文数组**，服务端解开后入库结果与
  不加密逐字段相同）、`Checks_SyncChannel.swift`（客户端确实带、备注确实隐去、堡垒机确实成形、
  每行确实带一格解得开的密文、摘掉密文格信封照旧可解）、`tools/syncd-smoke.sh`（真客户端 →
  **没配通道口令**的真服务端 → `GET /api/hosts` 八字段逐项在、口令与账号名逐项不在）。

## 6. HTTP API

全部 `application/json`。令牌有两种：管理端**会话令牌**（`/api/login` 发，进程内存表，重启即失效）
与**设备令牌**（`/api/pair/exchange` 发）。`/api/register|login|pair/exchange|healthz` 匿名可调，
其余一律要 `Authorization: Bearer <token>`；权限按端点分——`PUT /api/blob` 只认设备令牌，
`/api/channel`、`/api/pair`、`/api/devices*`、`/api/blob/rollback`、`/api/password` 只认会话令牌，
`GET /api/blob|history|/api/blob/at/*`、`/api/hosts`、`/api/snippets` 两种都认。

| 方法 | 路径 | 作用 |
|---|---|---|
| POST | `/api/register` | `{user,password}` → `{user}`；口令 argon2id 哈希后存 |
| POST | `/api/login` | `{user,password}` → `{token,userId}`（管理端会话令牌） |
| POST | `/api/pair` | 已登录会话创建 `{code,expiresIn:300}`，一次性（换成功即删，第二次一律 401） |
| POST | `/api/pair/exchange` | `{code}` → `{deviceToken,deviceId}`；设备令牌只给写自己 blob 的权限 |
| PUT | `/api/blob` | 请求体是信封；`If-Match: <revision>` 乐观并发，不匹配返回 `409 {current}` |
| GET | `/api/blob` | 最新信封，`ETag: <revision>`；没有则 `204` |
| GET | `/api/blob/history` | `[{revision,deviceId,createdAt,bytes}]`（只有元数据） |
| GET | `/api/blob/at/<revision>` | 某个历史信封，供管理端解密查看/回退 |
| POST | `/api/blob/rollback` | `{"revision":N}`：服务端把那一带密文原样前滚成新版本（服务端读不懂内容），返回新 `revision`；`PUT /api/blob` 只认设备令牌，所以浏览器会话的回退必须走这条 |
| GET | `/api/devices` | `[{id,name,lastSeen,revision}]` |
| POST | `/api/devices/revoke` | `{deviceId}`；吊销设备令牌 |
| GET | `/api/hosts` | 库里的主机清单 `[{name,group,hostname,port,username,authKind,notes,jump,revision}]`；**永远 `200`**（没有就是空数组），不需要先启用通道密钥，见 §5.1。响应头 `X-Inventory-Source: stored\|empty` 只说明库里有没有 |
| GET | `/api/snippets` | 库里的片段清单 `[{name,group,body,params,updatedAt,revision}]`，最新修订在前、同修订按名字；与 `/api/hosts` 同权（会话令牌或设备令牌均可）、同样**永远 `200`**（没有就是空数组）、同样不需要先启用通道密钥，见 §5.1。`body` 是端侧嗅探过的那一份：命中疑似口令或过长时它是替换文本，不是原样命令 |
| GET | `/api/channel` | 会话令牌专属：`{enabled,source:"page"\|"none",fingerprint}`。**只报存在性与指纹，永不回传口令**；`flag` 那一档随启动参数一起删掉了 |
| POST | `/api/channel` | 会话令牌专属：`{key}`，`key` 是自己定的通道口令（trim 之后至少 8 个字符，中文一个字算一个）；空串＝清除本页配置（之后服务端只当不透明密文存）。太短 `400 通道密钥太短：至少 8 个字符`，成功返回最新状态并就地重建主机索引 |
| POST | `/api/password` | 会话令牌专属：`{oldPassword,newPassword}`，改的是**管理端登录口令**（与端到端口令无关，见 §7）。原口令错 `403`，新口令 <10 字符或与原口令相同 `400`，成功 `200 {reason}` 并把该账号**其他**浏览器会话全部作废（当前这张留着，设备令牌不受影响） |

约束：信封 ≤ 8 MiB；`/api/register|login|pair` 每 IP 每分钟 10 次；口令最少 10 字符。
未启用通道密钥时服务端**不解析信封**，只按 `(account, revision)` 存 `bytes`。

## 7. 部署

- 单二进制，`net/http` + `embed` 前端静态资源。默认 SQLite（纯 Go 的 `glebarez/sqlite`，内核是
  `modernc.org/sqlite`，无 cgo，所以 `CGO_ENABLED=0` 那条发布路照样打得出来）。
- `-dsn`（或 env `SYNCD_DSN`）换后端，前缀只用来挑方言，剩下的形状由驱动定：
  `sqlite://路径`、`mysql://user:pw@tcp(h:3306)/db`（go-sql-driver 那一串，`tcp(...)` 不能省）、
  `postgres://user:pw@host:5432/db?sslmode=disable`（PG 这一侧只认 URL 形，keyword 串不支持）。
- 存储层 2026-10-06 起读写走 GORM，但**建表口径仍由那一份手写 `schemaStatements` 说了算**：同一个
  来源既跑在启动迁移里，也由 `sh migrations/regenerate.sh` 导出成 `migrations/0001-baseline-<方言>.sql`
  给 DBA 复核。两道门盯着它：`TestBaselineDDLFilesMatchCode` 逐字节比那三份文件的正文与代码输出，
  `TestModelsMatchBaselineDDL` 逐表比列集合与结构体 —— 漂了就红。为什么不让 GORM 建表见 `store.go` 顶上那段。
- TLS 交给反代（Caddy/nginx）或 `-listen` 只绑 127.0.0.1；端侧对 `http://` 明文会警告并要求确认。
- 通道口令只有管理页这一个入口：服务不带任何密钥启动，在「概览 › 加密传输（通道口令）」里按账号配置；
  它原样存进 `settings` 表（`skey = channel:<userID>`，值是口令明文），所以库文件的属主与权限要按密钥级
  秘密对待。`-channel-key` / `DROPTERM_CHANNEL_KEY` 已在 2026-10-06 删除（一次重新部署不该是开关）。
