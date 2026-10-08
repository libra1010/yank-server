# Yank 同步服务（syncd）

Mac 终端 **Yank** 的自托管同步端：一个 Go 单二进制，收端到端加密的同步信封，
附带一个 Vue 管理台（登录、设备与配对码、同步历史与回退、主机/片段清单）。
它**不是**同步网盘，也**不是**凭据保险库 —— 它是那台 Mac 自己账户下的一个版本仓库。

- 协议口径（信封格式、每一个接口、每一个错误码）在 [`SPEC.md`](SPEC.md)，那份才是规范，这里只讲怎么跑起来。
- 管理台源码与它的负向门禁在 [`web/`](web/README.md)。
- 本目录就是一个独立 git 仓库的根，所以文内 `server/` `migrations/` 这样的路径都相对这里。

## 一分钟起起来（容器）

```bash
cp .env.example .env      # 填管理账号；不想让人自助注册就写 SYNCD_OPEN_SIGNUP=0
docker compose up -d --build
docker compose ps         # healthcheck 应变成 healthy
curl -s localhost:8791/api/healthz
```

建镜像有两份 Dockerfile，指令一模一样，只有基础镜像的地址不同：

- **`Dockerfile.cn`（`docker-compose.yml` 默认用它）**：基础镜像走华为云 SWR 的公共加速地址，
  Go 模块默认 `goproxy.cn` —— 出不了境的机器上唯一能一把建起来的那一份。
- **`Dockerfile`（标准版）**：`FROM golang:…-alpine` / `FROM alpine:…` 直接取官方 Docker Hub，
  `GOPROXY` 默认 `proxy.golang.org`。要它就用 `docker compose build` 前把 `dockerfile:` 指过来，
  或 `docker build -f Dockerfile .`。

两份不许各改各的：`scripts/check.sh` 去掉源地址与 `GOPROXY` 默认值后逐行比对指令部分，
漂了就红（少一份文件也算红，不会静默跳过）。换别的加速地址不必改文件：`MIRROR`、`GOPROXY`
两个 build-arg 就够。产物是 `CGO_ENABLED=0` 的纯静态二进制 + alpine 运行层，非 root（uid 10001）跑。

## 不装容器：单二进制

```bash
cd server && go build -o /usr/local/bin/syncd .   # Go ≥ 1.27，不需要 cgo
syncd -listen 127.0.0.1:8791 -dsn sqlite:///var/lib/syncd/dropterm-sync.db
```

管理台已经 `go:embed` 进二进制（`server/webdist/`），所以线上形态是**同一个端口同时给 API 和页面**：
没有跨域、没有 CDN、断网也能开页面。改了前端要在 `web/` 里 `npm run build`，再把 `dist/` 的内容
复制进 `server/webdist/`，然后重新 `go build`。

## 注入方式：命令行参数 > 环境变量 > 默认值

只有这五个变量，别的都不读。**通道口令不在这一列** —— 它是端到端第一层之外的那个传输密钥，
只在管理页面「概览 › 加密传输」里按账号配置，`-channel-key` 这类启动参数已经删掉
（一次重新部署不该改变数据能不能解开）。

| 环境变量 | 默认值 | 作用 | 对应参数 |
| --- | --- | --- | --- |
| `SYNCD_LISTEN` | `127.0.0.1:8791` | 监听地址。容器里镜像默认给的是 `0.0.0.0:8791`，因为端口映射穿过 127.0.0.1 会失效 | `-listen` |
| `SYNCD_DSN` | `sqlite://dropterm-sync.db` | 数据库，带方言前缀，见下一节 | `-dsn` |
| `SYNCD_OPEN_SIGNUP` | `1` | 写 `0` 关掉自助注册：`POST /api/register` 直接 `403`。已登录的会话与设备不受影响 | 无 |
| `SYNCD_ADMIN_USER` | 空（不建号） | **只在库里没有这个账号时**建号。已存在就一个字都不动 —— 否则页面上改过的口令会被一次重启悄悄换回来 | 无 |
| `SYNCD_ADMIN_PASSWORD` | 空 | 只被上面那一次建号用到；最短 10 字符，口令散列与页面注册同一套 argon2id。建完号建议从 `.env` 里删掉，以后只在页面改 | 无 |

口令类变量一个字都不进日志，也不写进镜像。`SYNCD_ADMIN_USER` 不合格（3–64 字符、不含空格）
或口令太短，服务直接拒绝启动并把原因写在 `log.Fatalf` 里，不会静默降级成"没账号"。

还有一个只在构建时生效的：`-ldflags "-X main.version=v1.2.3"`。它决定启动日志和
`GET /api/healthz` 报的版本号，`docker compose build --build-arg VERSION=…` 会带上它。

## 换数据库：DSN 的写法是驱动定的

前缀（`sqlite://` / `mysql://` / `postgres://`）只用来挑方言，**剩下那串的形状由驱动定**：
MySQL 要的是 go-sql-driver 那串（摘掉前缀后原样递给驱动），PostgreSQL 要的是完整 URL（连前缀一起递），
SQLite 是路径。两边不一致不是这里选的，别把它"顺手统一"成一种写法。

```
sqlite:///data/dropterm-sync.db
mysql://syncd:pw@tcp(db.internal:3306)/syncd            ← go-sql-driver 那一串，tcp(...) 不能省
postgres://syncd:pw@db.internal:5432/syncd?sslmode=disable   ← PG 只认 URL 形，keyword 串不支持
```

- SQLite 自动补 `?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)`，纯 Go 驱动，不需要 cgo。
- `postgresql://` 也接受，等价于 `postgres://`。
- 换后端不必改代码、不必手工跑 SQL：启动时 `CREATE TABLE IF NOT EXISTS` 一遍，缺列自己补
  （`ALTER TABLE … ADD COLUMN`，靠"这一列在不在"的探测，同一个库反复跑幂等）。

## 表结构：那两份 DDL 是导出的，不是手抄的

交付的建表文件只有两份，都是**全量**：`migrations/mysql.sql`、`migrations/postgres.sql`。
没有 sqlite 那份 —— 内嵌库由服务自己建，交付它没意义；也没有 `0002-…` 那种按版本递增的增量脚本
（老库缺的那几列由 `Migrate()` 启动时探测补齐，不靠人跑 SQL）。

正文 = 代码里 `schemaStatements(方言)` 的逐字输出，由 `sh migrations/regenerate.sh` 重新导出
（连每份文件顶上那段给 DBA 看的说明也是它生成的，所以没人会去手抄）。三道门盯着它，漂了就红：

- `TestBaselineDDLFilesMatchCode` —— 两份文件的正文与代码输出逐字节比对；
- `TestMigrationsDirHasOnlyFullDDL` —— 目录里只许这两份加一个导出脚本，往里塞增量文件会当场拦住；
- `TestModelsMatchBaselineDDL` —— 真库里的列集合与 `server/models.go` 的结构体逐表比对。

为什么建表不让 GORM 的 `AutoMigrate` 干（读写全都走 GORM，建表口径却不让它定）：
`Migrator().CreateTable` 取不出建表语句文本，"审的就是我跑的"守不住；而 AutoMigrate 会照它自己
从结构体推的类型判断去 ALTER 它认为不合的列 —— 手写 DDL 里信封正文是 `MEDIUMBLOB`（8 MiB），
一次启动悄悄把列收窄，是那种"部署看着好、第一次大推送才炸"的坏法。分工写在 `server/store.go` 顶上。

什么时候才需要手工执行 DDL：当你要求"连库账号不许自己建表"时，由 DBA 先跑那一份、再把 CREATE
权限收掉。其余情况不用 —— 升级路径上没有"先跑 SQL 再启动"这一步。

`0002`–`0004` 是历史上分三次加进去的列（认证方式、备注+跳板、片段表）。**新库不需要它们**：
0001 里已经含这三样；老库也不用手工跑 —— 服务启动时自己补列。留着的意义是让复核的人看见
"哪一格是什么时候加的、当时为什么加"，以及在没有服务权限的库里按顺序执行一遍。

## 数据库里到底存了什么

`users`（argon2id 校验值，不可逆）、`devices`（令牌只存 SHA-256）、`pair_codes`（一次性，读即删）、
`blobs` + `blob_history`（不透明字节，服务端解不开）、`hosts` + `snippets`（明文清单）、
`settings`（每账号的通道口令）。

**没有一列装 SSH 口令或私钥。** 凭据本体只在端到端信封里，那一层服务端没有密钥。明文清单收的是
白名单字段（主机：名称/分组/地址/端口/登录用户/认证方式/备注/跳板；片段：名称/分组/正文/占位符），
认证方式只是"口令 / 私钥 / agent"这种**方法名**；备注与片段正文在离开 Mac 之前先过端侧嗅探，
看着像口令的那一条整条换成说明文字。边界与理由见 `SPEC.md` §3、§5、§5.1。

`settings` 里那把通道口令是明文存的，所以**库文件本身就是密钥级秘密**：文件权限、备份介质、
DBA 的读取面都要按这个等级对待。

## 运维要点

- 端口：默认 `8791`，一个端口同时给 API 和页面。要不要只绑 `127.0.0.1`、怎么套 TLS，见下面
  「放在公网之前」那一节。
- 容量与保留：单个信封 ≤ 8 MiB；`blob_history` 每次写入后裁到最近 200 版，所以同步频率不会吃满磁盘。
- 限流：`/api/register|login|pair` 每 IP 每分钟 10 次。管理端登录口令 <10 字符或与原口令相同 → `400`。
- 备份：SQLite 就是那一个文件（连同 `-wal`）；MySQL/PG 用你自己的例行快照。恢复 = 换回库文件，
  客户端不需要重建账号（设备令牌与端到端口令都不在库里，前者只在签发时给过一次）。
- 端到端口令一旦丢失，服务端的数据**不可恢复** —— 这是设计，不是缺陷；找回来的唯一路径是另一台
  还解锁着的设备。
- 优雅退出：`SIGINT`/`SIGTERM` → `Shutdown`（10 秒预算），进行中的上传不会写坏半封信封。

## 放在公网之前

这个服务收的东西决定了它的暴露面要按"能看见别人服务器地址簿"来算：

1. **套反代 + TLS**（Caddy/nginx），进程本身只绑 `127.0.0.1` 或容器内网。Mac 客户端对 `http://`
   明文会警告并要求确认 —— 那不是装饰，是因为信封之外还有明文清单在同一个端口上走。
2. **关掉自助注册**：`SYNCD_OPEN_SIGNUP=0`。开着它 = 任何人都能在你这台机器上建账号并占用存储。
3. **库文件按密钥级秘密对待**：`settings` 表里存着每个账号的通道口令明文（这是"页面配置、立刻生效"
   换来的代价，见 `SPEC.md` §5）。快照、备份介质、能 `SELECT` 这张表的账号，都按这个等级算。
4. 即便如此，**公网部署也不会让服务端读到 SSH 口令**：那一层是端到端的，密钥只在客户端钥匙串里。
   这条边界不随部署形状变化，也不靠"我们放在内网"来成立。

## 自检

```bash
curl -s localhost:8791/api/healthz
# {"dialect":"sqlite","ok":true,"openSignup":true,"version":"dev"}
```

（这一串是实测抄回来的，不是拼的：`SYNCD_OPEN_SIGNUP=0` 那一档真的会把 `openSignup` 翻成 `false`，
而 `SYNCD_ADMIN_USER`/`SYNCD_ADMIN_PASSWORD` 建的号会在启动日志里留一句话 —— 口令本身一个字不进日志。）

`/api/healthz` 不带令牌、不返回任何秘密值，Docker 的 `HEALTHCHECK` 打的就是它（只 grep `"ok":true`，
换版本号不该让一个健康运行的容器变成 unhealthy）。

跑测试：

```bash
cd server && go test ./...                       # 临时目录里的新 sqlite 文件，不碰任何真实数据
SYNCD_TEST_DSN='mysql://root@tcp(127.0.0.1:3306)/syncd_check' go test ./...
SYNCD_TEST_DSN='postgres://me:pw@127.0.0.1:5432/syncd_check?sslmode=disable' go test ./...
```

指着外部库时请给一个**空的专用库**：它不替你清表。每一轮用的账号、设备、设置键都带随机后缀，
所以同一张库反复跑不会互相踩。

已经真跑过的后端（2026-10-06）：SQLite、MySQL 9.7.2、PostgreSQL 18.6 三方言全绿。这一条之所以要写出来，
是因为更早的版本里 `postgres://` 那条路从来没通过（方言名当驱动名递给了数据库），而整套测试全绿照不
出来 —— "文档写了支持"和"真连上去跑过"是两件事。Dockerfile 本身在开发机上没 build 过（那台机器没有
docker），构建步骤里的 `go test ./...` 会替它把关。

## 许可与仓库边界

服务端（本目录）以 **Apache-2.0** 开源（[`LICENSE`](LICENSE)，Copyright 2026 libra1010）；
Mac 终端 **Yank** 闭源，父目录的 `Sources/`、`tools/`、`docs/` 不在这个仓库里。
两边是两个 git 仓库、两个地址：本目录是公开那个的根，父目录那份不要公开。
`server/webdist/` 是 `web/` 源码的构建产物，跟着二进制一起发（这样 clone 下来 `go build` 就能跑起完整页面），
改前端请连源码一起提交，别只提交产物。
