-- Yank syncd · 迁移 0004：新增片段清单表 snippets
--
-- 为什么要这张表：用户 2026-10-05 拍板——管理端要看得见片段本身，不只是"信封里有东西"。
-- 客户端从此在信封**旁边**再挂一个永远明文的 `snippets` 数组（SPEC §5.1），口径照 0003 那份
-- 主机清单：名称 / 分组 / 正文 / 用到的参数 / 更新时间进库，界面直接列。
--
-- 边界没有放松，也不可能放松：
--   · body 存的是**已经过端侧嗅探**的正文。命中疑似口令（`--password xxx`、`sshpass -p 'x'`、
--     `-p<字面量>` 这些命令行形态）时，整条正文在客户端就被换成
--     「（正文含疑似口令，已在本机隐去，未上传）」；长过管理端那一格时换成
--     「（正文过长，未在管理端展示；片段本身照常同步）」。服务端收到的是这两个替换文本之一
--     或原样命令，它不再判第二遍——判了也不会更严，只会把端侧的口径改成服务端自己的；
--   · params 是正文用到的占位符名（`host,user`），是名字不是值；正文被隐去时它是管理端唯一
--     还有信息量的一格；
--   · 片段的 id、没被隐去的完整正文、口令本体、私钥内容照旧一个字都不进这张表——它们只在
--     端到端信封里（SPEC §3、§5、§5.1），服务端解不开。
--
-- 这是**新表**，不是加列：老库第一次启动时 Migrate() 里的 CREATE TABLE IF NOT EXISTS 会自动建它
-- （store.go 的 snippetsDDL），**不需要 DBA 手工执行本文件**。这份是给审阅、留档与手工建仓用的
-- 等价物；正常升级路径上没有"先跑 SQL 再启动"这一步。
-- 与 0002/0003 的区别要说清：那两次给已存在的 hosts 补列（hasColumn 探到缺才 ALTER），这一次
-- 没有可补的列，只有整张新表；补列会留下空串，新表则在一开始就是空的。
--
-- 三方言通用（SQLite / MySQL / PostgreSQL 逐字相同，可直接执行）：
CREATE TABLE IF NOT EXISTS snippets (
  user_id       VARCHAR(32)  NOT NULL,
  name          VARCHAR(512) NOT NULL,
  snippet_group VARCHAR(512) NOT NULL,
  body          VARCHAR(2048) NOT NULL,
  params        VARCHAR(512) NOT NULL DEFAULT '',
  updated_at    VARCHAR(40)  NOT NULL DEFAULT '',
  revision      INTEGER      NOT NULL
);
CREATE INDEX IF NOT EXISTS snippets_user_rev ON snippets (user_id, revision);

-- 列名与容量的两处讲究：
--   · snippet_group 而不是 group：GROUP 是 SQL 保留字，而这份 DDL 要在三种方言上逐字跑通
--     （hosts 表里 host_group 是同一个理由）。
--   · body 给 2048，其余字段沿用 hosts 那一档 512：正文是命令，截断过的命令抄回去跑是另一码事。
--     服务端这道 clamp 只管容量（别让一句兆级字符串把列撑爆、把整次写入打挂），不管语义；
--     语义上"过长就不给看"由端侧决定（SnippetInventory.bodyLimit = 2040，刻意比 2048 小，
--     给替换文本留余量）。这条容量对比由 TestSwiftSendsTheSnippetKeyGoReads 盯着。
--     updated_at 是 RFC3339 文本（全库同一套时间写法，见 store.go 的 ts/stampArgs），
--     40 个字符用不满，夹一下同样是容量护栏而不是格式校验。
--   · 没有主键，只有 (user_id, revision) 一个索引：整表按账号被 REPLACE，查询只有"列我的清单"
--     一种形状，与 hosts 保持一致。
--
-- MySQL 版把索引写进表定义里（它没有 CREATE INDEX ... IF NOT EXISTS）：
--   CREATE TABLE IF NOT EXISTS snippets ( … , KEY snippets_user_rev (user_id, revision))
-- PostgreSQL 与 SQLite 走上面那两条语句的原样。
--
-- 存量行什么时候才有：这张表新建好就是空的。片段只有两个来源，且都只认客户端明文上传的那个
-- 数组——该账号下一次推送（PUT /api/blob）时整批写入，或管理端"保存通道密钥"/回退触发
-- rebuildInventory 时就地重数一遍。老客户端不发这个数组，那它就一直是空的；这不是丢数据，
-- 是那一版客户端根本没上传过片段。
--
-- 回滚：
DROP TABLE IF EXISTS snippets;
-- 删表只影响管理页面的片段列。端到端信封、blobs 与 blob_history 一个字节都不受影响——
-- 片段的本体从来都在信封里，这张表只是它的一份派生视图，下一次推送会原样长回来。
