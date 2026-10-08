-- Yank syncd · 迁移 0003：主机清单补"备注"与"堡垒机"两列
--
-- 为什么要这两列：用户 2026-10-03 拍板——不论是否开通道加密，数据库里就该存着、界面上就该
-- 看得见「名称 / 分组 / 主机:端口 / 登录用户 / 登录方式 / 备注 / 堡垒机」。0002 只补了登录方式，
-- 这两列补上剩下两项。
--
-- 边界没有放松，也不可能放松：
--   · notes 存的是客户端上传的备注，且**含疑似口令的那条在客户端就被整句替换**成
--     「（备注含疑似口令，已在本机隐去，未上传）」，服务端收到的是这句替换文本；
--   · jump 存的是堡垒机这一跳的目标（形如 ops@10.0.0.9:22），它是"下一跳地址"，
--     不是那一跳的凭据；
--   · 口令本体、私钥内容、钥匙串账号名依旧一个字都不进这张表（SPEC §5、§5.1）。
--
-- 三方言写法一致，可直接执行。syncd 启动时 Migrate() 会先探列再 ALTER（store.go hasColumn），
-- 所以正常升级不需要手工跑这里；这份文件是给 DBA 审阅与手工建仓用的等价物。
-- 服务端对这三种数据库都只做"加列"，从不重建 hosts 表——清单在下一次推送时会被整体重写，
-- 所以补列不会丢任何端到端数据。

-- SQLite / MySQL / PostgreSQL 通用：
ALTER TABLE hosts ADD COLUMN notes VARCHAR(1024) NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN jump   VARCHAR(512)  NOT NULL DEFAULT '';

-- 首次启动的新库由 Migrate() 里的 CREATE TABLE 直接带上这三列（auth_kind + notes + jump）：
--   CREATE TABLE IF NOT EXISTS hosts (
--     user_id VARCHAR(32) NOT NULL, name VARCHAR(512) NOT NULL, host_group VARCHAR(512) NOT NULL,
--     hostname VARCHAR(512) NOT NULL, port INTEGER NOT NULL, username VARCHAR(512) NOT NULL,
--     auth_kind VARCHAR(24) NOT NULL DEFAULT '', notes VARCHAR(1024) NOT NULL DEFAULT '',
--     jump VARCHAR(512) NOT NULL DEFAULT '', revision INTEGER NOT NULL);
-- MySQL 版把索引一并写进表定义（它没有 CREATE TABLE IF NOT EXISTS 之外的 CREATE INDEX IF NOT EXISTS）：
--   , KEY hosts_user_rev (user_id, revision)

-- 存量行的 notes / jump 会停在空串，直到该账号下一次推送（PUT /api/blob）或管理端"保存通道密钥"
-- 触发 rebuildInventory 才回填。想让它们立刻出现，用客户端再同步一次即可。
-- 注意：备注与堡垒机只来自客户端上传的**明文清单数组**（SPEC §5.1）。老客户端不发这个数组，
-- 那么这两列会一直是空串——这不是丢数据，是那一版客户端根本没上传过。

-- 长度上限在服务端也夹了一道（clampChannelField），超长的值会被截断而不是把整次写入打挂。

-- 回滚：
--   ALTER TABLE hosts DROP COLUMN notes;   -- SQLite 3.35+；MySQL/PostgreSQL 同样支持
--   ALTER TABLE hosts DROP COLUMN jump;
-- 删列只影响管理页面的显示，端到端信封与备份表(blob_history)一个字节都不受影响。
