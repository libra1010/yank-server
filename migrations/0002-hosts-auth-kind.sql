-- Yank syncd · 迁移 0002：主机清单增加"认证方式"一列
--
-- 为什么要这一列：用户拍板「服务端可以看主机、端口、用户名，以及是私钥还是密码」，
-- 但口令本体永远不进这一列，也不进服务端的任何地方（它锁在客户端解不开的外层信封里）。
-- 存的是判别名（password / keyboard-interactive / private-key / agent），
-- 不是账号名、不是私钥路径 —— 那两个字段在客户端上传的清单里也存在，服务端读完即丢。
--
-- 三方言写法相同，可直接执行；syncd 启动时 Migrate() 会自己补这一列（探测列在不在，
-- 不在才 ALTER），所以手工执行只是给 DBA 看的等价物。
--
-- 回滚：清单表在下一次推送时会被整体重写，删列不丢端到端数据；真要回退见文件末尾。

-- SQLite / MySQL / PostgreSQL 通用：
ALTER TABLE hosts ADD COLUMN auth_kind VARCHAR(24) NOT NULL DEFAULT '';

-- 存量行的 auth_kind 会停在空串（"未知"），直到下一次推送或"保存通道密钥"时重建索引
-- （handlers_admin.go 保存密钥当下会用最新信封重跑 HostsFromChannel）。
-- 想立刻回填，就用客户端对该账号再推一次：PUT /api/blob。

-- 已建库的新库路径（首次启动，无表）由 Migrate() 里的 CREATE TABLE 直接带上这一列：
--   CREATE TABLE IF NOT EXISTS hosts (
--     user_id VARCHAR(32) NOT NULL, name VARCHAR(512) NOT NULL, host_group VARCHAR(512) NOT NULL,
--     hostname VARCHAR(512) NOT NULL, port INTEGER NOT NULL, username VARCHAR(512) NOT NULL,
--     auth_kind VARCHAR(24) NOT NULL DEFAULT '', revision INTEGER NOT NULL);

-- 回滚：
--   ALTER TABLE hosts DROP COLUMN auth_kind;   -- SQLite 3.35+ 支持；更早的 sqlite 需重建表
