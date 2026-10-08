-- Yank syncd · 全量建表语句（PostgreSQL）
--
-- 这一份是**导出的**，不是事实来源：事实来源是 server/store.go 里的 schemaStatements("postgres")。
-- 重新导出：sh migrations/regenerate.sh（只打印，不碰任何数据库）。逐字对不上由
-- server/ddl_parity_test.go 判红，不靠人记着跑。
--
-- 什么时候真要手工跑它：只有"连库账号被禁止建表"的生产库 —— DBA 先审这一份、自己建。
-- 正常升级路径不需要：服务启动时 Migrate() 自己 CREATE TABLE IF NOT EXISTS，
-- 老库缺的那几列（auth_kind / notes / jump）也是它探测着补，所以这里没有按版本递增的增量脚本。
--
-- 审表时可以顺手确认的边界（口令与私钥在任何一列都不该出现）：
--   · hosts.auth_kind 存判别名（password / keyboard-interactive / private-key / agent），
--     不是登录账号名，也不是私钥路径 —— 那两个字段服务端读完即丢；
--   · hosts.notes 与 snippets.body 是端侧嗅探过的内容，命中疑似口令的那条在离机前就被整句替换；
--   · blobs.payload 与历史版本是端到端信封密文，服务端不解析、不落列、任何 GET 都不回吐；
--   · settings 里那一格通道口令是**原文**存的（外层只挡"读得清主机地址，读不出 SSH 口令"），
--     所以库文件本身要当凭据级资产对待 —— 这句必须写在交付说明里，不是吓人的。
CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(32) PRIMARY KEY, name VARCHAR(190) NOT NULL, pw_hash VARCHAR(255) NOT NULL,
			created_at VARCHAR(32) NOT NULL, UNIQUE (name));
CREATE TABLE IF NOT EXISTS devices (
			id VARCHAR(40) PRIMARY KEY, user_id VARCHAR(32) NOT NULL, name VARCHAR(120) NOT NULL,
			token_hash VARCHAR(64) NOT NULL, created_at VARCHAR(32) NOT NULL, last_seen VARCHAR(32),
			revoked INTEGER NOT NULL DEFAULT 0, UNIQUE (token_hash));
CREATE TABLE IF NOT EXISTS pair_codes (
			code_hash VARCHAR(64) PRIMARY KEY, user_id VARCHAR(32) NOT NULL,
			expires_at VARCHAR(32) NOT NULL, used_at VARCHAR(32));
CREATE TABLE IF NOT EXISTS blobs (
			user_id VARCHAR(32) PRIMARY KEY, revision INTEGER NOT NULL, device_id VARCHAR(40) NOT NULL,
			body BYTEA NOT NULL, created_at VARCHAR(32) NOT NULL);
CREATE TABLE IF NOT EXISTS blob_history (
			user_id VARCHAR(32) NOT NULL, revision INTEGER NOT NULL, device_id VARCHAR(40) NOT NULL,
			body BYTEA NOT NULL, created_at VARCHAR(32) NOT NULL, UNIQUE (user_id, revision));
CREATE TABLE IF NOT EXISTS settings (
			skey VARCHAR(64) PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hosts (
			user_id VARCHAR(32) NOT NULL, name VARCHAR(512) NOT NULL, host_group VARCHAR(512) NOT NULL,
			hostname VARCHAR(512) NOT NULL, port INTEGER NOT NULL, username VARCHAR(512) NOT NULL,
			auth_kind VARCHAR(24) NOT NULL DEFAULT '', notes VARCHAR(1024) NOT NULL DEFAULT '',
			jump VARCHAR(512) NOT NULL DEFAULT '', revision INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS hosts_user_rev ON hosts (user_id, revision);
CREATE TABLE IF NOT EXISTS snippets (
			user_id VARCHAR(32) NOT NULL, name VARCHAR(512) NOT NULL, snippet_group VARCHAR(512) NOT NULL,
			body VARCHAR(2048) NOT NULL, params VARCHAR(512) NOT NULL DEFAULT '',
			updated_at VARCHAR(40) NOT NULL DEFAULT '', revision INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS snippets_user_rev ON snippets (user_id, revision);
