-- Yank syncd · 基线建表（PostgreSQL）
--
-- 这份文件是**导出的**，不是事实来源：事实来源是 server/store.go 里 Migrate() 用的那一份
-- schemaStatements("postgres")。改了表就重新导出正文（它只打印，不碰任何数据库）：
--
--     sh migrations/regenerate.sh
--
-- 那个脚本保留本段说明、只换第一条 CREATE 之后的正文。逐字对不上由
-- server/ddl_parity_test.go 判红，不靠人记得跑。
--
-- 为什么要单独出一份：DBA 得先看清这张库里有哪些表、哪些列，才敢把服务起起来；
-- "读代码里那串 Go 字面量"不是一种可复核的交付。
--
-- 什么时候才需要手工执行它：只有当你要求"连库账号不许自己建表"（生产库常这么管权限）时，
-- 由 DBA 先跑这一份、再把 CREATE 权限收掉。其余情况不用 —— syncd 每次启动都会
-- CREATE TABLE IF NOT EXISTS 一遍，缺表缺列自己补，升级路径上没有"先跑 SQL 再启动"这一步。
--
-- 口令与私钥永远不在这些表里：正文只在端到端信封里，服务端解不开（../SPEC.md §3、§5）。
-- 明文入库的只有两张清单表 —— hosts（主机、端口、用户名、认证方式）与 snippets（片段正文），
-- 这是 2026-10 拍板下来的口径，见 ../SPEC.md §5.1 与 0002/0003/0004 那三份迁移的说明。

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
