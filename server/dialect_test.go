// 三方言的实测入口。
//
// 为什么非要有这一条：PostgreSQL 这条路从来没人真跑过 —— 存储层把方言名直接当驱动名递给
// 数据库，而 pgx 注册的是另一个名字，于是 postgres://… 开局就死在 unknown driver。
// 三方言的 DDL 打印得逐字正确、测试整套全绿，都没有替这个字付过钱。
// 这个测试就是那一下"真连上去跑一遍"：跑的是存储层每一条 GORM 读写，包括三种方言各自的
// 建表语句（MySQL 把索引写进表定义、BYTEA/MEDIUMBLOB 这三种 BLOB 写法）、无主键表的
// 整体替换、复合主键的历史行，以及中文正文进得去出得来。
//
//	# SQLite（默认：落到临时目录里的一个新文件，不碰任何真数据）
//	go test ./...
//	# PostgreSQL（先建一个空的检查库，别指到生产库上）。PG 这一侧只认 URL 形，
//	# 而且 ?sslmode=disable 这一串是有意的：它就是曾经被 DSN 启发式读歪的那一种。
//	CREATE DATABASE syncd_check; \
//	SYNCD_TEST_DSN='postgres://me:pw@127.0.0.1:54330/syncd_check?sslmode=disable' go test ./...
//	# MySQL（DSN 是 go-sql-driver 那一串的写法，tcp(...) 不能省，前缀摘掉后原样交给驱动）
//	SYNCD_TEST_DSN='mysql://syncd:pw@tcp(127.0.0.1:3306)/syncd' go test ./...
//
// 指着外部库跑时，每一轮用的账号、设备、设置键都是随机后缀，所以同一张库反复跑不会互相踩；
// 但它不会替你清表 —— 那应当是一次 DROP DATABASE / 建一个专用库的事。
//
// 已经真跑过的两侧（2026-10-06，都是本机临时集群，端口与生产无关）：PostgreSQL 18.6、
// MySQL 9.7.2。三个测试（表可查 / 全链路读写 / 列集合对得上结构体）在两边各自全绿。
// 这条记录存在的理由：换 GORM 之前 postgres:// 那条路从来没通过，而门禁全绿照不出来 ——
// "文档里写了支持"和"真连上去跑过"是两件事。
package main

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func dialectStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("SYNCD_TEST_DSN")
	if dsn == "" {
		dsn = "sqlite://" + filepath.Join(t.TempDir(), "dialect-check.db")
		t.Logf("SYNCD_TEST_DSN 没给：这一轮跑的是临时 sqlite 文件（%s）", dsn)
	} else {
		t.Logf("这一轮跑的是 %s 那一侧的真实后端", dsn)
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("Open(%s)：%v", dsn, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate(%s)：%v", dsn, err)
	}
	return store
}

// 建表语句里有的那些表，必须一张都不差地真能查 —— 导出的 migrations/{mysql,postgres}.sql
// 和跑着的这份 schema 是同一事实来源的两个出口，这里钉它一次。
func TestDialectTablesAllQueryable(t *testing.T) {
	store := dialectStore(t)
	ctx := context.Background()
	names := regexp.MustCompile(`CREATE TABLE IF NOT EXISTS (\w+)`).FindAllStringSubmatch(mustDDL(t, store.kind), -1)
	if len(names) < 6 {
		t.Fatalf("从建表语句里只认出 %d 张表，这条门本身坏了", len(names))
	}
	for _, m := range names {
		var one int
		if err := store.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM "+m[1]).Scan(&one); err != nil {
			t.Errorf("表 %s 查不动：%v", m[1], err)
		}
	}
	t.Logf("%s：建表语句里的 %d 张表全部可查", store.kind, len(names))
}

func mustDDL(t *testing.T, kind string) string {
	t.Helper()
	statements, err := ddlFor(kind)
	if err != nil {
		t.Fatalf("ddlFor(%s)：%v", kind, err)
	}
	return strings.Join(statements, "\n")
}

func TestDialectRoundTrip(t *testing.T) {
	store := dialectStore(t)
	ctx := context.Background()
	suffix := randomID(8)
	userID, other := "u-"+suffix, "u2-"+suffix
	now := time.Now().UTC().Truncate(time.Second)

	for _, id := range []string{userID, other} {
		if err := store.CreateUser(ctx, id, id+"@example", "hash-"+id, now); err != nil {
			t.Fatalf("建账号 %s：%v", id, err)
		}
	}
	gotName, gotHash, err := store.UserByName(ctx, userID+"@example")
	if err != nil || gotName != userID || gotHash != "hash-"+userID {
		t.Fatalf("按名字读账号回 %q/%q（%v），要 %q", gotName, gotHash, err, userID)
	}
	if err := store.SetPasswordHash(ctx, userID, "rotated"); err != nil {
		t.Fatalf("改口令散列：%v", err)
	}
	if got, err := store.PasswordHash(ctx, userID); err != nil || got != "rotated" {
		t.Fatalf("读回口令散列 %q（%v）—— 库里那一列没写进去或读不出来", got, err)
	}

	// 设备：令牌只存散列，读出来的是散列那一条；最后停用要真的停用。
	devID := "d-" + suffix
	if err := store.AddDevice(ctx, devID, userID, "公司的 Mac", "tok-"+suffix, now); err != nil {
		t.Fatalf("建设备：%v", err)
	}
	if got, owner, err := store.DeviceByTokenHash(ctx, "tok-"+suffix); err != nil || got != devID || owner != userID {
		t.Fatalf("按令牌找设备：%q/%q（%v）", got, owner, err)
	}
	seen := now.Add(90 * time.Second)
	if err := store.TouchDevice(ctx, devID, seen); err != nil {
		t.Fatalf("记一次在线：%v", err)
	}
	devices, err := store.ListDevices(ctx, userID)
	if err != nil || len(devices) != 1 {
		t.Fatalf("设备表回 %d 条（%v）", len(devices), err)
	}
	if devices[0].Name != "公司的 Mac" || devices[0].LastSeen == nil || devices[0].Revoked {
		t.Errorf("设备那一条不对：%+v —— 中文名进得去出得来吗？", devices[0])
	}
	if err := store.RevokeDevice(ctx, userID, devID); err != nil {
		t.Fatalf("停用设备：%v", err)
	}
	if _, _, err := store.DeviceByTokenHash(ctx, "tok-"+suffix); err == nil {
		t.Error("停用之后按令牌还能找出设备 —— 那一条 REVOKE 没生效")
	}

	// 配对码：一次性的，用过第二次就不认。
	codeHash := "code-" + suffix
	if err := store.PutPairCode(ctx, codeHash, userID, now.Add(5*time.Minute)); err != nil {
		t.Fatalf("存配对码：%v", err)
	}
	if got, err := store.TakePairCode(ctx, codeHash, now); err != nil || got != userID {
		t.Fatalf("用配对码得到 %q（%v）", got, err)
	}
	if _, err := store.TakePairCode(ctx, codeHash, now); err == nil {
		t.Error("配对码被用了第二次 —— 一次性这条在方言之间漏了")
	}
	if _, err := store.TakePairCode(ctx, "code-没有这个东西", now); err == nil {
		t.Error("不存在的配对码也放行？")
	}

	// 信封正文：带 0x00 与非法 UTF-8 的一串，三种 BLOB 写法都得原样吐回来。
	body := append([]byte{0x00, 0xff, 0xfe}, []byte("密文样子的那一串")...)
	rev1, err := store.PutBlob(ctx, userID, devID, body, 0)
	if err != nil || rev1 != 1 {
		t.Fatalf("第一次推送回 revision=%d（%v），要 1", rev1, err)
	}
	if _, err := store.PutBlob(ctx, userID, devID, []byte("旧的"), 0); err != ErrStaleWrite {
		t.Errorf("expect 打错了却回了 %v —— 乐观锁这条在 %s 上不成立", err, store.kind)
	}
	rev2, err := store.PutBlob(ctx, userID, devID, []byte("第二版正文"), 1)
	if err != nil || rev2 != 2 {
		t.Fatalf("第二次推送回 revision=%d（%v），要 2", rev2, err)
	}
	latest, err := store.LatestBlob(ctx, userID)
	if err != nil || string(latest.Body) != "第二版正文" || latest.Revision != 2 {
		t.Fatalf("最新一版回 %+v（%v）", latest, err)
	}
	old, err := store.BlobAt(ctx, userID, 1)
	if err != nil || !equalBytes(old.Body, body) {
		t.Fatalf("回滚到第 1 版取回 %+v（%v）—— 那一串 0x00/0xff 是不是被哪一侧吞了", old, err)
	}
	history, err := store.ListHistory(ctx, userID, 10)
	if err != nil || len(history) != 2 || history[0].Revision != 2 || history[0].Bytes != len("第二版正文") {
		t.Fatalf("历史表回 %+v（%v）—— 顺序或字节数不对", history, err)
	}
	if n, err := store.PruneHistory(ctx, userID, 1); err != nil || n != 1 {
		t.Fatalf("裁历史删了 %d 行（%v），要 1 行", n, err)
	}

	// 主机清单与片段清单：明文那两张表，中文、空串、0 端口都得原样。
	hosts := []HostRow{
		{Name: "生产库", Group: "生产", Hostname: "db.internal", Port: 5432, Username: "ops",
			AuthKind: "private-key", Notes: "只在 VPN 里连得到", Jump: "ops@bastion.example:22"},
		{Name: "空的", Group: "", Hostname: "10.0.0.9", Port: 22, Username: "root",
			AuthKind: "", Notes: "", Jump: "", Revision: 3},
	}
	if err := store.ReplaceHosts(ctx, userID, 3, hosts); err != nil {
		t.Fatalf("整体换主机表：%v", err)
	}
	gotHosts, err := store.ListHosts(ctx, userID)
	if err != nil || len(gotHosts) != 2 {
		t.Fatalf("读主机表回 %d 条（%v）", len(gotHosts), err)
	}
	if gotHosts[0].Name != "生产库" || gotHosts[0].Port != 5432 || gotHosts[0].AuthKind != "private-key" ||
		gotHosts[0].Notes != "只在 VPN 里连得到" || gotHosts[0].Jump != "ops@bastion.example:22" {
		t.Errorf("主机那一条读回来变了样：%+v", gotHosts[0])
	}
	// 整体替换的"整体"：清单里少了一台，库里就必须少一行，不许留墓碑之外的残行。
	if err := store.ReplaceHosts(ctx, userID, 4, hosts[:1]); err != nil {
		t.Fatalf("第二次整体换主机表：%v", err)
	}
	if again, err := store.ListHosts(ctx, userID); err != nil || len(again) != 1 {
		t.Fatalf("删掉一台之后再读，回 %d 条（%v）—— 旧行没被清掉", len(again), err)
	}

	snips := []SnippetRow{{Name: "看日志", Group: "本机", Body: "journalctl -u nginx -n 200",
		Params: "host", UpdatedAt: "2026-10-06T12:00:00Z"},
		{Name: "长正文没格子", Group: "", Body: strings.Repeat("x", 900), Params: "", UpdatedAt: ""}}
	if err := store.ReplaceSnippets(ctx, userID, 5, snips); err != nil {
		t.Fatalf("整体换片段表：%v", err)
	}
	gotSnips, err := store.ListSnippets(ctx, userID)
	if err != nil || len(gotSnips) != 2 {
		t.Fatalf("读片段表回 %d 条（%v）", len(gotSnips), err)
	}
	if gotSnips[0].Body != "journalctl -u nginx -n 200" || gotSnips[0].Params != "host" ||
		gotSnips[0].UpdatedAt != "2026-10-06T12:00:00Z" {
		t.Errorf("片段读回来变了样：%+v", gotSnips[0])
	}

	// 设置表那一格：列名是 skey，不是 KEY（MySQL 里 KEY 是保留字）。
	key := "channel/" + suffix
	if err := store.SetSetting(ctx, key, "值一"); err != nil {
		t.Fatalf("写设置：%v", err)
	}
	if v, err := store.GetSetting(ctx, key); err != nil || v != "值一" {
		t.Fatalf("读设置回 %q（%v）", v, err)
	}
	if err := store.SetSetting(ctx, key, "值二"); err != nil {
		t.Fatalf("改设置（那是 UPSERT 的一条）：%v", err)
	}
	if v, err := store.GetSetting(ctx, key); err != nil || v != "值二" {
		t.Fatalf("改过之后读到 %q（%v）—— 覆盖没生效", v, err)
	}
	if err := store.DeleteSetting(ctx, key); err != nil {
		t.Fatalf("删设置：%v", err)
	}
	// 删掉之后读到的是空串：这一条按 store.go 里写明的口径（"没配过"和"配成空"一样对待），
	// 不是"读不到就报错"。
	if v, err := store.GetSetting(ctx, key); err != nil || v != "" {
		t.Errorf("删掉的设置读回 %q（%v），要空串", v, err)
	}

	// 别的账号不许看见这条数据：每一张表都按 user_id 隔开。
	if otherHosts, err := store.ListHosts(ctx, other); err != nil || len(otherHosts) != 0 {
		t.Errorf("另一个账号读到了 %d 条主机（%v）", len(otherHosts), err)
	}
	if b, err := store.LatestBlob(ctx, other); err == nil && b != nil {
		t.Errorf("另一个账号读到了信封：%+v", b)
	}
	t.Logf("%s：账号/设备/配对码/信封与历史/主机/片段/设置 全跑通", store.kind)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// 建表语句（migrations/{mysql,postgres}.sql 就是从这一处打印的）和 models.go 的结构体，
// 各说一遍"这张表有哪些列"。两边漂一次的症状是"部署看着好好的、第一次真读写才炸在某一列上"，
// 而且大概率炸在 PG 那侧 —— sqlite/mysql 常年真跑，PG 那条今年才刚把驱动名接对。
// 所以这里不比文字、比**真库里长出来的列**：Migrate() 照 DDL 建完表，再逐表问一遍列集合，
// 和结构体推导出来的名字对得上才算数。给了 SYNCD_TEST_DSN 就在 mysql/pgsql 上同样走一遍。
func TestModelsMatchBaselineDDL(t *testing.T) {
	store := dialectStore(t)
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate：%v", err)
	}
	for _, model := range everyModel() {
		stmt := &gorm.Statement{DB: store.g}
		if err := stmt.Parse(model); err != nil {
			t.Fatalf("%T 的 schema 解析不了：%v", model, err)
		}
		table := stmt.Schema.Table
		if !store.g.Migrator().HasTable(model) {
			t.Errorf("表 %s 没被建出来：DDL 与结构体有一边在说谎", table)
			continue
		}
		types, err := store.g.Migrator().ColumnTypes(model)
		if err != nil {
			t.Errorf("读 %s 的列失败：%v", table, err)
			continue
		}
		got := map[string]bool{}
		for _, col := range types {
			got[col.Name()] = true
		}
		for _, field := range stmt.Schema.DBNames {
			if !got[field] {
				t.Errorf("%s：结构体说有 %s 这一列，库里没有（DDL 那份文件里也没有）", table, field)
			}
			delete(got, field)
		}
		for extra := range got {
			// 多出来的列不是错（老库升级留下的、或 GORM 自己塞的），但必须看得见：
			// 一旦是 id/created_at/deleted_at 那一类，说明有人给结构体嵌了 gorm.Model。
			t.Logf("%s：库里多一列 %s（不在结构体里）", table, extra)
		}
	}
}
