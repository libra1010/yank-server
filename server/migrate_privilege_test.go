package main

// 线上那一档：表由 DBA 按 migrations/<方言>.sql 建好，应用账号只给读写。
//
// 以前 Migrate() 一上来就发 CREATE TABLE IF NOT EXISTS。那个 IF NOT EXISTS 是数据库自己判的，
// 而 PostgreSQL 在走到那句判断之前就要 schema public 的 CREATE 权限 —— 于是权限最小的线上账号
// 直接把服务起不来（SQLSTATE 42501），而 README 里"应用账号不必有建表权限"是写在纸上的承诺。
//
// 这里用文件权限模拟"没有 DDL 权限"：库文件设成只读，SELECT 照走、DDL 写不进。
// 先跑负向对照 —— 证明这个模拟真挡得住 DDL，否则下面那句"Migrate 成功"什么都说明不了。

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateNeedsNoDDLPrivilegesWhenSchemaExists(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "prod.db")
	store, err := Open("sqlite://" + dbPath)
	if err != nil {
		t.Fatalf("开库：%v", err)
	}
	defer store.Close()
	ctx := context.Background()

	// 第一步照旧是有权限的：先把表建起来，才有"表已齐"这个前提。
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("第一次 Migrate（账号能建表）：%v", err)
	}
	if got := store.missingTables(); len(got) != 0 {
		t.Fatalf("建完表还缺 %v：missingTables 这张名单和 schemaStatements 对不上了", got)
	}

	if err := os.Chmod(dbPath, 0o444); err != nil {
		t.Fatalf("设只读失败：%v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dbPath, 0o644) })

	// root 不受文件权限约束（CAP_DAC_OVERRIDE），这一档在 root 下模拟不出"没有建表权限"。
	// 说清楚而不是硬跑：硬跑的"通过"是假的，跳过则要写明是被环境挡了。
	if os.Geteuid() == 0 {
		t.Skip("以 root 跑：只读文件挡不住 DDL，这一档测不出东西（非 root 的开发机与 CI 会跑到）")
	}

	// 对照一：这个只读状态真发不出 DDL。
	if _, err := store.exec("CREATE TABLE probe_should_fail (x INTEGER)"); err == nil {
		t.Fatal("只读的库文件居然还能建表 —— 这一轮没模拟出\"没有建表权限\"，下面的通过不算数")
	} else {
		t.Logf("对照成立：DDL 被挡（%v）", err)
	}
	// 对照二：读写账号该有的 SELECT 还在，探表才谈得上"表已齐"。
	if !store.hasTable("users") {
		t.Fatal("只读之后读不到 users：这一轮连\"表已在\"都没成立")
	}

	if err := store.Migrate(ctx); err != nil {
		t.Errorf("表已齐时 Migrate 还是去碰了 DDL：%v —— 线上就是这一档，起不来的是服务", err)
	}
}

// 缺表时不许装成"跳过"：必须真去建，而且报错要点名缺哪几张、DBA 该跑哪份文件。
func TestMissingTablesAreNamedInTheError(t *testing.T) {
	store, err := Open("sqlite://" + filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatalf("开库：%v", err)
	}
	defer store.Close()
	missing := store.missingTables()
	if len(missing) == 0 {
		t.Fatal("空库里 missingTables 回了空：这条门会在\"表齐了\"和\"没表\"之间没有区分")
	}
	for _, want := range []string{"users", "blobs", "hosts", "snippets"} {
		found := false
		for _, m := range missing {
			if m == want {
				found = true
			}
		}
		if !found {
			t.Errorf("空库里没把 %q 报成缺表：实得 %v", want, missing)
		}
	}
}
