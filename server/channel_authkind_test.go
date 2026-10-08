package main

// 主机清单里的"认证方式"。用户拍板的边界是：服务端可以知道这台是密码登录还是私钥登录，
// 但永远拿不到口令、私钥内容、钥匙串账号名。这一组检查就钉在这条线上：
// 判别名要读得到（读不到就等于用户说的"什么都看不了"），而它旁边的每一个字都要漏不出去。

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Swift 的 Codable 对一个枚举带值 case 写成 {"case":{"label":value}}，不带值的 case
// 写成裸字符串 "agent"。四种形状都按客户端真实产出的样子喂进去。
func TestAuthKindReadsEverySwiftCaseShape(t *testing.T) {
	cases := []struct {
		name string
		auth any
		want string
	}{
		{"password", map[string]any{"password": map[string]any{"secretAccount": "ssh:db-01:admin"}}, "password"},
		{"keyboardInteractive", map[string]any{"keyboardInteractive": map[string]any{"secretAccount": "ssh:vpn:tun"}}, "keyboard-interactive"},
		{"privateKey", map[string]any{"privateKey": map[string]any{"path": "/home/dev/.ssh/id_ed25519", "passphraseAccount": nil}}, "private-key"},
		{"agent", "agent", "agent"},
		// 真客户端发的是 {"agent":{}} 而不是裸字符串 —— 这条是按 Swift 侧实测的字节形状补的
		// （Sync 门禁 Checks_SyncChannel.swift 里钉着同一个形状）。
		{"agent 对象形态", map[string]any{"agent": map[string]any{}}, "agent"},
	}
	for _, tc := range cases {
		manifest := manifestJSON(t, map[string]any{
			"name": "h-" + tc.name, "group": "g", "hostname": "h.example", "port": 22,
			"username": "devops", "auth": tc.auth,
		})
		rows, err := HostsFromChannel(manifest)
		if err != nil {
			t.Fatalf("%s: 清单读失败 %v", tc.name, err)
		}
		if len(rows) != 1 || rows[0].AuthKind != tc.want {
			t.Errorf("%s: 认证方式应为 %q，实际 %+v", tc.name, tc.want, rows)
		}
	}
}

// 反例（这条功能的真正风险）：判别名之外的东西一个都不许留下。账号名、私钥路径、口令
// 全部就在清单明文里、就在 auth 那一层里面 —— 只读键名就必须把它们丢掉。
func TestAuthKindNeverLeaksAccountPathOrSecret(t *testing.T) {
	manifest := manifestJSON(t,
		map[string]any{"name": "a", "group": "g", "hostname": "h", "port": 22, "username": "u",
			"auth": map[string]any{"password": map[string]any{"secretAccount": "ssh:db-01:admin"}}},
		map[string]any{"name": "b", "group": "g", "hostname": "h", "port": 22, "username": "u",
			"auth": map[string]any{"privateKey": map[string]any{"path": "/home/dev/.ssh/id_ed25519",
				"passphraseAccount": "ssh:build:key"}}},
	)
	rows, err := HostsFromChannel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	dumped, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	text := string(dumped)
	for _, forbidden := range []string{
		"ssh:db-01:admin", "ssh:build:key", "/home/dev/.ssh/id_ed25519",
		"id_ed25519", "passphraseAccount", "secretAccount", fakePassword, fakeVault,
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("凭据侧信息漏进主机行了：%q → %s", forbidden, text)
		}
	}
	for _, want := range []string{"password", "private-key"} {
		if !strings.Contains(text, want) {
			t.Errorf("判别名 %q 应当可见，实际 %s", want, text)
		}
	}

	// v2 形状（SPEC §3/§5.1）把这条边界抬得更靠前：钥匙串账号名与私钥路径**压根不在明文里**，
	// 它们在每行那一格 secret 背后。这里用最坏的情况测 —— 假如有坏客户端把账号名/路径直接
	// 当字面填进 secret 串里，服务端只当不透明串：行里没有、GET 接口里没有、「收到了什么」里也
	// 只有字节数。原始上传字节照旧进 blobs（那是设备自己的东西，GET /api/blob 原样还给它）。
	body := v2UploadBody(t, `[
	  {"name":"a","group":"g","hostname":"h","port":22,"username":"u","authKind":"password","notes":"","jump":"",
	   "secret":"ssh:db-01:admin"},
	  {"name":"b","group":"g","hostname":"h2","port":22,"username":"u","authKind":"private-key","notes":"","jump":"",
	   "secret":"/home/dev/.ssh/id_ed25519"}
	]`, "", `"`+fakeMetaLedger+`"`)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := IngestUploadV2(body)
	if err != nil {
		t.Fatalf("合法 v2 行不该被拒：%v", err)
	}
	dumpedV2, err := json.Marshal(parsed.hosts)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"ssh:db-01:admin", "/home/dev/.ssh/id_ed25519",
		"id_ed25519", fakeMetaLedger, "secret"} {
		if strings.Contains(string(dumpedV2), forbidden) {
			t.Errorf("v2 主机行漏了：%q → %s", forbidden, dumpedV2)
		}
	}
	for _, want := range []string{"password", "private-key"} {
		if !strings.Contains(string(dumpedV2), want) {
			t.Errorf("v2 判别名 %q 应当可见，实际 %s", want, dumpedV2)
		}
	}
	// 端到端再看一眼接口：同一条边界由 HTTP 侧守一次。
	e := inventoryEnv(t)
	if res, got := e.putBlob(body, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("v2 推送应 200：%d %s", res.StatusCode, got)
	}
	_, res, hostsRaw := getHosts(t, e, e.token)
	for _, forbidden := range []string{"ssh:db-01:admin", "/home/dev/.ssh/id_ed25519", fakeMetaLedger} {
		if strings.Contains(string(hostsRaw), forbidden) {
			t.Errorf("GET /api/hosts 回吐了 secret 格的内容 %q：%s", forbidden, hostsRaw)
		}
	}
	_ = res
}

// 认不出来就说认不出来，不许猜成"密码"。
func TestAuthKindUnknownForAbsentOrOddAuth(t *testing.T) {
	for name, auth := range map[string]any{
		"缺失":        nil,
		"不认识的 case": map[string]any{"totallyNew": map[string]any{"x": 1}},
		"数字":        7,
		"空对象":       map[string]any{},
	} {
		var manifest []byte
		if auth == nil {
			manifest = manifestJSON(t, map[string]any{"name": name, "group": "g",
				"hostname": "h", "port": 22, "username": "u"})
		} else {
			manifest = manifestJSON(t, map[string]any{"name": name, "group": "g",
				"hostname": "h", "port": 22, "username": "u", "auth": auth})
		}
		rows, err := HostsFromChannel(manifest)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(rows) != 1 || rows[0].AuthKind != "" {
			t.Errorf("%s: 应为空串（界面显示未知），实际 %+v", name, rows)
		}
	}
}

// 端到端：客户端推上来的信封，经 GET /api/hosts 出来要带 authKind。
// 这条是"用户在管理页看得到"的最低要求，只测函数不够。
func TestHostsAPIExposesAuthKind(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	manifest := manifestJSON(t,
		map[string]any{"name": "堡垒机", "group": "生产", "hostname": "jump.example", "port": 22,
			"username": "ops", "auth": "agent"},
		map[string]any{"name": "数据库", "group": "生产", "hostname": "db.example", "port": 5432,
			"username": "dba", "auth": map[string]any{"password": map[string]any{"secretAccount": "ssh:db:dba"}}},
	)
	if res, body := e.putBlob(sealManifest(t, chanA, manifest), "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("推送失败：%d %s", res.StatusCode, body)
	}
	rows, res, raw := getHosts(t, e, e.token)
	if res.StatusCode != http.StatusOK || len(rows) != 2 {
		t.Fatalf("应看到 2 行：%d %s", res.StatusCode, raw)
	}
	got := map[string]string{}
	for _, r := range rows {
		got[r.Name] = r.AuthKind
	}
	if got["堡垒机"] != "agent" || got["数据库"] != "password" {
		t.Errorf("接口没把认证方式带出来：%+v", got)
	}
	if strings.Contains(string(raw), "ssh:db:dba") {
		t.Errorf("接口把钥匙串账号名吐给浏览器了：%s", raw)
	}
}

// 已在跑的库不会自动获得新列（CREATE TABLE IF NOT EXISTS 对存在的表什么都不做），
// 所以升级路径要单独测：老表 + Migrate() 之后，列必须在那儿、老行必须还读得出来。
func TestMigrateAddsAuthKindToPreExistingTable(t *testing.T) {
	dbPath := t.TempDir() + "/old.db"
	store, err := Open("sqlite://" + dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// 手工复刻 0002 之前的表形状。
	if _, err := store.exec(`CREATE TABLE hosts (
		user_id VARCHAR(32) NOT NULL, name VARCHAR(512) NOT NULL, host_group VARCHAR(512) NOT NULL,
		hostname VARCHAR(512) NOT NULL, port INTEGER NOT NULL, username VARCHAR(512) NOT NULL,
		revision INTEGER NOT NULL)`); err != nil {
		t.Fatalf("建老表失败：%v", err)
	}
	if _, err := store.exec(`INSERT INTO hosts (user_id, name, host_group, hostname, port, username, revision)
		VALUES ('u1', '老机器', '默认', 'old.example', 22, 'devops', 3)`); err != nil {
		t.Fatalf("塞老行失败：%v", err)
	}
	if store.hasColumn("hosts", "auth_kind") {
		t.Fatal("老表本来不该有这一列，检查自己失效了")
	}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatalf("升级失败：%v", err)
	}
	if !store.hasColumn("hosts", "auth_kind") {
		t.Fatal("Migrate 之后仍没有 auth_kind 列")
	}
	// 老行还在，且新列取默认空串（界面显示"未知"），不是报错、不是丢行。
	rows, err := store.ListHosts(t.Context(), "u1")
	if err != nil {
		t.Fatalf("升级后读清单失败：%v", err)
	}
	if len(rows) != 1 || rows[0].Name != "老机器" || rows[0].AuthKind != "" {
		t.Errorf("老行应完好且 auth_kind 为空：%+v", rows)
	}
	// 再写一次必须能落上新列。
	if err := store.ReplaceHosts(t.Context(), "u1", 4, []HostRow{
		{Name: "新机器", Group: "默认", Hostname: "new.example", Port: 22, Username: "devops", AuthKind: "private-key"}}); err != nil {
		t.Fatalf("升级后写入失败：%v", err)
	}
	rows, err = store.ListHosts(t.Context(), "u1")
	if err != nil || len(rows) != 1 || rows[0].AuthKind != "private-key" {
		t.Errorf("认证方式没存进库：%+v %v", rows, err)
	}
	// 幂等：再 Migrate 一次不能因为"列已存在"而失败。
	if err := store.Migrate(t.Context()); err != nil {
		t.Errorf("重复 Migrate 应幂等，实际失败：%v", err)
	}
	_ = store.Close()
}
