package main

// 片段清单（SPEC §5.1，用户 2026-10-05 拍板："管理端要看得见片段本身"）的端到端与门禁。
// 路子照主机清单抄：客户端在信封**旁边**挂一个永远明文的 `snippets` 数组，服务端不配通道
// 密钥也列得出来；数组里塞进凭据键就整次写入拒收；`snippets: []` 真的清表。
// 键名与字段集合是两端各写一遍的约定，改一边忘另一边时后果不是编译错误而是页面的片段列
// 静默变空，所以最后那一组直接把 Swift 源读来对字面量。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// snippetEnv 借用 newChanEnv(t, "")：一台通道密钥都没配的服务器，注册与配对都替测试做完了。
// 这一组要的前提恰恰是"密钥不存在"；留着 store 与 dbPath 是给字节级的反证用的。
func snippetEnv(t *testing.T) (*env, *Store, string) {
	t.Helper()
	return newChanEnv(t, "")
}

// snippetEnvelopePlaintext 是内层那份端到端信封的明文 —— 服务端解不开它，这里只是把它当作
// "客户端本机才有的东西"。登生产库那条的正文里真的带着口令字面值：它只随密文上行，
// 绝不该出现在片段表的任何一列里。下面那条 grep 的意义就在这里。
func snippetEnvelopePlaintext() string {
	return `{"revision":1,"profiles":[],"snippets":[` +
		`{"id":"S1","name":"重启 nginx","body":"systemctl restart nginx"},` +
		`{"id":"S2","name":"登生产库","body":"mysql -h {host} -u {user} --password=` + fakePassword + `"}]}`
}

// bodyWithBothArrays 造新客户端真实上传的形状：信封 + 并肩挂着的明文 hosts 与 snippets
// 两个数组（这两份数组的线上形状见 SPEC.md §5.1，服务端只认字段名，不认是谁发的）。
// 传空串表示这一格不挂，用来模拟只发其中一个数组的客户端。
func bodyWithBothArrays(t *testing.T, hostsJSON, snippetsJSON string) []byte {
	t.Helper()
	var bag map[string]json.RawMessage
	if err := json.Unmarshal(envelopeBody(t, snippetEnvelopePlaintext()), &bag); err != nil {
		t.Fatal(err)
	}
	if hostsJSON != "" {
		bag[inventoryWireKey] = json.RawMessage(hostsJSON)
	}
	if snippetsJSON != "" {
		bag[snippetInventoryWireKey] = json.RawMessage(snippetsJSON)
	}
	out, err := json.Marshal(bag)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func getSnippets(t *testing.T, e *env, auth string) ([]SnippetRow, *http.Response, []byte) {
	t.Helper()
	res, body := e.call("GET", "/api/snippets", auth, nil)
	var rows []SnippetRow
	if err := json.Unmarshal(body, &rows); err != nil && res.StatusCode == http.StatusOK {
		t.Fatalf("片段清单不是合法 JSON 数组：%v %s", err, body)
	}
	return rows, res, body
}

// assertNothingLikeThePasswordStored 直接查库：片段表的每一列都不许出现那个口令字面值，
// 被端侧隐去的那一条也不许以原样命令的形态回来。最后再 grep 整份库文件的字节 ——
// WAL 里可能留着最新写入，只读主文件的 grep 证明不了任何事（diskBytes 同一套理由）。
func assertNothingLikeThePasswordStored(t *testing.T, store *Store, dbPath string) {
	t.Helper()
	rows, err := store.db.Query("SELECT name, snippet_group, body, params, updated_at FROM snippets")
	if err != nil {
		t.Fatalf("查片段表失败：%v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, group, body, params, updatedAt string
		if err := rows.Scan(&name, &group, &body, &params, &updatedAt); err != nil {
			t.Fatal(err)
		}
		for _, cell := range []string{name, group, body, params, updatedAt} {
			if strings.Contains(cell, fakePassword) {
				t.Errorf("片段表里出现了口令字面值：%q", cell)
			}
		}
		if strings.Contains(body, "--password") {
			t.Errorf("端侧已经隐去的正文在服务端又是原样命令：%q", body)
		}
	}
	if raw := diskBytes(t, dbPath); bytes.Contains(raw, []byte(fakePassword)) {
		t.Errorf("库文件字节里搜得到口令字面值（扫了 %d 字节）", len(raw))
	}
}

// 用户要的那件事本身：一台什么都没配的服务器上，片段本身进库、列得出来，
// 而那个口令字面值连片段表的边都没碰到。
func TestSnippetInventoryEndToEndWithoutChannelKey(t *testing.T) {
	e, store, dbPath := snippetEnv(t)

	// 一次都没推过：200 空数组。"这个账号还没推过片段"是一次陈述，不该拿 503 去怪读的人
	// 没启用某个功能。
	rows, res, raw := getSnippets(t, e, e.token)
	if res.StatusCode != http.StatusOK || strings.TrimSpace(string(raw)) != "[]" || len(rows) != 0 {
		t.Fatalf("空账号应 200 且响应体是 []，实际 %d %s", res.StatusCode, raw)
	}

	if res, got := e.putBlob(bodyWithBothArrays(t, twoHostInventory, twoSnippetInventory), "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("带片段数组的推送应被收下：%d %s", res.StatusCode, got)
	}

	rows, res, raw = getSnippets(t, e, e.token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("片段接口应 200，实际 %d %s", res.StatusCode, raw)
	}
	if len(rows) != 2 {
		t.Fatalf("应列出 2 条片段，实际 %s", raw)
	}
	byName := map[string]SnippetRow{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	restart := byName["重启 nginx"]
	if restart.Body != "systemctl restart nginx" || restart.Group != "生产" ||
		restart.Params != "" || restart.UpdatedAt != "2026-10-05T04:00:00Z" || restart.Revision != 1 {
		t.Errorf("片段本身要照端侧的字面列出来：%+v", restart)
	}
	// 被隐去的那一条：正文是端侧那句替换文本（原样存，服务端不猜也不补），参数名照常可见——
	// 正文没了的时候 params 那一格是管理端唯一还有信息量的地方。
	redacted := byName["登生产库"]
	if redacted.Body != "（正文含疑似口令，已在本机隐去，未上传）" || redacted.Params != "host,user" {
		t.Errorf("被隐去的那一条应存隐去说明、参数照常：%+v", redacted)
	}

	// 鉴权与 GET /api/hosts 同权：设备令牌读得到，匿名读不到。
	if _, res, raw = getSnippets(t, e, e.device); res.StatusCode != http.StatusOK {
		t.Errorf("设备令牌应读得到片段清单，实际 %d %s", res.StatusCode, raw)
	}
	if res, _ := e.call("GET", "/api/snippets", "", nil); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("匿名读片段清单应 401，实际 %d", res.StatusCode)
	}
	// 同一次推送照旧把主机写进 hosts 表：片段这一条不该动主机那条路径的对外行为。
	if hosts, _, hostRaw := getHosts(t, e, e.token); len(hosts) != 2 {
		t.Errorf("一次推送要同时喂两张表，主机清单应 2 行：%s", hostRaw)
	}

	assertNothingLikeThePasswordStored(t, store, dbPath)

	// 缺键与清空是两件事（handler 层这一半也要钉住）：只发 hosts、不发 snippets 的那一次推送
	// 是"这一版没谈片段"，库里那两条必须原地不动， revision 也还是第一次那个号。
	if res, got := e.putBlob(bodyWithBothArrays(t, twoHostInventory, ""), "1"); res.StatusCode != http.StatusOK {
		t.Fatalf("不带片段数组的推送应被收下：%d %s", res.StatusCode, got)
	}
	if rows, _, raw := getSnippets(t, e, e.token); len(rows) != 2 || rows[0].Revision != 1 {
		t.Errorf("没有 snippets 键不该动片段表，实际 %s", raw)
	}

	// 删掉最后一条片段：`snippets: []` 必须真的清表，而且不牵连主机那两行 —— 两张表各清各的。
	if res, got := e.putBlob(bodyWithBothArrays(t, twoHostInventory, `[]`), "2"); res.StatusCode != http.StatusOK {
		t.Fatalf("推空片段清单应 200：%d %s", res.StatusCode, got)
	}
	rows, res, raw = getSnippets(t, e, e.token)
	if res.StatusCode != http.StatusOK || strings.TrimSpace(string(raw)) != "[]" || len(rows) != 0 {
		t.Errorf("清完最后一行后服务端还留着片段：%d %s", res.StatusCode, raw)
	}
	if hosts, _, hostRaw := getHosts(t, e, e.token); len(hosts) != 2 {
		t.Errorf("片段清表不该顺手清掉主机清单：%s", hostRaw)
	}
}

// 反例（这条新功能唯一真正的风险）：有人把凭据塞进明文片段数组 —— 不管是不小心还是恶意，
// 服务端必须整次拒绝，而不是"忽略那一格"悄悄收下。整次拒绝意味着什么都没存：信封没落库，
// 连同一次请求里那份合法的主机清单也不落库。
func TestSnippetInventoryRejectsCredentialBearingEntries(t *testing.T) {
	cases := map[string]string{
		"直接给口令":  `[{"name":"a","body":"ls","password":"hunter2"}]`,
		"给凭据材料":  `[{"name":"a","body":"ls","secretMaterial":[]}]`,
		"给私钥路径":  `[{"name":"a","body":"ls","privateKeyPath":"/x/id"}]`,
		"给端到端口令": `[{"name":"a","body":"ls","passphrase":"x"}]`,
		"给令牌":    `[{"name":"a","body":"ls","token":"x"}]`,
	}
	for label, snippets := range cases {
		e := inventoryEnv(t)
		res, body := e.putBlob(bodyWithBothArrays(t, twoHostInventory, snippets), "0")
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s：应 400 整次拒收，实际 %d %s", label, res.StatusCode, body)
			continue
		}
		if !strings.Contains(string(body), "凭据") {
			t.Errorf("%s：400 的理由要点明是凭据问题，实际 %s", label, body)
		}
		if r, _ := e.call("GET", "/api/blob", e.token, nil); r.StatusCode != http.StatusNoContent {
			t.Errorf("%s：被拒的写入不该留下信封，实际 %d", label, r.StatusCode)
		}
		if rows, _, raw := getHosts(t, e, e.token); len(rows) != 0 {
			t.Errorf("%s：整次写入拒绝就不该有主机行，实际 %s", label, raw)
		}
		if rows, _, raw := getSnippets(t, e, e.token); len(rows) != 0 {
			t.Errorf("%s：整次写入拒绝就不该有片段行，实际 %s", label, raw)
		}
	}
}

// 白名单以外的键也不许混进来（它今天不是凭据，明天就可能变成某个新字段的藏身处），
// 理由要说清是形状而不是凭据。
func TestSnippetInventoryRejectsUnknownKeys(t *testing.T) {
	e := inventoryEnv(t)
	res, body := e.putBlob(bodyWithBothArrays(t, twoHostInventory,
		`[{"name":"a","group":"g","body":"ls","params":"","updatedAt":"2026-10-05T04:00:00Z","weird":"x"}]`), "0")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("未知键应 400，实际 %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "形状") {
		t.Errorf("400 应点明形状不合法，实际 %s", body)
	}
}

// 回退要带着片段索引一起回退，否则 /api/snippets 还在广告刚被撤销的那一版：
// rebuildInventory 从存下来的那一份体里把两个明文数组都重数一遍。
func TestRollbackReindexesSnippets(t *testing.T) {
	e := inventoryEnv(t)
	first := bodyWithBothArrays(t, twoHostInventory,
		`[{"name":"一版片段","group":"g","body":"echo one","params":"","updatedAt":"2026-10-05T04:00:00Z"}]`)
	second := bodyWithBothArrays(t, twoHostInventory,
		`[{"name":"二版片段","group":"g","body":"echo two","params":"","updatedAt":"2026-10-05T05:00:00Z"}]`)
	if res, body := e.putBlob(first, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("第一版写入失败：%d %s", res.StatusCode, body)
	}
	if res, body := e.putBlob(second, "1"); res.StatusCode != http.StatusOK {
		t.Fatalf("第二版写入失败：%d %s", res.StatusCode, body)
	}
	rows, _, raw := getSnippets(t, e, e.token)
	if len(rows) != 1 || rows[0].Name != "二版片段" {
		t.Fatalf("推过第二版后应只剩二版那一条，实际 %s", raw)
	}
	res, body := e.json("POST", "/api/blob/rollback", e.token, map[string]int64{"revision": 1})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("回退失败：%d %s", res.StatusCode, body)
	}
	rows, _, raw = getSnippets(t, e, e.token)
	if len(rows) != 1 || rows[0].Name != "一版片段" || rows[0].Body != "echo one" {
		t.Fatalf("回退后片段索引应回到第一版，实际 %s", raw)
	}
}

// ---------------------------------------------------------------- 键名门禁（两端各写一遍）

func swiftSnippetSource(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "Sources", "TermKit", "Credentials", "SnippetInventory.swift")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到客户端片段清单定义 %s：%v（静默跳过会让这条变成最弱的那种绿）", path, err)
	}
	return string(raw)
}

func TestSwiftSendsTheSnippetKeyGoReads(t *testing.T) {
	src := swiftSnippetSource(t)
	// Go 侧按 snippetInventoryWireKey 取数组；Swift 侧那个常量必须逐字相同。
	if !strings.Contains(src, `wireKey = "`+snippetInventoryWireKey+`"`) {
		t.Fatalf("客户端上传的键名与服务端读的不是一个：服务端读 %q", snippetInventoryWireKey)
	}
	// 端侧"过长就不展示"的容量必须不高于服务端那一格的容量：否则客户端以为自己在传完整正文，
	// 服务端却把它截了 —— 而截断过的命令抄回去跑是另一码事。
	match := regexp.MustCompile(`bodyLimit = (\d+)`).FindStringSubmatch(src)
	if match == nil {
		t.Fatal("客户端里找不到 bodyLimit 那个容量常量")
	}
	limit, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("客户端的 bodyLimit 不是个数字：%s", match[1])
	}
	if limit > snippetBodyMaxRunes {
		t.Errorf("端侧容量 %d 大于服务端那一格 %d：正文会被服务端截断而不是整条不展示",
			limit, snippetBodyMaxRunes)
	}
}

func TestSwiftSnippetFieldsAreExactlyTheWhitelist(t *testing.T) {
	src := swiftSnippetSource(t)
	start := strings.Index(src, "public struct SnippetInventoryEntry")
	if start < 0 {
		t.Fatal("客户端里找不到 SnippetInventoryEntry 这个结构")
	}
	end := strings.Index(src[start:], "\n}")
	if end < 0 {
		t.Fatal("SnippetInventoryEntry 的结构没闭合")
	}
	body := src[start : start+end]
	fields := regexp.MustCompile(`(?m)^\s*public var (\w+)`).FindAllStringSubmatch(body, -1)
	got := map[string]bool{}
	for _, match := range fields {
		got[match[1]] = true
	}
	if len(got) != len(snippetWhitelist) {
		t.Fatalf("字段数对不上：客户端 %d 个，服务端白名单 %d 个（客户端=%v）",
			len(got), len(snippetWhitelist), keysOf(got))
	}
	for want := range snippetWhitelist {
		if !got[want] {
			t.Errorf("客户端没有 %q 这一项，服务端白名单却收它：片段列会缺格", want)
		}
	}
	// 反向：客户端多发的键会在 PUT 时被整次拒绝，所以"多一个"同样是事故。
	for have := range got {
		if !snippetWhitelist[have] {
			t.Errorf("客户端发了 %q，服务端白名单里没有：每次同步都会被 400 拒掉", have)
		}
	}
}
