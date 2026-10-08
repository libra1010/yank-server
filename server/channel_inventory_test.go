package main

// v2 上传体 + 通道口令（SPEC §3/§5，2026-10-06 拍板）。这一组钉两件事：
//  1. 开了加密传输，**外层没有任何明文数组** —— hosts/snippets/meta 连同每行那格端侧密文
//     全在通道 ciphertext 里面，外面只剩通道自己的 6 个字段；
//  2. 服务端解开外层之后走的是和不加密传输**同一份 ingest**，入库结果逐字节相同
//     （用户的话："服务端收到后再转换为不加密传输的情况那样进行"）。
// 顺带钉 secret/meta 的不透明口径：只当字符串收下，不解码、不落列、不从 GET 回吐。

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// 假的两格端侧密文：对服务端就是一串 base64 形状的字面，谁都不该把它解到别处去。
// 哨兵值同时是漏检的探针 —— 它出现在除 blobs 原始字节之外的任何地方都是事故。
const (
	fakeRowSecret   = "cm93LXNlY3JldC1TRVJWRVItTVVTVC1OT1QtTEVBS0U="
	fakeMetaLedger  = "bWV0YS1sZWRnZXItU0VSVkVSLU1VU1QtTk9ULUxFQUtF"
	fakeLooseSecret = "bG9vc2UtYnV0LW5ldmVyLXJldHVybmVk"
)

// v2UploadBody 按 §3 造上传体。三个参数各传空串表示那一格整个不带（缺席与清空是两件事，
// 空数组要传 "[]" / "\"\"" 之类真实的 JSON 值）。metaJSON 传的是**原始 JSON 值**，
// 好让非法形状的测试也能进来。
func v2UploadBody(t *testing.T, hostsJSON, snippetsJSON, metaJSON string) []byte {
	t.Helper()
	doc := map[string]any{
		"cipher":        "aes-256-gcm",
		"formatVersion": formatVersionV2,
		"createdAt":     "2026-10-06T08:33:31Z",
		"kdf": map[string]any{
			"algorithm":      kdfAlgorithm,
			"keyLengthBytes": keyLengthBytes,
			"rounds":         1200000,
			"salt":           base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 16)),
		},
	}
	if hostsJSON != "" {
		doc[inventoryWireKey] = json.RawMessage(hostsJSON)
	}
	if snippetsJSON != "" {
		doc[snippetInventoryWireKey] = json.RawMessage(snippetsJSON)
	}
	if metaJSON != "" {
		doc[metaWireKey] = json.RawMessage(metaJSON)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// 端侧真实会上来的两行：8 个明文键 + 每行一格 secret（SPEC §5.1 示例的字面口径）。
const twoV2HostInventory = `[
  {"name":"生产 Web-01","group":"生产","hostname":"10.0.0.1","port":22,"username":"root",
   "authKind":"password","notes":"机房A，跳板用","jump":"ops@bastion.example:22",
   "secret":"` + fakeRowSecret + `"},
  {"name":"构建机","group":"默认","hostname":"build.lan","port":2222,"username":"devops",
   "authKind":"private-key","notes":"","jump":"","secret":"` + fakeLooseSecret + `"}
]`

const twoV2SnippetInventory = `[
  {"name":"重启 nginx","group":"生产","body":"systemctl restart nginx","params":"",
   "updatedAt":"2026-10-06T08:33:30Z","secret":"` + fakeRowSecret + `"},
  {"name":"登生产库","group":"生产","body":"（正文含疑似口令，已在本机隐去，未上传）",
   "params":"host,user","updatedAt":"2026-10-06T08:33:30Z","secret":"` + fakeLooseSecret + `"}
]`

func v2Body(t *testing.T) []byte {
	t.Helper()
	return v2UploadBody(t, twoV2HostInventory, twoV2SnippetInventory, `"`+fakeMetaLedger+`"`)
}

// seenFromPut 发一次上传并取回服务端自己写的那句结论（seen_test.go 的 putSeen 带不了
// If-Match，v2 的测试经常要在同一台上推第二版）。
func seenFromPut(t *testing.T, e *env, body []byte, ifMatch string) string {
	t.Helper()
	res, raw := e.putBlob(body, ifMatch)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("上传应成功：%d %s", res.StatusCode, raw)
	}
	var reply struct {
		Seen string `json:"seen"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil || reply.Seen == "" {
		t.Fatalf("响应里没有 seen 这一句：%v %s", err, raw)
	}
	return reply.Seen
}

// ---------------------------------------------------------------- 解析层

// 合法 v2：8/5 个明文键 + secret 照单建索引，secret/meta 只留下字节数这一个事实。
func TestIngestUploadV2IndexesCleartextAndTreatsSecretsAsOpaque(t *testing.T) {
	facts, err := IngestUploadV2(v2Body(t))
	if err != nil {
		t.Fatalf("合法 v2 上传体不该报错：%v", err)
	}
	if len(facts.hosts) != 2 || facts.hosts[0].Hostname != "10.0.0.1" ||
		facts.hosts[0].AuthKind != "password" || facts.hosts[1].Jump != "" {
		t.Errorf("主机索引不对：%+v", facts.hosts)
	}
	if len(facts.snippets) != 2 || facts.snippets[1].Params != "host,user" {
		t.Errorf("片段索引不对：%+v", facts.snippets)
	}
	if !facts.hasMeta || facts.metaBytes != len(fakeMetaLedger) {
		t.Errorf("meta 只该被数了字节：%+v", facts)
	}
	if facts.secretBytes != len(fakeRowSecret)*2+len(fakeLooseSecret)*2 {
		t.Errorf("每行 secret 的字节数要如实报给「收到了什么」那句：%d", facts.secretBytes)
	}
	// 行结构体里没有 secret 这一格的容身之处 —— 它被摘掉之后没人再碰过。
	dumped, err := json.Marshal(facts.hosts)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{fakeRowSecret, fakeLooseSecret, fakeMetaLedger, "secret"} {
		if strings.Contains(string(dumped), needle) {
			t.Errorf("不透明串漏进了主机行的 JSON：%q → %s", needle, dumped)
		}
	}

	// 缺席与清空：没有 hosts 键 → nil（不动表）；空数组 → 非 nil 空切片（清表）。
	absent, err := IngestUploadV2(v2UploadBody(t, "", "", `"`+fakeMetaLedger+`"`))
	if err != nil || absent.hosts != nil || absent.snippets != nil {
		t.Errorf("没带数组应返回 nil：%+v %v", absent, err)
	}
	empty, err := IngestUploadV2(v2UploadBody(t, `[]`, `[]`, ""))
	if err != nil || empty.hosts == nil || len(empty.hosts) != 0 || empty.snippets == nil {
		t.Errorf("空数组应返回非 nil 空切片（清表）：%+v %v", empty, err)
	}
	if empty.hasMeta {
		t.Error("这一包没带 meta，不该记成带了")
	}

	// 行内 secret 必须是不透明**串**：给个数组合照旧整次拒绝（Swift 侧的口径是"不是空串、
	// 不是空数组"，形状不符就是形状错误，不是"忽略那一格"）。
	if _, err := IngestUploadV2(v2UploadBody(t,
		`[{"name":"a","hostname":"h","port":22,"username":"u","secret":["不","是","串"]}]`,
		"", "")); !errors.Is(err, errInventoryShape) {
		t.Errorf("secret 不是字符串应报形状错误，实际 %v", err)
	}
	if _, err := IngestUploadV2(v2UploadBody(t, "", "", `{"revision":7}`)); !errors.Is(err, errInventoryShape) {
		t.Errorf("meta 不是字符串应报形状错误，实际 %v", err)
	}
	// 顶层 §2 参数筛不过（轮数离谱）：那是"根本不是合法 v2"，不是清单的错。
	badKdf := v2Body(t)
	badKdf = []byte(strings.Replace(string(badKdf), `"rounds":1200000`, `"rounds":90000000`, 1))
	if _, err := IngestUploadV2(badKdf); !errors.Is(err, errUploadShape) {
		t.Errorf("离谱的 rounds 应按上传体形状拒掉，实际 %v", err)
	}
}

// ---------------------------------------------------------------- 外层形状与同一份 ingest

// §5 的核心断言（2026-10-06 修的就是这条）：开通道口令后，**外层只剩通道自己的 6 个字段**，
// hosts/snippets/meta 连同每行那格端侧密文全在 ciphertext 里面。
func TestChannelOuterLayerCarriesNoCleartextInventory(t *testing.T) {
	sealed, err := SealChannel(chanA, v2Body(t))
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(sealed, &outer); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{inventoryWireKey, snippetInventoryWireKey, metaWireKey, rowSecretWireKey} {
		if _, ok := outer[key]; ok {
			t.Errorf("通道外层挂着明文字段 %q：这一档在网络上又什么都没遮住了", key)
		}
	}
	if len(outer) != len(channelWireFields) {
		names := make([]string, 0, len(outer))
		for k := range outer {
			names = append(names, k)
		}
		sort.Strings(names)
		t.Fatalf("外层应只剩通道自己的 %d 个字段，实际 %d（%v）",
			len(channelWireFields), len(outer), names)
	}
	// 解开后拿到的必须**就是**那一份 v2 字节 —— "转换为不加密传输的情况"的前提。
	plain, err := OpenChannel([]byte(chanA), sealed)
	if err != nil {
		t.Fatalf("正确口令解不开外层：%v", err)
	}
	if !bytes.Equal(plain, v2Body(t)) {
		t.Errorf("通道明文与被封进去的上传体不是同一份字节")
	}
}

// 用户第三点本身：同一份 v2 上传体，不加密直传与封进通道层后上传，入库结果逐字节相同。
// 两台服务器各跑各的：一台什么都没配，一台按页面配了通道口令。
func TestV2IngestIsByteIdenticalThroughChannel(t *testing.T) {
	body := v2Body(t)
	plainSrv := inventoryEnv(t)
	chanSrv, _, _ := newChanEnv(t, chanA)

	sealed, err := SealChannel(chanA, body)
	if err != nil {
		t.Fatal(err)
	}
	if res, got := plainSrv.putBlob(body, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("不加密直传应 200：%d %s", res.StatusCode, got)
	}
	if res, got := chanSrv.putBlob(sealed, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("通道上传应 200：%d %s", res.StatusCode, got)
	}

	// 原始字节照旧各存各的：一台存明文上传体，一台存通道外层，服务端不替设备重排。
	if res, pulled := plainSrv.call("GET", "/api/blob", plainSrv.device, nil); res.StatusCode != http.StatusOK || !bytes.Equal(pulled, body) {
		t.Errorf("不加密那台的 blobs 该原样存上传体：%d", res.StatusCode)
	}
	if res, pulled := chanSrv.call("GET", "/api/blob", chanSrv.device, nil); res.StatusCode != http.StatusOK || !bytes.Equal(pulled, sealed) {
		t.Errorf("通道那台的 blobs 该原样存外层信封：%d", res.StatusCode)
	}

	// 索引结果逐字节相同（第一次推送，两台的修订号都是 1，所以连 revision 都该一致）。
	plainHosts, _, plainRaw := getHosts(t, plainSrv, plainSrv.token)
	chanHosts, _, chanRaw := getHosts(t, chanSrv, chanSrv.token)
	if string(plainRaw) != string(chanRaw) {
		t.Errorf("主机索引不一致：\n不加密 %s\n通道   %s", plainRaw, chanRaw)
	}
	if len(plainHosts) != 2 || len(chanHosts) != 2 {
		t.Fatalf("应有 2 行：%d/%d %s", len(plainHosts), len(chanHosts), plainRaw)
	}
	plainSnips, _, plainSnipRaw := getSnippets(t, plainSrv, plainSrv.token)
	_, _, chanSnipRaw := getSnippets(t, chanSrv, chanSrv.token)
	if string(plainSnipRaw) != string(chanSnipRaw) {
		t.Errorf("片段索引不一致：\n不加密 %s\n通道   %s", plainSnipRaw, chanSnipRaw)
	}
	if len(plainSnips) != 2 {
		t.Fatalf("应有 2 条片段：%s", plainSnipRaw)
	}

	// 「收到了什么」那句：清单部分必须一字不差，只有字节数与通道那一截按各自的形状说。
	// 再推一版同样的字节（If-Match 1）——索引本来就按修订整批覆盖，句子与第一版同形。
	plainSeen := seenFromPut(t, plainSrv, body, "1")
	chanSeen := seenFromPut(t, chanSrv, sealed, "1")
	for _, clause := range []string{
		"明文主机清单 2 条", "明文片段清单 2 条",
		"另加每行一格不透明 secret", "账本 meta 随包上行",
	} {
		if !strings.Contains(plainSeen, clause) || !strings.Contains(chanSeen, clause) {
			t.Errorf("两句都该有「%s」：\n%s\n%s", clause, plainSeen, chanSeen)
		}
	}
	if !strings.Contains(plainSeen, "通道层：没启用") || !strings.Contains(chanSeen, "通道层已用通道密钥解开") {
		t.Errorf("通道那一截要按各自的形状说：\n%s\n%s", plainSeen, chanSeen)
	}
}

// ---------------------------------------------------------------- 端到端：收得下、不外漏

func TestV2UploadStoredAndListed(t *testing.T) {
	e, store, dbPath := newChanEnv(t, "") // 没配通道口令：网络上就是 §3 那一整包
	if res, got := e.putBlob(v2Body(t), "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("v2 上传体应被收下：%d %s", res.StatusCode, got)
	}
	rows, _, raw := getHosts(t, e, e.token)
	if len(rows) != 2 {
		t.Fatalf("应索引到 2 行：%s", raw)
	}
	byName := map[string]HostRow{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	if web := byName["生产 Web-01"]; web.Hostname != "10.0.0.1" || web.Port != 22 ||
		web.Username != "root" || web.AuthKind != "password" || web.Notes != "机房A，跳板用" ||
		web.Jump != "ops@bastion.example:22" {
		t.Errorf("8 个明文键没存全：%+v", web)
	}
	snips, _, snipRaw := getSnippets(t, e, e.token)
	if len(snips) != 2 {
		t.Fatalf("应列出 2 条片段：%s", snipRaw)
	}

	// secret/meta 只活在 blobs 的原始字节里（设备要靠它解密）；清单接口与历史接口一个字都不回吐。
	for name, response := range map[string][]byte{
		"GET /api/hosts": raw, "GET /api/snippets": snipRaw,
	} {
		for _, needle := range []string{fakeRowSecret, fakeLooseSecret, fakeMetaLedger} {
			if strings.Contains(string(response), needle) {
				t.Errorf("%s 回吐了不透明串 %q：%s", name, needle, response)
			}
		}
	}
	if res, hist := e.call("GET", "/api/blob/history", e.token, nil); res.StatusCode != http.StatusOK {
		t.Fatalf("历史接口应 200：%d", res.StatusCode)
	} else {
		for _, needle := range []string{fakeRowSecret, fakeLooseSecret, fakeMetaLedger} {
			if strings.Contains(string(hist), needle) {
				t.Errorf("历史接口回吐了不透明串 %q：%s", needle, hist)
			}
		}
	}
	// 「收到了什么」那句同样只报字节数与键名，不报内容。
	seen := seenFromPut(t, e, v2Body(t), "1")
	for _, needle := range []string{fakeRowSecret, fakeLooseSecret, fakeMetaLedger, "10.0.0.1"} {
		if strings.Contains(seen, needle) {
			t.Errorf("结论句里漏了内容 %q：%s", needle, seen)
		}
	}

	// 表里没有为 secret/meta 开的列：两张表的列集合和 v1 一模一样。
	for table, want := range map[string][]string{
		"hosts":    {"user_id", "name", "host_group", "hostname", "port", "username", "auth_kind", "notes", "jump", "revision"},
		"snippets": {"user_id", "name", "snippet_group", "body", "params", "updated_at", "revision"},
	} {
		cols := tableColumns(t, store, table)
		if len(cols) != len(want) {
			t.Errorf("%s 列集合应是 %v，实际 %v", table, want, keysOf(cols))
		}
		for _, c := range want {
			if !cols[c] {
				t.Errorf("%s 缺列 %s", table, c)
			}
		}
	}
	// 库文件的原始字节里，不透明串只该出现在 blob 那一个位置；清单行里没有它们的容身处。
	if onDisk := diskBytes(t, dbPath); !bytes.Contains(onDisk, []byte(fakeMetaLedger)) {
		t.Error("整包原始字节照旧要进 blobs —— meta 不在库文件里说明上传体没存下来")
	}
	if err := store.ReplaceHosts(t.Context(), "u2", 9, []HostRow{
		{Name: "哨兵", Group: "", Hostname: "sentinel.example", Port: 22, Username: "u", AuthKind: ""}}); err != nil {
		t.Fatal(err)
	}
	if hosts, err := store.ListHosts(t.Context(), "u2"); err != nil || len(hosts) != 1 ||
		strings.Contains(hosts[0].Name, fakeRowSecret) {
		t.Errorf("行结构里不该有任何 secret 的残留：%+v %v", hosts, err)
	}
}

// 关掉「口令随包同步」时，留下的那一行**没有 secret 键**（不是空串、不是空数组）—— 服务端
// 必须照常收下并建索引，缺席不是错。
func TestV2RowsWithoutSecretStillIngest(t *testing.T) {
	e := inventoryEnv(t)
	body := v2UploadBody(t, twoHostInventory, `[{"name":"n","group":"","body":"ls","params":"",
		"updatedAt":"2026-10-06T08:33:30Z"}]`, "")
	if res, got := e.putBlob(body, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("行不带 secret 应照常收下：%d %s", res.StatusCode, got)
	}
	if rows, _, raw := getHosts(t, e, e.token); len(rows) != 2 {
		t.Errorf("索引不对：%s", raw)
	}
	if snips, _, raw := getSnippets(t, e, e.token); len(snips) != 1 {
		t.Errorf("片段索引不对：%s", raw)
	}
}

// 空数组清表在 v2 同理（两张表互不牵连）：这一版把最后一台删了，库里就不能留影。
func TestV2EmptyArraysClearTheirTables(t *testing.T) {
	e := inventoryEnv(t)
	if res, got := e.putBlob(v2Body(t), "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("首推失败：%d %s", res.StatusCode, got)
	}
	second := v2UploadBody(t, `[]`, twoV2SnippetInventory, `"`+fakeMetaLedger+`"`)
	if res, got := e.putBlob(second, "1"); res.StatusCode != http.StatusOK {
		t.Fatalf("第二推失败：%d %s", res.StatusCode, got)
	}
	if rows, _, raw := getHosts(t, e, e.token); len(rows) != 0 {
		t.Errorf("hosts: [] 必须清表：%s", raw)
	}
	if snips, _, raw := getSnippets(t, e, e.token); len(snips) != 2 {
		t.Errorf("片段数组没带变化，不该被牵连：%s", raw)
	}
}

// 整次写入拒绝在 v2 的每一格上都成立：行里多一个未知键、命中凭据词根的键（secret 以外的），
// 或者 meta 不是串，PUT 整包拒收，blob/主机/片段哪个表都不许动。
func TestV2RowKeyViolationsRejectWholePut(t *testing.T) {
	cases := map[string]struct{ hosts, snippets, meta string }{
		"主机行塞了口令":     {hosts: `[{"name":"a","hostname":"h","port":22,"username":"u","password":"hunter2","secret":"` + fakeRowSecret + `"}]`, meta: `"` + fakeMetaLedger + `"`},
		"主机行塞了私钥路径":   {hosts: `[{"name":"a","hostname":"h","port":22,"username":"u","privateKeyPath":"/x/id"}]`, meta: `"` + fakeMetaLedger + `"`},
		"主机行多一个未知键":   {hosts: `[{"name":"a","hostname":"h","port":22,"username":"u","weird":"x"}]`, meta: `"` + fakeMetaLedger + `"`},
		"片段行塞了令牌":     {hosts: twoV2HostInventory, snippets: `[{"name":"n","body":"ls","token":"x"}]`, meta: `"` + fakeMetaLedger + `"`},
		"片段行多一个未知键":   {hosts: twoV2HostInventory, snippets: `[{"name":"n","body":"ls","weird":"x"}]`, meta: `"` + fakeMetaLedger + `"`},
		"meta 不是不透明串": {hosts: twoV2HostInventory, meta: `[1,2,3]`},
	}
	for label, tc := range cases {
		e := inventoryEnv(t)
		res, body := e.putBlob(v2UploadBody(t, tc.hosts, tc.snippets, tc.meta), "0")
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s：应 400 整次拒收，实际 %d %s", label, res.StatusCode, body)
			continue
		}
		if r, _ := e.call("GET", "/api/blob", e.token, nil); r.StatusCode != http.StatusNoContent {
			t.Errorf("%s：被拒的写入不该留下上传体，实际 %d", label, r.StatusCode)
		}
		if rows, _, raw := getHosts(t, e, e.token); len(rows) != 0 {
			t.Errorf("%s：整次拒绝就不该有主机行，实际 %s", label, raw)
		}
		if rows, _, raw := getSnippets(t, e, e.token); len(rows) != 0 {
			t.Errorf("%s：整次拒绝就不该有片段行，实际 %s", label, raw)
		}
	}
}

// v2 的凭据词根与未知键各按 §5.1 的两句 400 分别说：词根命中 → "不得携带凭据字段"，
// 其余 → "形状不合法"。理由说错方向会让人以为换个键名就能混进来。
func TestV2RejectReasonsPointAtTheRightArray(t *testing.T) {
	e := inventoryEnv(t)
	_, body := e.putBlob(v2UploadBody(t,
		`[{"name":"a","hostname":"h","port":22,"username":"u","passphrase":"x"}]`, "", ""), "0")
	if !strings.Contains(string(body), "主机清单里不得携带凭据字段") {
		t.Errorf("命中词根该指主机清单：%s", body)
	}
	e = inventoryEnv(t)
	_, body = e.putBlob(v2UploadBody(t, twoV2HostInventory,
		`[{"name":"n","body":"ls","vault":"x"}]`, ""), "0")
	if !strings.Contains(string(body), "片段清单里不得携带凭据字段") {
		t.Errorf("片段数组的词根该指片段清单：%s", body)
	}
	e = inventoryEnv(t)
	_, body = e.putBlob(v2UploadBody(t, twoV2HostInventory, "", `{"不是":"串"}`), "0")
	if !strings.Contains(string(body), "meta") {
		t.Errorf("meta 的理由要点了这一格的名字：%s", body)
	}
}

// 顶层形状根本不是 v2 的"假装包"：版本号 2 但 cipher/kdf 对不上 —— 按 415 拒，
// 与 v1 垃圾信封那一句同一档。
func TestV2ScreeningRejectsBogusHeader(t *testing.T) {
	e := inventoryEnv(t)
	body := v2Body(t)
	body = []byte(strings.Replace(string(body), `"cipher":"aes-256-gcm"`, `"cipher":"rot13"`, 1))
	if res, got := e.putBlob(body, "0"); res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("假 v2 形状应 415，实际 %d %s", res.StatusCode, got)
	}
}

// 回退带着 v2 索引一起回：重建走的是同一份 IngestUploadV2，两个数组都跟着回到那一版。
func TestRollbackReindexesV2Inventory(t *testing.T) {
	e := inventoryEnv(t)
	first := v2UploadBody(t, twoV2HostInventory,
		`[{"name":"一版片段","group":"g","body":"echo one","params":"","updatedAt":"2026-10-06T08:33:30Z","secret":"`+fakeRowSecret+`"}]`,
		`"`+fakeMetaLedger+`"`)
	second := v2UploadBody(t, twoV2HostInventory,
		`[{"name":"二版片段","group":"g","body":"echo two","params":"","updatedAt":"2026-10-06T08:33:31Z","secret":"`+fakeRowSecret+`"}]`,
		`"`+fakeMetaLedger+`"`)
	if res, got := e.putBlob(first, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("第一版失败：%d %s", res.StatusCode, got)
	}
	if res, got := e.putBlob(second, "1"); res.StatusCode != http.StatusOK {
		t.Fatalf("第二版失败：%d %s", res.StatusCode, got)
	}
	if res, got := e.json("POST", "/api/blob/rollback", e.token, map[string]int64{"revision": 1}); res.StatusCode != http.StatusOK {
		t.Fatalf("回退失败：%d %s", res.StatusCode, got)
	}
	rows, _, raw := getSnippets(t, e, e.token)
	if len(rows) != 1 || rows[0].Name != "一版片段" {
		t.Fatalf("回退后片段索引应回到第一版：%s", raw)
	}
	if hosts, _, raw := getHosts(t, e, e.token); len(hosts) != 2 {
		t.Errorf("回退后主机索引应还是那一版的 2 行：%s", raw)
	}
	// 回退前滚出来的那份历史里，不透明串没被换地方：secret 只跟着原始字节走。
	res, pulled := e.call("GET", "/api/blob", e.token, nil)
	if res.StatusCode != http.StatusOK || !bytes.Equal(pulled, first) {
		t.Errorf("回退应原样前滚第一版的字节：%d", res.StatusCode)
	}
}

// tableColumns 读一张表的列集合（PRAGMA 是 sqlite 侧的测试专用口径，同 TestChannelSecretBoundary）。
func tableColumns(t *testing.T, store *Store, table string) map[string]bool {
	t.Helper()
	rows, err := store.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		cols[name] = true
	}
	return cols
}
