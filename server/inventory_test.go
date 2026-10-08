package main

// 明文清单元数据（SPEC §5.1）。用户这次把口径改了：不管有没有开通道加密，服务端库里都要存
// 主机、端口、登录账号、登录方式、名称、备注、堡垒机，界面上都要能直接看到。
// 这一组就钉这两头：**没有密钥也列得出清单**，以及**清单里塞进凭据就整次拒收**。
// 片段数组（#88，2026-10-05 的同一句话：管理端要看得见片段本身）走的是同一条闸，所以它
// 的解析层断言也放在这里，端到端与键名门禁在 snippet_inventory_test.go。

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

// inventoryEnv 是"什么都没配"的服务器：没有通道密钥种子、没有 flag，只有刚注册的用户和刚
// 配对的设备。这一组检查要的前提就是"密钥不存在"。
func inventoryEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.enroll("devops", "a-long-enough-pass")
	e.pairDevice("mac-a")
	return e
}

// bodyWithInventory 造一个"端到端信封 + 并肩放着的明文 hosts 数组"的请求体，
// 也就是新客户端真实上传的形状。信封部分是随便一句被加密的话：服务端解不开它，
// 而这一组检查关心的恰恰是"解不开也照样有清单"。
func bodyWithInventory(t *testing.T, hostsJSON string) []byte {
	t.Helper()
	body := envelopeBody(t, `{"revision":1,"profiles":[]}`)
	var bag map[string]json.RawMessage
	if err := json.Unmarshal(body, &bag); err != nil {
		t.Fatal(err)
	}
	bag[inventoryWireKey] = json.RawMessage(hostsJSON)
	out, err := json.Marshal(bag)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const twoHostInventory = `[
  {"name":"生产 Web-01","group":"生产","hostname":"10.0.0.1","port":22,"username":"root",
   "authKind":"password","notes":"机房A，跳板用","jump":"ops@bastion.example:22"},
  {"name":"构建机","group":"默认","hostname":"build.lan","port":2222,"username":"devops",
   "authKind":"private-key","notes":"","jump":""}
]`

// 用户要的那件事本身：一个通道密钥都没配的服务器上，清单照样进库、照样列得出来。
func TestCleartextInventoryNeedsNoChannelKey(t *testing.T) {
	e := inventoryEnv(t) // newEnv 不带 -channel-key
	if res, body := e.putBlob(bodyWithInventory(t, twoHostInventory), "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("没配密钥的服务器应收下这份体：%d %s", res.StatusCode, body)
	}
	rows, res, raw := getHosts(t, e, e.token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("清单接口应 200，实际 %d %s", res.StatusCode, raw)
	}
	if len(rows) != 2 {
		t.Fatalf("应有 2 行，实际 %s", raw)
	}
	byName := map[string]HostRow{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	web := byName["生产 Web-01"]
	if web.Hostname != "10.0.0.1" || web.Port != 22 || web.Username != "root" {
		t.Errorf("主机/端口/用户没存对：%+v", web)
	}
	if web.AuthKind != "password" {
		t.Errorf("登录方式应是 password：%+v", web)
	}
	if web.Notes != "机房A，跳板用" {
		t.Errorf("备注要按用户要求存下来：%+v", web)
	}
	if web.Jump != "ops@bastion.example:22" {
		t.Errorf("堡垒机要存下来：%+v", web)
	}
	if byName["构建机"].AuthKind != "private-key" || byName["构建机"].Jump != "" {
		t.Errorf("第二行不对：%+v", byName["构建机"])
	}
}

// 反例（这条新功能唯一真正的风险）：有人把凭据塞进明文清单里 —— 不管是不小心还是恶意，
// 服务端必须整次拒绝，而不是"忽略掉那一格"悄悄收下。
func TestInventoryRejectsCredentialBearingEntries(t *testing.T) {
	cases := map[string]string{
		"直接给口令":       `[{"name":"a","hostname":"h","port":22,"username":"u","password":"hunter2"}]`,
		"给凭据材料":       `[{"name":"a","hostname":"h","port":22,"username":"u","secretMaterial":[]}]`,
		"给私钥路径":       `[{"name":"a","hostname":"h","port":22,"username":"u","privateKeyPath":"/x/id"}]`,
		"给端到端口令":      `[{"name":"a","hostname":"h","port":22,"username":"u","passphrase":"x"}]`,
		"给账号名（判别名以外）": `[{"name":"a","hostname":"h","port":22,"username":"u","authKind":{"secretAccount":"ssh:a:u"}}]`,
	}
	for label, hosts := range cases {
		e := inventoryEnv(t)
		res, body := e.putBlob(bodyWithInventory(t, hosts), "0")
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s：应 400 整次拒收，实际 %d %s", label, res.StatusCode, body)
			continue
		}
		if !strings.Contains(string(body), "凭据") && !strings.Contains(string(body), "形状") {
			t.Errorf("%s：400 要带中文理由，实际 %s", label, body)
		}
		// 拒收必须是"什么都没存"：留下第 1 版等于把这份带凭据的体存进了库。
		if r, _ := e.call("GET", "/api/blob", e.token, nil); r.StatusCode != http.StatusNoContent {
			t.Errorf("%s：被拒的写入不该留下信封，实际 %d", label, r.StatusCode)
		}
	}
}

// 白名单以外的键也不许混进来（它今天不是凭据，明天就可能变成某个新字段的藏身处）。
func TestInventoryRejectsUnknownKeys(t *testing.T) {
	e := inventoryEnv(t)
	res, body := e.putBlob(bodyWithInventory(t,
		`[{"name":"a","hostname":"h","port":22,"username":"u","weird":"x"}]`), "0")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("未知键应 400，实际 %d %s", res.StatusCode, body)
	}
}

// 删掉最后一台主机必须真的把清单清空 —— 空数组和"没有这个键"是两件事。
func TestEmptyInventoryClearsStoredRows(t *testing.T) {
	e := inventoryEnv(t)
	if res, body := e.putBlob(bodyWithInventory(t, twoHostInventory), "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("首推失败：%d %s", res.StatusCode, body)
	}
	if rows, _, _ := getHosts(t, e, e.token); len(rows) != 2 {
		t.Fatalf("应先有 2 行：%+v", rows)
	}
	res, body := e.putBlob(bodyWithInventory(t, `[]`), "1")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("推空清单应 200，实际 %d %s", res.StatusCode, body)
	}
	rows, _, raw := getHosts(t, e, e.token)
	if len(rows) != 0 {
		t.Errorf("删完最后一台后服务端还留着清单：%s", raw)
	}
}

// 认不出的登录方式就留空，界面显示"未知"，不许猜成"密码"。
func TestAuthKindIsClampedNotGuessed(t *testing.T) {
	e := inventoryEnv(t)
	if res, body := e.putBlob(bodyWithInventory(t,
		`[{"name":"a","group":"g","hostname":"h","port":22,"username":"u","authKind":"totally-new","notes":"","jump":""}]`), "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("合法键的陌生取值不该拒收整个请求：%d %s", res.StatusCode, body)
	}
	rows, _, raw := getHosts(t, e, e.token)
	if len(rows) != 1 || rows[0].AuthKind != "" {
		t.Errorf("陌生判别名应存成空串（界面显示未知），实际 %s", raw)
	}
}

// v2 拍板（SPEC §5，2026-10-06）改了这里的口径：通道密文里装的是 §3 那一整包，**外面一个
// 明文字节都不许留**。从前"挂在旁边的明文清单盖过通道层"的规矩随旧形状一起作废 —— 现在
// 通道信封旁边还挂着 hosts 数组，就是这一档修掉的那个洞（开了加密传输、网络上却什么都没遮住），
// 服务端整次拒收，绝不静默退回从外面那层读清单的老路。
func TestCleartextArraysBesideChannelEnvelopeAreRejected(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	manifest := manifestJSON(t, map[string]any{"name": "通道层那台", "group": "g",
		"hostname": "channel.example", "port": 22, "username": "u"})
	env := sealManifest(t, chanA, manifest)
	var bag map[string]json.RawMessage
	if err := json.Unmarshal(env, &bag); err != nil {
		t.Fatal(err)
	}
	bag[inventoryWireKey] = json.RawMessage(twoHostInventory)
	merged, err := json.Marshal(bag)
	if err != nil {
		t.Fatal(err)
	}
	res, got := e.putBlob(merged, "0")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("通道信封外挂着明文数组必须整次拒收，实际 %d %s", res.StatusCode, got)
	}
	if !strings.Contains(string(got), "通道密钥") {
		t.Errorf("拒绝理由要落在通道这一层（格式非法归这一句，不留 oracle）：%s", got)
	}
	// 拒收 = 什么都没存：信封没落库，清单也没有行。
	if r, _ := e.call("GET", "/api/blob", e.token, nil); r.StatusCode != http.StatusNoContent {
		t.Errorf("被拒的写入不该留下信封，实际 %d", r.StatusCode)
	}
	if rows, _, raw := getHosts(t, e, e.token); len(rows) != 0 {
		t.Errorf("被拒的写入不该产生主机行：%s", raw)
	}
}

// 单元层：形状检查必须在解码之前发生，且不能因为信封不是合法 JSON 就整个崩掉。
func TestInventoryParsesWithoutTouchingEnvelope(t *testing.T) {
	rows, err := InventoryFromEnvelope([]byte(`{"hosts":[{"name":"n","port":22}]}`))
	if err != nil || len(rows) != 1 || rows[0].Name != "n" {
		t.Fatalf("缺省字段应照常收下：%+v %v", rows, err)
	}
	// 没有 hosts 键（老客户端）不是错误，而是"没有清单可更新"。
	missing, err := InventoryFromEnvelope(envelopeBody(t, "老客户端"))
	if err != nil || missing != nil {
		t.Errorf("没有明文清单应返回 (nil, nil)，实际 %+v %v", missing, err)
	}
	if got, err := InventoryFromEnvelope([]byte("not json at all")); err != nil || got != nil {
		t.Errorf("非 JSON 体应交给信封那条路径报错，这里不该拦：%+v %v", got, err)
	}
	if _, err := InventoryFromEnvelope([]byte(`{"hosts":{"name":"不是数组"}}`)); err == nil {
		t.Error("hosts 不是数组时应报形状错误")
	}
	_ = bytes.MinRead
}

// ---------------------------------------------------------------- 片段数组的解析层（#88）

// 端侧真正发出来的那两行：一行原样正文，一行是客户端嗅探后替换掉的隐去说明。
// 服务端在这里看到的就只是普通字符串 —— 内容判断是端侧做过的事。
const twoSnippetInventory = `[
  {"name":"重启 nginx","group":"生产","body":"systemctl restart nginx","params":"",
   "updatedAt":"2026-10-05T04:00:00Z"},
  {"name":"登生产库","group":"生产","body":"（正文含疑似口令，已在本机隐去，未上传）",
   "params":"host,user","updatedAt":"2026-10-05T04:00:00Z"}
]`

// 片段数组的语义与 hosts 逐条对齐：缺键不是错、空数组要清表、形状与未知键整次拒收。
// 这一组是纯函数层的，所以任何一条挂了都只可能是解析本身变了。
func TestSnippetsInventoryParsesLikeHostsInventory(t *testing.T) {
	// 没有 snippets 键（老客户端）：没有片段可更新，不是错误。
	missing, err := SnippetsFromEnvelope(envelopeBody(t, "老客户端"))
	if err != nil || missing != nil {
		t.Errorf("没有片段数组应返回 (nil, nil)，实际 %+v %v", missing, err)
	}
	if got, err := SnippetsFromEnvelope([]byte("not json at all")); err != nil || got != nil {
		t.Errorf("非 JSON 体应交给信封那条路径报错，这里不该拦：%+v %v", got, err)
	}
	// 空数组与缺键是两件事：删掉最后一条片段必须真的清表。
	empty, err := SnippetsFromEnvelope([]byte(`{"snippets":[]}`))
	if err != nil || empty == nil || len(empty) != 0 {
		t.Errorf("空数组应返回非 nil 的空切片（要清表），实际 %+v %v", empty, err)
	}
	// 形状不合法：键在但不是数组，或者某个值的类型不对。
	for _, bad := range []string{`{"snippets":{"name":"不是数组"}}`, `{"snippets":[{"body":{"a":1}}]}`} {
		if _, err := SnippetsFromEnvelope([]byte(bad)); !errors.Is(err, errInventoryShape) {
			t.Errorf("%s：应报形状错误，实际 %v", bad, err)
		}
	}
	// 合法两行：五个键按端侧的字面存下来，一个都不许多。
	rows, err := SnippetsFromEnvelope([]byte(`{"snippets":` + twoSnippetInventory + `}`))
	if err != nil {
		t.Fatalf("合法数组不该报错：%v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("应有 2 行，实际 %+v", rows)
	}
	first := rows[0]
	if first.Name != "重启 nginx" || first.Group != "生产" || first.Body != "systemctl restart nginx" ||
		first.Params != "" || first.UpdatedAt != "2026-10-05T04:00:00Z" {
		t.Errorf("第一行不对：%+v", first)
	}
	if rows[1].Body != "（正文含疑似口令，已在本机隐去，未上传）" || rows[1].Params != "host,user" {
		t.Errorf("被隐去的那一行要照端侧的字面存：%+v", rows[1])
	}
	// 白名单以外的键同样整次拒绝（它今天不是凭据，明天就是某个新字段的藏身处）。
	if _, err := SnippetsFromEnvelope(
		[]byte(`{"snippets":[{"name":"n","body":"ls","weird":"x"}]}`)); !errors.Is(err, errInventoryShape) {
		t.Errorf("未知键应报形状错误，实际 %v", err)
	}
	// 未知键里命中凭据词根的那一类用 errSecretInInventory 拒：被改坏的客户端完全可以把口令
	// 塞进一个新键里冒充"正文"。注意这里扫的是**键名**，值不参与 —— body 里出现 --password
	// 是端侧已经判过的事。
	for _, key := range []string{"password", "secretMaterial", "passphrase", "privateKeyPath",
		"token", "vault", "credential"} {
		if _, err := SnippetsFromEnvelope([]byte(`{"snippets":[{"name":"n","body":"ls","` +
			key + `":"x"}]}`)); !errors.Is(err, errSecretInInventory) {
			t.Errorf("片段数组里的 %s 应报凭据错误，实际 %v", key, err)
		}
	}
	// 容量护栏只管容量（语义上的"过长不给看"是端侧定的）：超长正文夹到 body 那一列的容量，
	// 名称夹到其余字段那一档，而且按 rune 截、不留半个字。
	long, err := SnippetsFromEnvelope([]byte(`{"snippets":[{"name":"` + strings.Repeat("名", 600) +
		`","body":"` + strings.Repeat("盘", 3000) + `"}]}`))
	if err != nil {
		t.Fatalf("超长值不该把整次数组解析打挂：%v", err)
	}
	if got := utf8.RuneCountInString(long[0].Body); got != snippetBodyMaxRunes {
		t.Errorf("超长正文应夹到 %d 个 rune，实际 %d", snippetBodyMaxRunes, got)
	}
	if got := utf8.RuneCountInString(long[0].Name); got != channelMaxFieldRunes {
		t.Errorf("超长名称应夹到 %d 个 rune，实际 %d", channelMaxFieldRunes, got)
	}
}
