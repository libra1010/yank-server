package main

// Tests for the page-configured channel passphrase. The shape under test is a state machine, not a
// field: 没口令 → 通道信封只当不透明密文存；口令设上 → **已经躺在库里**的那份信封立刻可读并建好
// 索引；口令填错 → 旧清单还在；清空 → 回到未启用，但已入库的清单不跟着消失。每一次转移都只从
// 外面看（HTTP + hosts 表），并且检查口令本身有没有从服务端漏出去。

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// chanC 是页面上"改对的那一句"，用不到的地方也提醒 reader：口令就是这么短的一句话。
const chanC = "把这一段当成口令来填"

type channelState struct {
	Enabled     bool   `json:"enabled"`
	Source      string `json:"source"`
	Fingerprint string `json:"fingerprint"`
}

func (e *env) channelGet(auth string) (channelState, *http.Response, []byte) {
	e.t.Helper()
	res, body := e.call("GET", "/api/channel", auth, nil)
	var st channelState
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &st); err != nil {
			e.t.Fatalf("GET /api/channel 响应不是合法 JSON：%v %s", err, body)
		}
	}
	return st, res, body
}

func (e *env) channelSet(auth, passphrase string) (*http.Response, []byte) {
	e.t.Helper()
	return e.json("POST", "/api/channel", auth, map[string]string{"key": passphrase})
}

// 没配口令时通道信封照旧存成不透明密文（这是兼容性承诺），而配上口令的当下就把存量字节变成
// 清单——不用重推、不用重启。这个接口存在的全部理由就是这一条。
func TestChannelKeyFromPageUnlocksStoredEnvelope(t *testing.T) {
	e, _, _ := newChanEnv(t, "")

	res, body := e.putBlob(sealManifest(t, chanA, oneHostManifest(t)), "0")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("无口令时通道信封应照旧存为密文：%d %s", res.StatusCode, body)
	}
	if st, res, _ := e.channelGet(e.token); st.Enabled || st.Source != "none" || res.StatusCode != http.StatusOK {
		t.Fatalf("初始状态应是 none/未启用，实际 %+v %d", st, res.StatusCode)
	}
	// 用户 2026-10-03 拍板改了口径：清单不再"要先有通道密钥才给看"。没口令、客户端也没传明文
	// 清单时，接口回 200 + 空数组（真的还没有数据），而不是 503 把功能没开的责任推给读的人。
	if rows, res, raw := getHosts(t, e, e.token); res.StatusCode != http.StatusOK || len(rows) != 0 {
		t.Fatalf("未启用口令也该 200（空清单），实际 %d %s", res.StatusCode, raw)
	}

	res, body = e.channelSet(e.token, chanA)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("页面配置口令失败：%d %s", res.StatusCode, body)
	}
	if strings.Contains(string(body), chanA) {
		t.Errorf("响应把通道口令原样回显了：%s", body)
	}
	st, _, _ := e.channelGet(e.token)
	if !st.Enabled || st.Source != "page" || st.Fingerprint != ChannelFingerprint(chanA) {
		t.Fatalf("应报告 page 来源与正确指纹，实际 %+v", st)
	}

	rows, res, raw := getHosts(t, e, e.token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("配置口令后 /api/hosts 应可用，实际 %d %s", res.StatusCode, raw)
	}
	if len(rows) != 1 || rows[0].Hostname != "nas.lan" {
		t.Fatalf("存量信封应在配置口令当下就建立索引，实际 %+v", rows)
	}

	// 清空回到未启用。
	if res, body = e.channelSet(e.token, ""); res.StatusCode != http.StatusOK {
		t.Fatalf("清除口令失败：%d %s", res.StatusCode, body)
	}
	if st, _, _ := e.channelGet(e.token); st.Enabled || st.Source != "none" || st.Fingerprint != "" {
		t.Fatalf("清除后应回到未启用，实际 %+v", st)
	}
	// 清除口令不再让清单消失（用户 2026-10-03 改了口径）：库里的行是客户端明文传来的既有数据，
	// 服务端不会因为"这一层口令被撤了"就把用户已经看到的东西删掉。
	rows, res, raw = getHosts(t, e, e.token)
	if res.StatusCode != http.StatusOK {
		t.Errorf("清除口令后清单应仍是 200，实际 %d %s", res.StatusCode, raw)
	}
	if len(rows) != 1 {
		t.Errorf("清除口令不该毁掉已入库的清单，实际 %s", raw)
	}
}

// 配上口令之后的推送要用页面那一句来解，而不是启动参数那把（已经不存在了）——所以解析器必须
// 每个请求现查，不能在启动时抓一份快照。
func TestChannelKeyFromPageAppliesToNextPush(t *testing.T) {
	e, _, _ := newChanEnv(t, "")
	if res, body := e.channelSet(e.token, chanA); res.StatusCode != http.StatusOK {
		t.Fatalf("配置口令失败：%d %s", res.StatusCode, body)
	}
	res, body := e.putBlob(sealManifest(t, chanA, twoHostManifest(t)), "0")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("用页面口令推送到通道信封失败：%d %s", res.StatusCode, body)
	}
	rows, _, _ := getHosts(t, e, e.token)
	if len(rows) != 2 {
		t.Fatalf("应索引到两条主机，实际 %+v", rows)
	}

	// 另一句口令封的信封必须被直接拒掉，绝不静默落库。
	res, body = e.putBlob(sealManifest(t, chanB, oneHostManifest(t)), "2")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("口令不符的信封必须被拒，实际 %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "通道密钥") {
		t.Errorf("拒绝理由应指向通道密钥，实际 %s", body)
	}
}

// reindexChannel 的反向对照：页面上把口令填错，不该让人丢掉口令填对时已经建立的清单。
func TestChannelWrongKeyKeepsOldInventory(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	if res, body := e.putBlob(sealManifest(t, chanA, twoHostManifest(t)), "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("推送失败：%d %s", res.StatusCode, body)
	}
	if st, _, _ := e.channelGet(e.token); st.Source != "page" {
		t.Fatalf("页面配过口令之后应报告 page 来源，实际 %+v", st)
	}

	if res, body := e.channelSet(e.token, chanB); res.StatusCode != http.StatusOK {
		t.Fatalf("配置错误口令不应报错（它只是打不开存量信封）：%d %s", res.StatusCode, body)
	}
	rows, res, raw := getHosts(t, e, e.token)
	if res.StatusCode != http.StatusOK || len(rows) != 2 {
		t.Fatalf("写错的口令不该清空既有索引，实际 %d %s %+v", res.StatusCode, raw, rows)
	}
	if st, _, _ := e.channelGet(e.token); st.Fingerprint != ChannelFingerprint(chanB) {
		t.Errorf("指纹应跟着页面口令变化，实际 %+v", st)
	}

	// 改回正确的那一句立刻生效，不用再推一次。
	if res, body := e.channelSet(e.token, chanA); res.StatusCode != http.StatusOK {
		t.Fatalf("改回正确口令失败：%d %s", res.StatusCode, body)
	}
	if st, _, _ := e.channelGet(e.token); st.Fingerprint != ChannelFingerprint(chanA) {
		t.Fatalf("改回正确口令后指纹应随之恢复，实际 %+v", st)
	}
}

// 口令是给人念的，不是 64 个字符的十六进制：太短的一律 400，理由是中文，而且库里的旧状态不动。
func TestChannelKeyTooShortRejectedKeepsState(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	for _, tooShort := range []string{"1234567", "口令太短了", "   abc   ", strings.Repeat("字", 7)} {
		res, body := e.channelSet(e.token, tooShort)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("口令 %q 应 400，实际 %d %s", tooShort, res.StatusCode, body)
		}
		if !strings.Contains(string(body), "至少") {
			t.Errorf("400 的理由应说明长度下限，实际 %s", body)
		}
	}
	st, _, _ := e.channelGet(e.token)
	if st.Fingerprint != ChannelFingerprint(chanA) {
		t.Errorf("被拒的短口令不该改动既有状态，实际 %+v", st)
	}
}

func TestChannelKeyAPIRejectsNonUsers(t *testing.T) {
	e, _, _ := newChanEnv(t, "")

	if res, _ := e.channelSet("", chanC); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("未登录配置口令应 401，实际 %d", res.StatusCode)
	}
	if _, res, _ := e.channelGet(e.token); res.StatusCode != http.StatusOK {
		t.Errorf("已登录读取状态应 200，实际 %d", res.StatusCode)
	}
	// 设备令牌是 App 的凭据；App 不该能替服务端改钥匙。
	res, body := e.call("GET", "/api/channel", e.device, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("设备令牌读通道状态应 401，实际 %d %s", res.StatusCode, body)
	}
	req, err := http.NewRequest("POST", e.srv.URL+"/api/channel",
		strings.NewReader(`{"key":"`+chanC+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+e.device)
	res, err = e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("设备令牌配置口令应 401，实际 %d", res.StatusCode)
	}
}

// 口令只进不出。页面能看到的只有 6 位指纹；库里那一行存的是口令本身，这一点在界面上写着，
// 所以接口把口令回显出去就等于把"谁拿到库文件谁解得开"升级成"任何一份响应快照都能看见"。
func TestChannelKeyNeverLeavesServer(t *testing.T) {
	e, _, _ := newChanEnv(t, "")
	if res, body := e.putBlob(sealManifest(t, chanC, oneHostManifest(t)), "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("未启用时通道信封应照旧存下：%d %s", res.StatusCode, body)
	}
	res, body := e.channelSet(e.token, chanC)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("配置失败：%d %s", res.StatusCode, body)
	}
	_, raw := e.call("GET", "/api/blob", e.token, nil)
	for name, down := range map[string][]byte{"配置响应": body, "状态接口": raw} {
		if strings.Contains(string(down), chanC) {
			t.Errorf("%s 里出现了通道口令本身：%s", name, down)
		}
	}
	st, _, statusBody := e.channelGet(e.token)
	if !st.Enabled || st.Fingerprint != ChannelFingerprint(chanC) {
		t.Fatalf("状态应是 page/正确指纹，实际 %+v %s", st, statusBody)
	}
	if strings.Contains(string(statusBody), chanC) {
		t.Errorf("状态接口回显了口令：%s", statusBody)
	}
	_, _, hostsBody := getHosts(t, e, e.token)
	if strings.Contains(string(hostsBody), chanC) {
		t.Errorf("GET /api/hosts 回显了通道口令：%s", hostsBody)
	}
}
