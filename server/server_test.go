package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

type env struct {
	t      *testing.T
	srv    *httptest.Server
	token  string // web session token
	device string // device token
}

func newEnv(t *testing.T) *env {
	t.Helper()
	store, err := Open("sqlite://" + filepath.Join(t.TempDir(), "sync.db"))
	if err != nil {
		t.Fatalf("开库失败：%v", err)
	}
	ctx := t.Context()
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败：%v", err)
	}
	srv := httptest.NewServer(NewServer(store).Handler())
	t.Cleanup(func() { srv.Close(); _ = store.Close() })
	return &env{t: t, srv: srv}
}

func (e *env) call(method, path, auth string, body []byte) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("%s %s 请求失败：%v", method, path, err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res, out
}

func (e *env) json(method, path, auth string, body any) (*http.Response, []byte) {
	e.t.Helper()
	raw := []byte("{}")
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			e.t.Fatal(err)
		}
		raw = encoded
	}
	return e.call(method, path, auth, raw)
}

func (e *env) enroll(user, password string) {
	e.t.Helper()
	res, _ := e.json("POST", "/api/register", "", map[string]string{"user": user, "password": password})
	if res.StatusCode != http.StatusCreated {
		e.t.Fatalf("注册失败：%d", res.StatusCode)
	}
	res, body := e.json("POST", "/api/login", "", map[string]string{"user": user, "password": password})
	if res.StatusCode != http.StatusOK {
		e.t.Fatalf("登录失败：%d %s", res.StatusCode, body)
	}
	var session struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &session); err != nil || session.Token == "" {
		e.t.Fatalf("登录响应里没有令牌：%s", body)
	}
	e.token = session.Token
}

func (e *env) pairDevice(name string) {
	e.t.Helper()
	res, body := e.json("POST", "/api/pair", e.token, nil)
	if res.StatusCode != http.StatusOK {
		e.t.Fatalf("配对码申请失败：%d %s", res.StatusCode, body)
	}
	var code struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &code)
	res, body = e.json("POST", "/api/pair/exchange", "",
		map[string]string{"code": code.Code, "deviceName": name})
	if res.StatusCode != http.StatusOK {
		e.t.Fatalf("配对码换取令牌失败：%d %s", res.StatusCode, body)
	}
	var device struct {
		DeviceToken string `json:"deviceToken"`
	}
	_ = json.Unmarshal(body, &device)
	if device.DeviceToken == "" {
		e.t.Fatalf("换取响应缺 deviceToken：%s", body)
	}
	e.device = device.DeviceToken
}

func envelopeBody(t *testing.T, text string) []byte {
	t.Helper()
	body, err := SealWith("passphrase-under-test", bytes.Repeat([]byte{7}, 16),
		bytes.Repeat([]byte{3}, 12), []byte(text), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRegisterLoginAndWeakInputRejected(t *testing.T) {
	e := newEnv(t)
	e.enroll("ops@example", "a-long-enough-pass")

	res, _ := e.json("POST", "/api/register", "", map[string]string{"user": "ops@example", "password": "another-long-pass"})
	if res.StatusCode != http.StatusConflict {
		t.Errorf("重复账号应 409，实际 %d", res.StatusCode)
	}
	res, _ = e.json("POST", "/api/register", "", map[string]string{"user": "second", "password": "short"})
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("弱口令应 400，实际 %d", res.StatusCode)
	}
	res, _ = e.json("POST", "/api/register", "", map[string]string{"user": "bad name", "password": "long-enough-pass"})
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("带空格的账号名应 400，实际 %d", res.StatusCode)
	}
	res, body := e.json("POST", "/api/login", "", map[string]string{"user": "ops@example", "password": "wrong-password"})
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("错口令应 401，实际 %d %s", res.StatusCode, body)
	}
}

func TestBlobRoundTripAndRevision(t *testing.T) {
	e := newEnv(t)
	e.enroll("devops", "a-long-enough-pass")
	e.pairDevice("MacBook-Air")

	// Empty account: 204, not a fabricated empty document.
	res, _ := e.call("GET", "/api/blob", e.device, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("空账号应 204，实际 %d", res.StatusCode)
	}

	first := envelopeBody(t, `{"revision":1}`)
	// If-Match is mandatory: a client always states which revision it merged against, so a blind
	// overwrite of a peer's newer data is not expressible. "0" means "I believe there is none".
	res, body := e.putBlob(first, "0")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("首次写入应成功：%d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), `"revision":1`) {
		t.Errorf("返回的修订号不对：%s", body)
	}

	second := envelopeBody(t, `{"revision":2}`)
	// Stale expectation: the server must refuse rather than clobber, and say what it holds.
	res, body = e.putBlob(second, "0")
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("旧版本号写入应 409，实际 %d %s", res.StatusCode, body)
	}
	if got := res.Header.Get("X-CURRENT-REVISION"); got != "1" {
		t.Errorf("409 应带上当前版本号 1，实际 %q", got)
	}

	res, body = e.putBlob(second, "1")
	if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"revision":2`) {
		t.Fatalf("带正确 If-Match 的写入应到第 2 版：%d %s", res.StatusCode, body)
	}

	res, got := e.call("GET", "/api/blob", e.device, nil)
	if res.StatusCode != http.StatusOK || !bytes.Equal(got, second) {
		t.Errorf("读回的最新信封与写入不一致：%d %s", res.StatusCode, got)
	}
	if res.Header.Get("ETag") != "2" {
		t.Errorf("ETag 应是 2，实际 %q", res.Header.Get("ETag"))
	}
	// Rollback data must still be there.
	res, old := e.call("GET", "/api/blob/at/1", e.token, nil)
	if res.StatusCode != http.StatusOK || !bytes.Equal(old, first) {
		t.Errorf("第 1 版历史信封读不回来：%d %s", res.StatusCode, old)
	}
	res, hist := e.call("GET", "/api/blob/history", e.token, nil)
	var history struct {
		Items []HistoryRow `json:"items"`
	}
	if err := json.Unmarshal(hist, &history); res.StatusCode != 200 || err != nil {
		t.Fatalf("历史接口异常：%d %v %s", res.StatusCode, err, hist)
	}
	if len(history.Items) != 2 {
		t.Errorf("应有 2 条历史，实际 %d", len(history.Items))
	}
	for _, item := range history.Items {
		if item.Bytes == 0 {
			t.Error("历史条目没带字节数")
		}
	}
}

func TestGarbageEnvelopeAndAuthZ(t *testing.T) {
	e := newEnv(t)
	e.enroll("devops", "a-long-enough-pass")
	e.pairDevice("MacBook-Air")

	res, _ := e.call("PUT", "/api/blob", e.device, []byte(`{"formatVersion":1}`))
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("非信封内容应 415，实际 %d", res.StatusCode)
	}
	res, _ = e.call("PUT", "/api/blob", "", envelopeBody(t, "x"))
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("无令牌写入应 401，实际 %d", res.StatusCode)
	}
	res, _ = e.call("GET", "/api/blob", "not-a-real-token", nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("假令牌读取应 401，实际 %d", res.StatusCode)
	}
	// A pairing code is single-use.
	res, body := e.json("POST", "/api/pair", e.token, nil)
	var code struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &code)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("配对码申请失败")
	}
	if res, _ = e.json("POST", "/api/pair/exchange", "", map[string]string{"code": code.Code}); res.StatusCode != http.StatusOK {
		t.Fatal("首次兑换应成功")
	}
	if res, _ = e.json("POST", "/api/pair/exchange", "", map[string]string{"code": code.Code}); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("配对码重放应被拒，实际 %d", res.StatusCode)
	}
}

func TestRevokeDeviceKillsItsToken(t *testing.T) {
	e := newEnv(t)
	e.enroll("devops", "a-long-enough-pass")
	e.pairDevice("MacBook-Pro")

	res, body := e.call("GET", "/api/devices", e.token, nil)
	var listing struct {
		Items []Device `json:"items"`
	}
	if err := json.Unmarshal(body, &listing); err != nil || res.StatusCode != 200 ||
		len(listing.Items) != 1 {
		t.Fatalf("设备列表异常：%d %v %s", res.StatusCode, err, body)
	}
	res, _ = e.json("POST", "/api/devices/revoke", e.token,
		map[string]string{"deviceId": listing.Items[0].ID})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("吊销失败：%d", res.StatusCode)
	}
	res, _ = e.call("GET", "/api/blob", e.device, nil)
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("吊销后旧令牌应 401，实际 %d", res.StatusCode)
	}
	// The account's data survives: it belongs to the user, not to the lost laptop.
	res, _ = e.call("GET", "/api/blob", e.token, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("吊销不应动数据，读取应 204，实际 %d", res.StatusCode)
	}
}

// TestPairCodeIgnoresDashesAndCase pins the bug where the stored hash kept the separator but the
// lookup stripped it: every exchange 401'd.
func TestPairCodeIgnoresDashesAndCase(t *testing.T) {
	e := newEnv(t)
	e.enroll("devops", "a-long-enough-pass")
	res, body := e.json("POST", "/api/pair", e.token, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("配对码申请失败：%d %s", res.StatusCode, body)
	}
	var issued struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &issued)
	typed := strings.ReplaceAll(strings.ToLower(issued.Code), "-", "")
	res, body = e.json("POST", "/api/pair/exchange", "", map[string]string{"code": typed})
	if res.StatusCode != http.StatusOK {
		t.Errorf("去掉分隔符的小写配对码应能兑换：%d %s", res.StatusCode, body)
	}
}

func TestLoginRateLimited(t *testing.T) {
	e := newEnv(t)
	e.enroll("devops", "a-long-enough-pass")
	for i := 0; i < 12; i++ {
		res, _ := e.json("POST", "/api/login", "", map[string]string{"user": "devops", "password": "wrong-wrong"})
		if res.StatusCode == http.StatusTooManyRequests {
			return
		}
	}
	t.Error("连续错口令没有触发限流")
}

// putBlob pushes an envelope as the enrolled device, stating the revision it merged against.
func (e *env) putBlob(body []byte, ifMatch string) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequest("PUT", e.srv.URL+"/api/blob", bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+e.device)
	req.Header.Set("Content-Type", "application/json")
	if ifMatch != "" {
		req.Header.Set("If-Match", ifMatch)
	}
	res, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatalf("PUT /api/blob 请求失败：%v", err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res, out
}

// The web console only ever holds a session token, and PUT /api/blob is device-only by design,
// so "回退到这一版" needs its own user-authenticated route. It moves ciphertext forward: the
// server cannot read what it is restoring.
func TestRollbackFromWebSession(t *testing.T) {
	e := newEnv(t)
	e.enroll("root", "Passw0rd!23")
	e.pairDevice("mac-a")
	first := envelopeBody(t, "第一版")
	if res, body := e.putBlob(first, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("首版写入失败：%d %s", res.StatusCode, body)
	}
	second := envelopeBody(t, "第二版")
	if res, body := e.putBlob(second, "1"); res.StatusCode != http.StatusOK {
		t.Fatalf("第二版写入失败：%d %s", res.StatusCode, body)
	}
	res, body := e.json("POST", "/api/blob/rollback", e.token, map[string]int64{"revision": 1})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("会话回退被拒：%d %s", res.StatusCode, body)
	}
	res, pulled := e.call("GET", "/api/blob", e.token, nil)
	if res.StatusCode != http.StatusOK || string(pulled) != string(first) {
		t.Fatalf("回退后拉到的不是第一版：%d %s", res.StatusCode, pulled)
	}
	if rev := res.Header.Get("ETag"); rev != "3" {
		t.Fatalf("回退应当前滚成新版本而不是改写历史，ETag=%s", rev)
	}
	if res, _ := e.json("POST", "/api/blob/rollback", e.token, map[string]int64{"revision": 99}); res.StatusCode != http.StatusNotFound {
		t.Fatalf("不存在的版本应当 404，得到 %d", res.StatusCode)
	}
	if res, _ := e.json("POST", "/api/blob/rollback", "", map[string]int64{"revision": 1}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("匿名回退应当 401，得到 %d", res.StatusCode)
	}
	// A device token must not be able to roll back through the user route either way; the
	// session table is what authorises it.
	if res, _ := e.json("POST", "/api/blob/rollback", e.device, map[string]int64{"revision": 2}); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("设备令牌走用户路由应当 401，得到 %d", res.StatusCode)
	}
}
