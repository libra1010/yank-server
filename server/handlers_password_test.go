package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// 改管理端登录口令的门禁。这一组要钉住的不是"接口返回 200"，而是四条边界：
// 原口令错就一个字都不改；弱新口令拒收；改完只有当前这张浏览器会话还活着；
// Mac 客户端的设备令牌不受网页改密的影响。响应里绝不回显任何口令。

const (
	oldPass = "dropterm-old-2026"
	newPass = "dropterm-new-2026"
)

func (e *env) loginAs(user, password string) (string, int) {
	e.t.Helper()
	res, body := e.json("POST", "/api/login", "", map[string]string{"user": user, "password": password})
	if res.StatusCode != http.StatusOK {
		return "", res.StatusCode
	}
	var session struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(body, &session)
	return session.Token, res.StatusCode
}

func (e *env) changePassword(oldPassword, newPassword string) (*http.Response, []byte) {
	e.t.Helper()
	return e.json("POST", "/api/password", e.token,
		map[string]string{"oldPassword": oldPassword, "newPassword": newPassword})
}

func reasonOf(t *testing.T, body []byte) string {
	t.Helper()
	var r struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("响应不是 JSON：%s", body)
	}
	return r.Reason
}

func TestPasswordChangeWrongOldChangesNothing(t *testing.T) {
	e := newEnv(t)
	e.enroll("admin", oldPass)
	res, body := e.changePassword("wrong-old-password", newPass)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("原口令错该 403，实得 %d %s", res.StatusCode, body)
	}
	if got := reasonOf(t, body); got != "原口令不正确" {
		t.Errorf("说法不对：%q", got)
	}
	// 负向对照：被拒的那次新口令绝不能生效。
	if _, status := e.loginAs("admin", newPass); status != http.StatusUnauthorized {
		t.Fatalf("错原口令那次竟把口令改成了新值（登录状态 %d）", status)
	}
	if _, status := e.loginAs("admin", oldPass); status != http.StatusOK {
		t.Fatalf("原口令应当还能登录，实得 %d", status)
	}
}

func TestPasswordChangeInputValidation(t *testing.T) {
	e := newEnv(t)
	e.enroll("admin", oldPass)
	cases := []struct {
		name                  string
		old, news, wantReason string
	}{
		{"空原口令", "", newPass, "原口令和新口令都要填"},
		{"空新口令", oldPass, "", "原口令和新口令都要填"},
		{"新口令太短", oldPass, "short9", "管理端登录口令至少需要 10 个字符"},
		{"新旧同值", oldPass, oldPass, "新口令不能和原口令一样"},
	}
	for _, c := range cases {
		res, body := e.changePassword(c.old, c.news)
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s：该 400，实得 %d %s", c.name, res.StatusCode, body)
			continue
		}
		if got := reasonOf(t, body); got != c.wantReason {
			t.Errorf("%s：说法是 %q，想要 %q", c.name, got, c.wantReason)
		}
		// 任何一次失败都不回显输入的口令。
		if strings.Contains(string(body), newPass) || strings.Contains(string(body), oldPass) {
			t.Errorf("%s：响应里回显了口令：%s", c.name, body)
		}
	}
	// 请求体不是 JSON 也要挡在写库之前。
	res, body := e.call("POST", "/api/password", e.token, []byte("{not json"))
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("非法 JSON 该 400，实得 %d %s", res.StatusCode, body)
	}
}

func TestPasswordChangeOnlyCurrentSessionSurvives(t *testing.T) {
	e := newEnv(t)
	e.enroll("admin", oldPass)
	// 另一台笔记本上的浏览器会话。
	other, status := e.loginAs("admin", oldPass)
	if status != http.StatusOK {
		t.Fatalf("第二个会话登录失败：%d", status)
	}
	res, body := e.changePassword(oldPass, newPass)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("改密该 200，实得 %d %s", res.StatusCode, body)
	}
	if strings.Contains(string(body), newPass) {
		t.Errorf("成功响应回显了新口令：%s", body)
	}
	if _, status := e.loginAs("admin", oldPass); status != http.StatusUnauthorized {
		t.Errorf("旧口令竟然还能登录（%d）", status)
	}
	if _, status := e.loginAs("admin", newPass); status != http.StatusOK {
		t.Errorf("新口令登录失败（%d）", status)
	}
	call := func(token string) int {
		res, _ := e.call("GET", "/api/hosts", token, nil)
		return res.StatusCode
	}
	if got := call(other); got != http.StatusUnauthorized {
		t.Errorf("别的浏览器会话该作废，实得 %d", got)
	}
	if got := call(e.token); got != http.StatusOK {
		t.Errorf("当前会话不该被自己踢下线，实得 %d", got)
	}
}

func TestPasswordChangeKeepsDeviceSync(t *testing.T) {
	e := newEnv(t)
	e.enroll("admin", oldPass)
	e.pairDevice("MacBook-Pro")
	if res, body := e.putBlob(envelopeBody(t, "hosts-before-change"), "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("改密前该能同步，实得 %d %s", res.StatusCode, body)
	}
	if res, body := e.changePassword(oldPass, newPass); res.StatusCode != http.StatusOK {
		t.Fatalf("改密失败：%d %s", res.StatusCode, body)
	}
	// 改的是网页登录口令，不该把终端的同步通道一起掐了。
	res, _ := e.call("GET", "/api/hosts", e.device, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("设备令牌改密后失效：%d", res.StatusCode)
	}
	blob, _ := e.call("GET", "/api/blob", e.device, nil)
	if blob.StatusCode != http.StatusOK {
		t.Fatalf("设备读取同步内容失败：%d", blob.StatusCode)
	}
}

func TestPasswordChangeRequiresWebSession(t *testing.T) {
	e := newEnv(t)
	e.enroll("admin", oldPass)
	e.pairDevice("MacBook-Air")
	// 设备令牌能同步，但不能改管理端口令。
	res, body := e.json("POST", "/api/password", e.device,
		map[string]string{"oldPassword": oldPass, "newPassword": newPass})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("设备令牌该 401，实得 %d %s", res.StatusCode, body)
	}
	if _, status := e.loginAs("admin", newPass); status != http.StatusUnauthorized {
		t.Errorf("被拒的调用竟改了口令（%d）", status)
	}
}
