package main

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// 部署方式就是把这个 API 挂在 CDN/反代后面（SPEC §7）。中间层一旦按 URL 缓存 GET /api/blob，
// 两台设备会互相读到对方那一份，版本号也会停在被缓存的旧版 —— 客户端之后推什么都被 409 挡回
// 「请先拉取合并」，一台机器就能把自己锁死。所以每个 /api 响应都必须写明不许缓存。
func TestAPINeverCacheable(t *testing.T) {
	e := newEnv(t)
	e.enroll("devops", "a-long-enough-pass")
	e.pairDevice("MacBook-Air")

	// 204 那一格也要盖：空账号同样是一次按令牌区分的读取，缓存了它等于让后面每个人都拉不到。
	res, _ := e.call(http.MethodGet, "/api/blob", e.device, nil)
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("空账号的 GET /api/blob 应带 Cache-Control: no-store，实际 %q", got)
	}
	if put, _ := e.putBlob(envelopeBody(t, `{"revision":1}`), "0"); put.StatusCode != http.StatusOK {
		t.Fatalf("首发推送应 200，实际 %d", put.StatusCode)
	}
	res, body := e.call(http.MethodGet, "/api/blob", e.device, nil)
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("GET /api/blob 应带 Cache-Control: no-store，实际 %q", got)
	}
	// 版本号还得是客户端能解析成整数的形状：它拿这个值当 If-Match 用。
	etag := res.Header.Get("ETag")
	if _, err := strconv.ParseInt(strings.Trim(etag, `"`), 10, 64); err != nil {
		t.Errorf("ETag 应是可读的十进制版本号，实际 %q（%v）", etag, err)
	}
	if len(body) == 0 {
		t.Error("拉回应带正文")
	}
	// 只管 /api：控制台那些带 hash 的静态件被顺手盖上 no-store，会退化成每次全量下载。
	static, _ := e.call(http.MethodGet, "/brand.svg", "", nil)
	if strings.EqualFold(static.Header.Get("Cache-Control"), "no-store") {
		t.Error("静态件不该被盖上 no-store")
	}
}
