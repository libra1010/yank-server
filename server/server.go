package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	store    *Store
	sessions *sessionTable
	limiter  *ipLimiter
	// pairTTL is how long a pairing code stays valid: 5 minutes, because copying a code by hand
	// from one screen to another while the two machines are being set up does not fit in 60
	// seconds. What keeps the longer window honest is that the code is single-use (TakePairCode
	// deletes the row as it reads it) and the per-IP exchange limiter stays at one minute.
	pairTTL time.Duration
	// openSignup 决定 /api/register 还开不开。默认开着（自建服务第一次要能建号），但公网部署
	// 应该用 SYNCD_OPEN_SIGNUP=0 关掉：这个服务存的是一台台机器的口令信封，"谁都能注册一个账号"
	// 不是它该有的形状。关掉之后老账号照常登录、照常配对设备，只有新建账号这条路封了。
	openSignup bool
}

// 通道层没有"启动时开关"这一说了：它按账号在管理页面上配（见 channel_api.go）。
// 所以新建服务永远从不透明模式起步，第一个信封是通道形状而账号没配口令时，服务端照旧只存密文。
func NewServer(store *Store) *Server {
	return &Server{store: store, sessions: newSessionTable(),
		limiter: newIPLimiter(10, time.Minute), pairTTL: 5 * time.Minute, openSignup: true}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", s.handleRegister)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.requireUser(s.handleLogout))
	mux.HandleFunc("POST /api/password", s.requireUser(s.handlePassword))
	mux.HandleFunc("POST /api/pair", s.requireUser(s.handlePair))
	mux.HandleFunc("POST /api/pair/exchange", s.handlePairExchange)
	mux.HandleFunc("PUT /api/blob", s.requireDevice(s.handleBlobPut))
	mux.HandleFunc("GET /api/blob", s.requireAny(s.handleBlobGet))
	mux.HandleFunc("GET /api/blob/history", s.requireAny(s.handleHistory))
	mux.HandleFunc("GET /api/blob/at/{revision}", s.requireAny(s.handleBlobAt))
	// Rolling back is a user action: the console has a session, not a device token, and the
	// server is only copying ciphertext it cannot read.
	mux.HandleFunc("POST /api/blob/rollback", s.requireUser(s.handleRollback))
	mux.HandleFunc("GET /api/devices", s.requireUser(s.handleDevices))
	mux.HandleFunc("POST /api/devices/revoke", s.requireUser(s.handleRevoke))
	// The decrypted inventory: readable with a session token OR a device token, like GET /api/blob.
	mux.HandleFunc("GET /api/hosts", s.requireAny(s.handleHosts))
	// 片段清单同权、同一个理由（SPEC §5.1）：它也是客户端有意明文上传的那一小块。
	mux.HandleFunc("GET /api/snippets", s.requireAny(s.handleSnippets))
	// Channel key management is a console-only, session-only capability: a device token belongs to
	// an app, and an app must not be able to re-key the server.
	mux.HandleFunc("GET /api/channel", s.requireUser(s.handleChannelGet))
	mux.HandleFunc("POST /api/channel", s.requireUser(s.handleChannelSet))
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "dialect": s.store.kind,
			"version": version, "openSignup": s.openSignup})
	})
	// The Vue console is embedded; anything not under /api is a client-side route.
	mux.Handle("/", staticHandler())
	return mux
}

// ---------------------------------------------------------------- plumbing

type apiError struct {
	Status int    `json:"-"`
	Reason string `json:"reason"`
}

func (e apiError) Error() string { return e.Reason }

func fail(w http.ResponseWriter, status int, format string, args ...any) {
	writeJSON(w, status, map[string]string{"reason": fmt.Sprintf(format, args...)})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func decodeJSON(r *http.Request, into any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

// ---------------------------------------------------------------- auth

type sessionTable struct {
	mu sync.Mutex
	// token hash -> user id + expiry. Sessions are process-local: a restart logs the web UI
	// out, which is the right failure direction for an admin console.
	rows map[string]time.Time
	user map[string]string
}

func newSessionTable() *sessionTable {
	return &sessionTable{rows: map[string]time.Time{}, user: map[string]string{}}
}

func (t *sessionTable) issue(userID string, ttl time.Duration) string {
	token := randomID(32)
	t.mu.Lock()
	defer t.mu.Unlock()
	key := sha256Hex(token)
	t.rows[key] = time.Now().Add(ttl)
	t.user[key] = userID
	return token
}

func (t *sessionTable) lookup(token string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := sha256Hex(token)
	expiry, ok := t.rows[key]
	if !ok {
		return "", false
	}
	if expiry.Before(time.Now()) {
		delete(t.rows, key)
		delete(t.user, key)
		return "", false
	}
	return t.user[key], true
}

func (t *sessionTable) drop(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := sha256Hex(token)
	delete(t.rows, key)
	delete(t.user, key)
}

// dropUserExcept 把这个账号在别处的浏览器会话全部踢掉，只留下递进来的这一张。
// 改完登录口令正该如此：旧口令铸出的令牌不该还能继续用。
func (t *sessionTable) dropUserExcept(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	keep := sha256Hex(token)
	userID, ok := t.user[keep]
	if !ok {
		return
	}
	for key, owner := range t.user {
		if owner == userID && key != keep {
			delete(t.rows, key)
			delete(t.user, key)
		}
	}
}

func bearer(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if len(value) > 7 && strings.EqualFold(value[:7], "bearer ") {
		return value[7:]
	}
	return ""
}

// requireDevice guards the paths a Mac app uses. Device tokens may only touch their own
// account's blob, which is enforced by resolving the token to (device, user) here.
func (s *Server) requireDevice(next func(http.ResponseWriter, *http.Request, string, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearer(r)
		if token == "" {
			fail(w, http.StatusUnauthorized, "缺少设备令牌")
			return
		}
		deviceID, userID, err := s.store.DeviceByTokenHash(r.Context(), sha256Hex(token))
		if err != nil {
			fail(w, http.StatusUnauthorized, "设备令牌无效或已吊销")
			return
		}
		if err := s.store.TouchDevice(r.Context(), deviceID, time.Now().UTC()); err != nil {
			// A stale last_seen is not a reason to fail the user's sync.
			_ = err
		}
		next(w, r, userID, deviceID)
	}
}

func (s *Server) requireUser(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := s.sessions.lookup(bearer(r))
		if !ok {
			fail(w, http.StatusUnauthorized, "请先登录")
			return
		}
		next(w, r, userID)
	}
}

// requireAny lets the web console and the app read the same endpoint.
func (s *Server) requireAny(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if userID, ok := s.sessions.lookup(bearer(r)); ok {
			next(w, r, userID)
			return
		}
		token := bearer(r)
		if token == "" {
			fail(w, http.StatusUnauthorized, "需要登录或设备令牌")
			return
		}
		_, userID, err := s.store.DeviceByTokenHash(r.Context(), sha256Hex(token))
		if err != nil {
			fail(w, http.StatusUnauthorized, "令牌无效")
			return
		}
		next(w, r, userID)
	}
}

// ---------------------------------------------------------------- rate limit

type ipLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newIPLimiter(limit int, window time.Duration) *ipLimiter {
	return &ipLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

// allow records one attempt and reports whether it is inside the window's budget. Without this,
// /api/login is an offline-cracking oracle sitting on a public port.
func (l *ipLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.hits[key][:0:len(l.hits[key])]
	for _, at := range l.hits[key] {
		if now.Sub(at) < l.window {
			kept = append(kept, at)
		}
	}
	if len(kept) >= l.limit {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	if len(l.hits) > 4096 {
		for ip, list := range l.hits {
			if len(list) == 0 || now.Sub(list[len(list)-1]) > l.window {
				delete(l.hits, ip)
			}
		}
	}
	return true
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}

func revisionHeader(r *http.Request) (int64, error) {
	value := strings.Trim(r.Header.Get("If-Match"), "\"")
	if value == "" {
		return -1, errors.New("缺少 If-Match")
	}
	return strconv.ParseInt(value, 10, 64)
}
