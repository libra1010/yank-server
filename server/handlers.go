package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxEnvelopeBytes = 8 * 1024 * 1024

func validUserName(name string) bool {
	if len(name) < 3 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '-' || r == '_' || r == '@' || r > 127) {
			return false
		}
	}
	return true
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !s.openSignup {
		fail(w, http.StatusForbidden, "这台服务已关闭注册（SYNCD_OPEN_SIGNUP=0）；要加账号请先打开它再重启")
		return
	}
	if !s.limiter.allow("register:"+clientIP(r), time.Now()) {
		fail(w, http.StatusTooManyRequests, "注册过于频繁，请稍后再试")
		return
	}
	var body struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON：%v", err)
		return
	}
	name := strings.ToLower(strings.TrimSpace(body.User))
	if !validUserName(name) {
		fail(w, http.StatusBadRequest, "账号名需 3–64 个字符，不能含空格")
		return
	}
	hash, err := HashPassword(body.Password)
	if err != nil {
		fail(w, http.StatusBadRequest, "%v", err)
		return
	}
	id := randomID(16)
	if err := s.store.CreateUser(r.Context(), id, name, hash, time.Now().UTC()); err != nil {
		if errors.Is(err, ErrExists) {
			fail(w, http.StatusConflict, "该账号已存在")
			return
		}
		fail(w, http.StatusInternalServerError, "建号失败：%v", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"userId": id, "user": name})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	key := clientIP(r)
	if !s.limiter.allow("login:"+key, time.Now()) || !s.limiter.allow("login-all:"+key, time.Now()) {
		fail(w, http.StatusTooManyRequests, "尝试次数过多，请 1 分钟后再试")
		return
	}
	var body struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	name := strings.ToLower(strings.TrimSpace(body.User))
	// Always run a hash even for an unknown account, so response time does not reveal whether
	// the account exists.
	id, hash, err := s.store.UserByName(r.Context(), name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		fail(w, http.StatusInternalServerError, "查询失败：%v", err)
		return
	}
	if err != nil {
		hash = "argon2id$v=19$m=65536,t=2,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	if !VerifyPassword(body.Password, hash) || errors.Is(err, ErrNotFound) {
		fail(w, http.StatusUnauthorized, "%v", ErrBadCredential)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"token": s.sessions.issue(id, 12*time.Hour), "userId": id, "user": name})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, userID string) {
	s.sessions.drop(bearer(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	_ = userID
}

// handlePair mints a one-minute code from an already-authenticated web session.
func (s *Server) handlePair(w http.ResponseWriter, r *http.Request, userID string) {
	code, hash := NewPairCode()
	if err := s.store.PutPairCode(r.Context(), hash, userID, time.Now().UTC().Add(s.pairTTL)); err != nil {
		fail(w, http.StatusInternalServerError, "配对码生成失败：%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"code": code, "expiresIn": int(s.pairTTL.Seconds()),
		"note": "在五分钟内于新设备的偏好设置里输入；配对成功那一刻就失效，过期同样"})
}

func (s *Server) handlePairExchange(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow("pair:"+clientIP(r), time.Now()) {
		fail(w, http.StatusTooManyRequests, "配对尝试过于频繁")
		return
	}
	var body struct {
		Code       string `json:"code"`
		DeviceName string `json:"deviceName"`
	}
	if err := decodeJSON(r, &body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	userID, err := s.store.TakePairCode(r.Context(), sha256Hex(NormalizePairCode(body.Code)),
		time.Now().UTC())
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, ErrCodeExpired) {
			status = http.StatusGone
		}
		fail(w, status, "%v", err)
		return
	}
	token := randomID(32)
	deviceID := randomID(6)
	name := strings.TrimSpace(body.DeviceName)
	if name == "" || len(name) > 120 {
		name = "未命名设备"
	}
	if err := s.store.AddDevice(r.Context(), deviceID, userID, name, sha256Hex(token),
		time.Now().UTC()); err != nil {
		fail(w, http.StatusInternalServerError, "登记设备失败：%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deviceToken": token, "deviceId": deviceID})
}

// handleBlobPut stores an opaque envelope. The body is screened structurally (never decrypted)
// so a garbage or oversized write cannot turn into storage or CPU work. 三代形状各按各的闸：
// v2（SPEC §3，上传体本身就是清单＋行内密文）、v1（信封旁边挂明文数组，只读不写）、
// 通道外层（§5，解开后按 §3/§5 的老清单**同一份代码**入库；没配口令时整包照旧不透明）。
func (s *Server) handleBlobPut(w http.ResponseWriter, r *http.Request, userID, deviceID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxEnvelopeBytes+1))
	if err != nil {
		fail(w, http.StatusBadRequest, "读取请求体失败")
		return
	}
	if len(body) > maxEnvelopeBytes {
		fail(w, http.StatusRequestEntityTooLarge, "信封超过 8 MiB 上限")
		return
	}
	var facts *uploadFacts
	state, channelRows := channelAbsent, 0
	switch {
	case IsChannelEnvelope(body):
		state = channelNoKey
		if key, _ := s.channelKeyFor(r.Context(), userID); len(key) > 0 {
			plain, err := OpenChannel(key, body)
			if err != nil {
				// One fixed reason, no payload content: never fall back to silent storage.
				// 外层挂明文字节（旧形状的 hosts/snippets 数组）也归"格式非法"这一句 ——
				// 绝不静默退回从外面那层读清单的那条老路。
				fail(w, http.StatusBadRequest, "通道密钥不匹配或未配置")
				return
			}
			// 解开之后走和不加密传输一模一样的那条 ingest（SPEC §5）。
			ingested, err := ingestChannelPlain(plain)
			if err != nil {
				if errors.Is(err, errSecretInChannel) {
					fail(w, http.StatusBadRequest, "加密传输清单里不得携带 secretMaterial：口令只能锁在 secretVault")
					return
				}
				if failUploadIngestError(w, err) {
					return
				}
				fail(w, http.StatusBadRequest, "通道内容不是合法清单")
				return
			}
			facts = ingested
			state, channelRows = channelOpened, len(facts.hosts)
		}
		// No key configured: store the channel envelope as an opaque blob, exactly like before.
		// 外面那一层就算挂着明文数组也一个都不读 —— 那是这一档修掉的洞。
	case IsUploadV2(body):
		ingested, err := IngestUploadV2(body)
		if err != nil {
			if failUploadIngestError(w, err) {
				return
			}
			fail(w, http.StatusUnsupportedMediaType, "不是合法的 Yank 上传体：%v", err)
			return
		}
		facts = ingested
	default:
		// 明文清单元数据（SPEC §5.1 的 v1 形状）：客户端有意上传、服务端永远读得到的一小块，
		// 和信封并肩放着。
		inventory, invErr := InventoryFromEnvelope(body)
		if invErr != nil {
			if errors.Is(invErr, errSecretInInventory) {
				fail(w, http.StatusBadRequest, "主机清单里不得携带凭据字段：口令只能锁在端到端信封里")
				return
			}
			fail(w, http.StatusBadRequest, "主机清单形状不合法（只允许名称/分组/主机/端口/用户/认证方式/备注/堡垒机）")
			return
		}
		// 片段那一格走同一条闸（SPEC §5.1）：解析失败也是**整次写入拒绝**，绝不"只丢掉那一条"。
		// 正文内容不在这里判断——端侧已经嗅探过并换成隐去说明，服务端只校键名。
		snippets, snipErr := SnippetsFromEnvelope(body)
		if snipErr != nil {
			if errors.Is(snipErr, errSecretInInventory) {
				fail(w, http.StatusBadRequest, "片段清单里不得携带凭据字段：口令只能锁在端到端信封里")
				return
			}
			fail(w, http.StatusBadRequest, "片段清单形状不合法（只允许名称/分组/正文/参数/更新时间）")
			return
		}
		if _, err := ParseEnvelope(body); err != nil {
			fail(w, http.StatusUnsupportedMediaType, "不是合法的 Yank 信封：%v", err)
			return
		}
		// 注意空数组也算：客户端把最后一台删掉了，服务端这一版就该是空清单。
		facts = &uploadFacts{hosts: inventory, snippets: snippets}
	}
	expect, err := revisionHeader(r)
	if err != nil {
		fail(w, http.StatusBadRequest, "%v", err)
		return
	}
	revision, err := s.store.PutBlob(r.Context(), userID, deviceID, body, expect)
	if errors.Is(err, ErrStaleWrite) {
		// The client must merge against `current` rather than overwrite it.
		w.Header().Set("X-CURRENT-REVISION", strconv.FormatInt(revision, 10))
		// 版本号同时写进正文，不是冗余：挂在 CDN/反代后面时自定义响应头可能被换掉，而 JSON
		// 里的字段跟着体走。SPEC §6 一直写的是 `409 {current}`，此前只有头、没有体。
		writeJSON(w, http.StatusConflict, map[string]any{
			"reason":  "服务端已是第 " + strconv.FormatInt(revision, 10) + " 版，请先拉取合并",
			"current": revision})
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "写入失败：%v", err)
		return
	}
	if facts != nil && facts.hosts != nil {
		// The blob is already committed; the inventory is the derived view of THIS revision.
		if err := s.store.ReplaceHosts(r.Context(), userID, revision, facts.hosts); err != nil {
			fail(w, http.StatusInternalServerError, "主机清单入库失败")
			return
		}
	}
	if facts != nil && facts.snippets != nil {
		// 片段同理：必须在 blob 提交成功之后才动这张表，否则被 409 拒掉的那一次推送会把
		// 索引改成一个并不存在的修订号。
		if err := s.store.ReplaceSnippets(r.Context(), userID, revision, facts.snippets); err != nil {
			fail(w, http.StatusInternalServerError, "片段清单入库失败")
			return
		}
	}
	// History pruning is hygiene; failing the user's sync over it would be absurd.
	_, _ = s.store.PruneHistory(r.Context(), userID, 200)
	// 这一句既进日志也回给客户端：开没开通道密钥，后端看到的东西不一样，而能核对的只有服务端
	// 自己。客户端转述的是这句原话。
	seen := seenOf(body, facts, state, channelRows).String()
	log.Printf("上传 %s/%s 第 %d 版：%s", userID, deviceID, revision, seen)
	writeJSON(w, http.StatusOK, map[string]any{"revision": revision, "seen": seen})
}

// failUploadIngestError 把行/meta 级的形状与凭据问题映射成原来那几句 400 中文理由（按出自
// 哪一格分开说）。不是这一类错误（如顶层 §2 参数筛不过）时回 false，交给调用方报 415。
// 无论哪一句，整次写入都已拒绝 —— 什么都没存。
func failUploadIngestError(w http.ResponseWriter, err error) bool {
	var ie *ingestError
	if !errors.As(err, &ie) {
		return false
	}
	credentialed := errors.Is(ie.err, errSecretInInventory)
	switch ie.array {
	case "snippets":
		if credentialed {
			fail(w, http.StatusBadRequest, "片段清单里不得携带凭据字段：口令只能锁在端到端信封里")
		} else {
			fail(w, http.StatusBadRequest, "片段清单形状不合法（只允许名称/分组/正文/参数/更新时间，另加每行一格不透明 secret）")
		}
	case "meta":
		fail(w, http.StatusBadRequest, "上传体形状不合法：meta 只能是一格不透明串")
	default: // hosts
		if credentialed {
			fail(w, http.StatusBadRequest, "主机清单里不得携带凭据字段：口令只能锁在端到端信封里")
		} else {
			fail(w, http.StatusBadRequest, "主机清单形状不合法（只允许名称/分组/主机/端口/用户/认证方式/备注/堡垒机，另加每行一格不透明 secret）")
		}
	}
	return true
}

func (s *Server) handleBlobGet(w http.ResponseWriter, r *http.Request, userID string) {
	row, err := s.store.LatestBlob(r.Context(), userID)
	if errors.Is(err, ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取失败：%v", err)
		return
	}
	w.Header().Set("ETag", strconv.FormatInt(row.Revision, 10))
	// 同一个数字再给一份自定义头：`ETag` 是缓存校验器，中间层会按自己的规则改写甚至换掉它
	// （2026-10-10 线上就是这样：客户端拉回来的 ETag 不是版本号，于是永远推不进去）。
	w.Header().Set("X-REVISION", strconv.FormatInt(row.Revision, 10))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(row.Body)
}

// handleHosts exposes the host inventory (SPEC §6). Session token or device token — same access
// shape as GET /api/blob. It no longer requires a channel key: the metadata the console shows is
// the cleartext block the client uploads on purpose, and 口令/私钥内容不在其中。An empty list
// means "this account has pushed nothing yet" — said out loud instead of a 503 that blamed the
// reader for not having enabled a feature.
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request, userID string) {
	items, err := s.store.ListHosts(r.Context(), userID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取主机清单失败：%v", err)
		return
	}
	if items == nil {
		items = []HostRow{}
	}
	w.Header().Set("X-Inventory-Source", inventorySource(items))
	writeJSON(w, http.StatusOK, items)
}

// inventorySource 只回答"库里有没有清单"这一件事。至于那一份是明文数组传来的还是通道层解出来的，
// 表里没有记这一笔，接口就不假装知道——两条路写出来的行长得一模一样。
func inventorySource(items []HostRow) string {
	if len(items) == 0 {
		return "empty"
	}
	return "stored"
}

// handleSnippets 暴露片段清单（SPEC §6），鉴权与 handleHosts 同权：会话令牌或设备令牌都行，
// 因为要看的永远是"自己这个账号"的东西。同样不需要先启用通道密钥——那一份数组本来就是明文。
// 空清单还是 200 空数组：一次"这个账号还没推过片段"的陈述，不该拿 503 去怪读的人没开功能。
func (s *Server) handleSnippets(w http.ResponseWriter, r *http.Request, userID string) {
	items, err := s.store.ListSnippets(r.Context(), userID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取片段清单失败：%v", err)
		return
	}
	if items == nil {
		items = []SnippetRow{}
	}
	writeJSON(w, http.StatusOK, items)
}
