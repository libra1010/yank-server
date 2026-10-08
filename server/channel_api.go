package main

// 通道密钥只由这个页面配置。它原来还有一路来源——进程启动参数 —— 于是"关掉/打开加密传输"
// 要么改部署要么重启服务，而且那把 64 个字符的 hex 根本没人愿意手抄。现在只有一个入口：
// 管理页面上填一句自己定的口令。
//
// 存进去的就是那句口令本身（谁拿到库文件谁就解得开外层信封 —— 这句话在页面上写着，不藏着），
// 所以这个接口是单向的：只接受口令，只回报一个 6 位十六进制的指纹，永不回显口令。
// 指纹两端同算法（见 channel_passphrase.go 的 ChannelFingerprint），对得上才算两端配的是同一句。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// channelKeySetting is the settings.skey prefix; one row per account, so two users of one server
// can run two different channels.
const channelKeySetting = "channel:"

// channelKeyFor resolves the transport secret for one account, verbatim from the page. Nothing is
// cached, on purpose — a passphrase saved from the console has to take effect on the very next push.
func (s *Server) channelKeyFor(ctx context.Context, userID string) (secret []byte, source string) {
	if userID == "" {
		return nil, "none"
	}
	stored, err := s.store.GetSetting(ctx, channelKeySetting+userID)
	if err != nil {
		return nil, "none"
	}
	text := strings.TrimSpace(stored)
	if text == "" {
		return nil, "none"
	}
	return []byte(text), "page"
}

// channelShape is the only outward representation of the key state: enabled, where it came from,
// and the fingerprint. The secret itself never leaves.
func channelShape(source, text string) map[string]any {
	fingerprint := ""
	if text != "" {
		fingerprint = ChannelFingerprint(text)
	}
	return map[string]any{
		"enabled":     text != "",
		"source":      source,
		"fingerprint": fingerprint,
	}
}

func (s *Server) channelShapeFor(ctx context.Context, userID string) map[string]any {
	secret, source := s.channelKeyFor(ctx, userID)
	return channelShape(source, string(secret))
}

func (s *Server) handleChannelGet(w http.ResponseWriter, r *http.Request, userID string) {
	writeJSON(w, http.StatusOK, s.channelShapeFor(r.Context(), userID))
}

// handleChannelSet saves a passphrase, or removes it when the field is empty. The response is the
// resulting state, so the console can refresh its fingerprint line without a second request.
func (s *Server) handleChannelSet(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	value := strings.TrimSpace(req.Key)
	if value == "" {
		if err := s.store.DeleteSetting(r.Context(), channelKeySetting+userID); err != nil {
			fail(w, http.StatusInternalServerError, "清除失败：%v", err)
			return
		}
	} else {
		if err := CheckChannelPassphrase(value); err != nil {
			fail(w, http.StatusBadRequest, "%v", err)
			return
		}
		if err := s.store.SetSetting(r.Context(), channelKeySetting+userID, value); err != nil {
			fail(w, http.StatusInternalServerError, "保存失败：%v", err)
			return
		}
	}
	s.reindexChannel(r.Context(), userID)
	writeJSON(w, http.StatusOK, s.channelShapeFor(r.Context(), userID))
}

// reindexChannel reopens the newest envelope with the key that now applies and refreshes the host
// inventory, so setting the key on the page makes the already-stored hosts appear immediately
// instead of after the next sync. A key that cannot open the blob leaves the old index untouched:
// a typo in the field must not cost the user their inventory.
func (s *Server) reindexChannel(ctx context.Context, userID string) {
	row, err := s.store.LatestBlob(ctx, userID)
	if err != nil || row == nil {
		return
	}
	// 明文清单不需要任何密钥就能重建索引，通道层那一份才要密钥。所以密钥打错的时候
	// 旧索引一行不少（界面上填错一格不该让人丢掉整份清单），而没配密钥的账号只要客户端
	// 传过明文清单也照样有清单可看。
	s.rebuildInventory(ctx, userID, row.Body, row.Revision)
}
