package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
)

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request, userID string) {
	items, err := s.store.ListHistory(r.Context(), userID, 50)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取历史失败：%v", err)
		return
	}
	if items == nil {
		items = []HistoryRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleBlobAt hands back a stored envelope verbatim. Decryption happens on the client (app or
// browser) with the passphrase, which is the whole point: this endpoint can be logged, mirrored
// and subpoenaed and still reveals nothing.
func (s *Server) handleBlobAt(w http.ResponseWriter, r *http.Request, userID string) {
	revision, err := strconv.ParseInt(r.PathValue("revision"), 10, 64)
	if err != nil || revision < 1 {
		fail(w, http.StatusBadRequest, "版本号要是正整数")
		return
	}
	row, err := s.store.BlobAt(r.Context(), userID, revision)
	if errors.Is(err, ErrNotFound) {
		fail(w, http.StatusNotFound, "没有第 %d 版", revision)
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取失败：%v", err)
		return
	}
	w.Header().Set("ETag", strconv.FormatInt(row.Revision, 10))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(row.Body)
}

// handleRollback copies an earlier envelope forward as a new revision so a browser session can
// undo a bad merge. The server only moves ciphertext — it cannot read what it restores, and the
// client still needs its own passphrase to open the result.
func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Revision int64 `json:"revision"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.Revision < 1 {
		fail(w, http.StatusBadRequest, "要带上一个正整数 revision")
		return
	}
	row, err := s.store.BlobAt(r.Context(), userID, req.Revision)
	if errors.Is(err, ErrNotFound) {
		fail(w, http.StatusNotFound, "没有第 %d 版", req.Revision)
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取失败：%v", err)
		return
	}
	current, err := s.store.currentRevision(r.Context(), userID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取版本号失败：%v", err)
		return
	}
	if row.Revision == current {
		writeJSON(w, http.StatusOK, map[string]int64{"revision": current})
		return
	}
	next, err := s.store.PutBlob(r.Context(), userID, row.DeviceID, row.Body, current)
	if errors.Is(err, ErrStaleWrite) {
		fail(w, http.StatusConflict, "服务端已是第 %d 版，请刷新后重试", next)
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "回退失败：%v", err)
		return
	}
	// The index has to follow the blob forward too, otherwise /api/hosts keeps advertising the
	// version the user just undid.
	s.rebuildInventory(r.Context(), userID, row.Body, next)
	writeJSON(w, http.StatusOK, map[string]int64{"revision": next})
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, userID string) {
	items, err := s.store.ListDevices(r.Context(), userID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取设备失败：%v", err)
		return
	}
	if items == nil {
		items = []Device{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleRevoke stops a lost laptop from syncing. The blob stays: it belongs to the account, not
// to one device.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, userID string) {
	var body struct {
		DeviceID string `json:"deviceId"`
	}
	if err := decodeJSON(r, &body); err != nil || body.DeviceID == "" {
		fail(w, http.StatusBadRequest, "缺少 deviceId")
		return
	}
	if err := s.store.RevokeDevice(r.Context(), userID, body.DeviceID); err != nil {
		if errors.Is(err, ErrNotFound) {
			fail(w, http.StatusNotFound, "没有这台设备（或已吊销）")
			return
		}
		fail(w, http.StatusInternalServerError, "吊销失败：%v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
