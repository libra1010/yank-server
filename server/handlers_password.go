package main

// 改管理端登录口令（POST /api/password）。
//
// 这条接口存在的理由很直白：账号只能注册、不能改密，用户要么一直用初始那串、要么再注册一个
// 新账号名 —— 两个都不是应有的样子。
//
// 边界要说清楚，因为这一页同时管着两种"口令"：
//   - 改的是**浏览器登录这个管理端用的口令**，它和保护 SSH 凭据的端到端口令毫无关系；
//   - 端到端口令永远不进这个页面、不进这个接口、不进服务端数据库（SPEC §7）。
//
// 改完之后，这个账号在别处的浏览器会话全部作废（只留下当前这一张），旧口令铸出的令牌
// 不能继续用。设备令牌不受影响：那是 Mac 客户端同步用的，改网页密码不该把人家的终端踢下线。

import (
	"errors"
	"net/http"
	"time"
)

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, userID string) {
	key := clientIP(r)
	// 改密要先证明知道旧口令，所以它和登录一样是猜口令的入口，按同一个速率口径挡。
	if !s.limiter.allow("password:"+key, time.Now()) {
		fail(w, http.StatusTooManyRequests, "尝试次数过多，请 1 分钟后再试")
		return
	}
	var body struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := decodeJSON(r, &body); err != nil {
		fail(w, http.StatusBadRequest, "请求体不是合法 JSON")
		return
	}
	if body.NewPassword == "" || body.OldPassword == "" {
		fail(w, http.StatusBadRequest, "原口令和新口令都要填")
		return
	}
	stored, err := s.store.PasswordHash(r.Context(), userID)
	if errors.Is(err, ErrNotFound) {
		fail(w, http.StatusUnauthorized, "账号不存在或已被删除")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "读取账号失败")
		return
	}
	if !VerifyPassword(body.OldPassword, stored) {
		// 一句固定说法：不区分"账号不存在"和"口令错"，也不回显任何输入。
		fail(w, http.StatusForbidden, "原口令不正确")
		return
	}
	if body.NewPassword == body.OldPassword {
		fail(w, http.StatusBadRequest, "新口令不能和原口令一样")
		return
	}
	hash, err := HashPassword(body.NewPassword)
	if errors.Is(err, ErrWeakPassword) {
		fail(w, http.StatusBadRequest, "管理端登录口令至少需要 10 个字符")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "生成口令校验值失败")
		return
	}
	// 说明：Go 的字符串不可控清零（不像 C 的缓冲区），这里不假装"抹掉了"。
	// 真实边界是：口令只存在于这一个请求的生命周期内，不进日志、不进响应、不进数据库明文。
	if err := s.store.SetPasswordHash(r.Context(), userID, hash); err != nil {
		fail(w, http.StatusInternalServerError, "写入口令失败：%v", err)
		return
	}
	s.sessions.dropUserExcept(bearer(r))
	writeJSON(w, http.StatusOK, map[string]string{
		"reason": "登录口令已修改，其他浏览器上的会话都已退出",
	})
}
