package main

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
)

// Pair codes are the whole device-enrolment story: an already-trusted session mints a code that
// lives five minutes, and the new device exchanges it once for a device token — TakePairCode
// deletes the row as it reads it, so a second exchange with the same code fails even if both
// requests arrive at the same instant. Codes are stored hashed, so the database alone cannot be
// replayed or brute-forced.
func (s *Store) PutPairCode(ctx context.Context, codeHash, userID string, expiresAt time.Time) error {
	return s.g.WithContext(ctx).Create(&pairCodeRow{
		CodeHash: codeHash, UserID: userID, ExpiresAt: ts(expiresAt),
	}).Error
}

// TakePairCode deletes the row as it reads it: a second exchange with the same code must fail
// even if both requests arrive at the same instant.
func (s *Store) TakePairCode(ctx context.Context, codeHash string, now time.Time) (userID string, err error) {
	var one pairCodeRow
	err = s.g.WithContext(ctx).Where("code_hash = ?", codeHash).First(&one).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", ErrCodeUnknown
	}
	if err != nil {
		return "", err
	}
	userID = one.UserID
	// 先删再判过期：过期这一条也要把行收走，否则同一串码在被扫出来的时间窗里还能一直撞。
	if delErr := s.g.WithContext(ctx).Where("code_hash = ?", codeHash).
		Delete(&pairCodeRow{}).Error; delErr != nil {
		return "", delErr
	}
	expires, err := parseTS(one.ExpiresAt)
	if err != nil {
		return "", err
	}
	if expires.Before(now) {
		return "", ErrCodeExpired
	}
	return userID, nil
}

// PutBlob appends a revision under optimistic concurrency. expect is the revision the client last
// saw (0 when it believes there is none). A mismatch returns the server's current revision along
// with ErrStaleWrite so the client can pull-merge-push instead of silently clobbering a peer.
// body 存的是客户端发来的**原始字节本身**：v1 信封、v2 上传体（每行 secret 与 meta 那几格
// 不透明串跟着字节走）、通道外层，三种形状都不重排、不转码 —— 设备拉回去才能逐格解密。
func (s *Store) PutBlob(ctx context.Context, userID, deviceID string, body []byte, expect int64) (int64, error) {
	current, err := s.currentRevision(ctx, userID)
	if err != nil {
		return 0, err
	}
	if current != expect {
		return current, ErrStaleWrite
	}
	next := current + 1
	now := ts(time.Now().UTC())
	if current == 0 {
		if err := s.g.WithContext(ctx).Create(&blobRow{
			UserID: userID, Revision: next, DeviceID: deviceID, Body: body, CreatedAt: now,
		}).Error; err != nil {
			return 0, err
		}
	} else {
		// The `AND revision = ?` guard closes the window between the read above and this update:
		// zero rows affected means somebody else won the race.
		// 这里必须用 map 而不是结构体：结构体那一路 GORM 会跳过零值字段，而 revision/正文
		// 恰好是"换了"的那几格，跳一次就是"推送说成功、下一次还是旧版"。
		res := s.g.WithContext(ctx).Model(&blobRow{}).
			Where("user_id = ? AND revision = ?", userID, current).
			Updates(map[string]any{"revision": next, "device_id": deviceID, "body": body,
				"created_at": now})
		if res.Error != nil {
			return 0, res.Error
		}
		if res.RowsAffected == 0 {
			return current, ErrStaleWrite
		}
	}
	if err := s.g.WithContext(ctx).Create(&historyRow{
		UserID: userID, Revision: next, DeviceID: deviceID, Body: body, CreatedAt: now,
	}).Error; err != nil {
		return next, err
	}
	return next, nil
}

func (s *Store) currentRevision(ctx context.Context, userID string) (int64, error) {
	var one blobRow
	err := s.g.WithContext(ctx).Select("revision").Where("user_id = ?", userID).First(&one).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	return one.Revision, err
}

type BlobRow struct {
	Revision  int64
	DeviceID  string
	Body      []byte
	CreatedAt time.Time
}

func (s *Store) LatestBlob(ctx context.Context, userID string) (*BlobRow, error) {
	var one blobRow
	err := s.g.WithContext(ctx).Where("user_id = ?", userID).First(&one).Error
	return blobFrom(one.Revision, one.DeviceID, one.Body, one.CreatedAt, err)
}

func (s *Store) BlobAt(ctx context.Context, userID string, revision int64) (*BlobRow, error) {
	var one historyRow
	err := s.g.WithContext(ctx).Where("user_id = ? AND revision = ?", userID, revision).First(&one).Error
	return blobFrom(one.Revision, one.DeviceID, one.Body, one.CreatedAt, err)
}

// blobFrom 把"查不到"这一件事在三方言、几个驱动之间统一成 ErrNotFound：调用方判的就是这一条，
// 不该再去猜那一次写回来的是 "record not found" 还是别的什么大小写。
func blobFrom(revision int64, deviceID string, body []byte, created string, err error) (*BlobRow, error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	at, err := parseTS(created)
	if err != nil {
		return nil, err
	}
	return &BlobRow{Revision: revision, DeviceID: deviceID, Body: body, CreatedAt: at}, nil
}

type HistoryRow struct {
	Revision  int64     `json:"revision"`
	DeviceID  string    `json:"deviceId"`
	CreatedAt time.Time `json:"createdAt"`
	Bytes     int       `json:"bytes"`
}

// ListHistory returns metadata only — the browser cannot get a host list out of this, only the
// sizes and timestamps it needs to offer a rollback.
func (s *Store) ListHistory(ctx context.Context, userID string, limit int) ([]HistoryRow, error) {
	var rows []historyRow
	err := s.g.WithContext(ctx).Select("revision", "device_id", "created_at", "body").
		Where("user_id = ?", userID).Order("revision DESC").Limit(limit).Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]HistoryRow, 0, len(rows))
	for _, r := range rows {
		at, err := parseTS(r.CreatedAt)
		if err != nil {
			return nil, err
		}
		out = append(out, HistoryRow{Revision: r.Revision, DeviceID: r.DeviceID,
			CreatedAt: at, Bytes: len(r.Body)})
	}
	return out, nil
}

// PruneHistory keeps the newest `keep` revisions per account so an unbounded sync cadence cannot
// fill the disk. Returns how many rows went away.
func (s *Store) PruneHistory(ctx context.Context, userID string, keep int) (int64, error) {
	// 先读出"要留的那几版"，再删其余的。从前这里是一条 DELETE ... NOT IN (SELECT ... LIMIT ?)
	// 的套娃，为的是绕开 MySQL 不许子查询带 LIMIT 那一条；两边写法各不一样，而这一张表每个账号
	// 只留得下十几行，多一次查询换三方言各不猜，是划算的。
	var recent []int64
	q := s.g.WithContext(ctx).Model(&historyRow{}).Where("user_id = ?", userID).Order("revision DESC")
	if keep > 0 {
		q = q.Limit(keep)
	}
	if err := q.Pluck("revision", &recent).Error; err != nil {
		return 0, err
	}
	del := s.g.WithContext(ctx).Where("user_id = ?", userID)
	if len(recent) > 0 {
		del = del.Where("revision NOT IN ?", recent)
	}
	res := del.Delete(&historyRow{})
	return res.RowsAffected, res.Error
}
