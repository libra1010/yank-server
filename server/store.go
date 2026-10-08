package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/glebarez/sqlite" // 纯 Go 的 sqlite（modernc 内核）：CGO_ENABLED=0 那条单文件发布路靠它
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Store 是唯一和数据库说话的那一层。服务端不解密任何东西，所以这里每一格 body 都是不透明字节。
//
// 2026-10-06 起每一条读写走 GORM，但**建表口径不归它**：表结构仍以 schemaStatements 那份手写
// DDL 为准 —— 同一个来源既跑在 Migrate() 里，也打印成 migrations/{mysql,postgres}.sql 那两份
// 全量交付件给 DBA 审（sqlite 不交付，按版本递增的增量脚本已废）。两个理由都不是口味：
//
//	· GORM 的 Migrator 取不出建表语句的文本（CreateTable 返回 error 而不是 *gorm.DB，ToSQL
//	  那扇门对它不开；DryRun 会话下驱动的 HasTable 还会直接 nil 崩）。"审的就是我跑的"守不住。
//	· AutoMigrate 会照它从结构体推出来的类型判断去 ALTER 它认为不合的列。手写 DDL 里信封正文是
//	  MEDIUMBLOB（8 MiB），而 []byte 在 GORM 眼里是另一种形状 —— 一次启动悄悄把列收窄，是那种
//	  "部署看着好的、第一次大推送才炸"的坏法。
//
// 所以分工：表、列、索引、类型继续由那一份 DDL 说了算；GORM 负责读写。于是 `?` 改 `$n` 这类
// 方言翻译、以及驱动名拼错这一整类错（pgx 注册的驱动名是 "pgx"，从前这里递的是 "postgres"，
// PostgreSQL 那条路从头就没通过）再没有下手的地方。结构体与那两份全量 DDL 的列集合由
// TestModelsMatchBaselineDDL 逐表比对，漂了就红。
type Store struct {
	g    *gorm.DB
	kind string // sqlite | mysql | postgres

	// db 是 GORM 底下那把原生句柄。留着它不是为了绕开 GORM 写查询，而是有两件事 GORM 表达不了：
	// 一是"这一列在不在"的探测（老库升级），二是自检里那些 PRAGMA / information_schema 的读数。
	// 两条安装路径（服务自己建表 / DBA 先建好表）必须能互相验，靠的就是这个口子。
	db *sql.DB
}

var (
	ErrNotFound    = errors.New("记录不存在")
	ErrExists      = errors.New("记录已存在")
	ErrStaleWrite  = errors.New("客户端持有的是旧版本")
	ErrCodeUnknown = errors.New("配对码无效或已使用")
	ErrCodeExpired = errors.New("配对码已过期")
)

// Open 收 sqlite://路径 | mysql://<驱动那一串> | postgres://…。前缀只用来挑方言：摘掉前缀
// 剩下的部分原样交给各自的驱动（mysql 要的是 user:pw@tcp(host:3306)/db 那种写法，不是 URL；
// postgres 两种都认，见下面那段）。SQLite 是默认，因为"一台机器一个文件"是常态，
// 另外两档是给 k3s/HA 那个形状的。
func Open(dsn string) (*Store, error) {
	kind, rest, ok := strings.Cut(dsn, "://")
	if !ok {
		return nil, fmt.Errorf("DSN 必须带方言前缀：sqlite:// … | mysql:// … | postgres:// …")
	}
	var dialector gorm.Dialector
	switch kind {
	case "sqlite":
		if !strings.Contains(rest, "?") {
			// WAL + busy_timeout：第二个读者不至于撞上 "database is locked"。
			// modernc 内核认这串 _pragma 参数，所以仍然不需要 cgo。
			rest += "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
		}
		dialector = sqlite.Open(rest)
	case "mysql":
		dialector = mysql.New(mysql.Config{DSN: rest})
	case "postgres", "postgresql":
		kind = "postgres"
		// 这一档整串（连 scheme）原样递给 pgx，只有挑方言时才看那个前缀。
		// 从前这里是"摘掉前缀，剩下那半截没有 = 就补回 scheme"，想同时支持 pgx 的
		// keyword 串（host=… port=…）。那条启发式在带查询参数的 URL 上判错了：
		// ?sslmode=disable 里那个 = 让整串被当成 keyword 串，pgx 于是看不见 host，
		// 退回本机 unix socket、拿 OS 用户名去连，报的是 "failed to connect to
		// user=<OS 用户名> database=" —— 看着像服务坏了，其实是 DSN 被读歪。
		// 所以 PG 这一侧只认 URL 形：postgres://user:pw@host:5432/db?sslmode=disable。
		// mysql 反过来：go-sql-driver 要的是没有 scheme 的那串（user:pw@tcp(h:3306)/db），
		// 所以它摘前缀。两边形状不同是驱动定的，不是这里选的。
		dialector = postgres.Open(dsn)
	default:
		return nil, fmt.Errorf("不支持的数据库方言 %q", kind)
	}
	g, err := gorm.Open(dialector, &gorm.Config{
		// 每一条 SQL 都往日志里写的话，容器日志就装着信封正文和主机清单了 —— 这两样的可见面
		// 比这个服务大得多。要排 SQL 时把这一行临时改成 Info，而不是留着上线。
		Logger: logger.Default.LogMode(logger.Silent),
		// 打开它，"查不到这一行"才会是 gorm.ErrRecordNotFound 这个能判的错，而不是各驱动各写
		// 一边的大小写不同的字符串。下面那些 sentinel 全靠它翻译。
		TranslateError: true,
	})
	if err != nil {
		return nil, fmt.Errorf("连不上 %s：%w", kind, err)
	}
	raw, err := g.DB()
	if err != nil {
		return nil, err
	}
	if err := raw.Ping(); err != nil {
		return nil, fmt.Errorf("连不上 %s：%w", kind, err)
	}
	return &Store{g: g, kind: kind, db: raw}, nil
}

func (s *Store) Close() error {
	raw, err := s.g.DB()
	if err != nil {
		return err
	}
	return raw.Close()
}

// exec 走原生句柄：建表与补列那几句是 DDL，链式表达不了，也不该表达（见上面的分工）。
// 门禁也用它造"老形状"的表，好证明升级那一步真的补得上列。
func (s *Store) exec(query string, args ...any) (sql.Result, error) {
	return s.db.Exec(query, args...)
}

// hasColumn 用一次"只问这一列、不取任何行"的查询来判断列在不在。三种方言查列名的写法各不
// 相同（pragma / information_schema / 两套大小写规则），但对"列不存在"它们都报错、对
// "列存在"都成功，这条探法因此只有一份实现。
func (s *Store) hasColumn(table, column string) bool {
	// 两个标识符都来自本文件的常量，不是用户输入。
	return s.db.QueryRow("SELECT "+column+" FROM "+table+" LIMIT 0").Err() == nil
}

// hasTable 是一句只读的探表：它不需要任何建表权限，所以线上"DBA 已经把表建好、应用账号
// 只有读写"的那一档靠它判断该不该发 DDL。
func (s *Store) hasTable(table string) bool {
	return s.db.QueryRow("SELECT 1 FROM "+table+" LIMIT 0").Err() == nil
}

// missingTables 把"该有哪些表"从 schemaStatements 里抠出来再逐张探 —— 名单不另写一份，
// 否则建表语句加了张表而名单忘了跟，启动就会在第一次用到它时炸在别处。
func (s *Store) missingTables() []string {
	var missing []string
	for _, q := range schemaStatements(s.kind) {
		const head = "CREATE TABLE IF NOT EXISTS "
		if !strings.HasPrefix(q, head) {
			continue
		}
		fields := strings.Fields(q[len(head):])
		if len(fields) == 0 || s.hasTable(fields[0]) {
			continue
		}
		missing = append(missing, fields[0])
	}
	return missing
}

// ddlFor 是 `syncd -ddl <方言>` 那一半：不连库、只把建表语句原样打印出来。所以 migrations/ 里
// 那几份给 DBA 复核的 DDL 文件不是手抄副本，而是同一份 schemaStatements 的输出 —— 改表只需要
// 改那一处，再重新生成，文件不可能悄悄和代码长得不一样。
func ddlFor(kind string) ([]string, error) {
	switch kind {
	case "sqlite", "mysql", "postgres":
		return schemaStatements(kind), nil
	}
	return nil, fmt.Errorf("不认识的方言 %q：可选 sqlite | mysql | postgres", kind)
}

// schemaStatements 是建表语句的唯一来源：Migrate() 照它建库，`syncd -ddl <方言>` 也照它打印
// 交给 DBA 复核的那份文件。两边共用一份，README 和 migrations/ 里的 DDL 就不可能是过期的。
func schemaStatements(kind string) []string {
	blobType := map[string]string{"sqlite": "BLOB", "mysql": "MEDIUMBLOB", "postgres": "BYTEA"}[kind]
	// Timestamps are RFC3339 text in every dialect. One representation across sqlite (which
	// hands back a string), mysql and postgres (which hand back a time.Time) beats six casts,
	// and lexicographic order of UTC RFC3339 still sorts.
	tsType := "VARCHAR(32)"
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id VARCHAR(32) PRIMARY KEY, name VARCHAR(190) NOT NULL, pw_hash VARCHAR(255) NOT NULL,
			created_at ` + tsType + ` NOT NULL, UNIQUE (name))`,
		`CREATE TABLE IF NOT EXISTS devices (
			id VARCHAR(40) PRIMARY KEY, user_id VARCHAR(32) NOT NULL, name VARCHAR(120) NOT NULL,
			token_hash VARCHAR(64) NOT NULL, created_at ` + tsType + ` NOT NULL, last_seen ` + tsType + `,
			revoked INTEGER NOT NULL DEFAULT 0, UNIQUE (token_hash))`,
		`CREATE TABLE IF NOT EXISTS pair_codes (
			code_hash VARCHAR(64) PRIMARY KEY, user_id VARCHAR(32) NOT NULL,
			expires_at ` + tsType + ` NOT NULL, used_at ` + tsType + `)`,
		`CREATE TABLE IF NOT EXISTS blobs (
			user_id VARCHAR(32) PRIMARY KEY, revision INTEGER NOT NULL, device_id VARCHAR(40) NOT NULL,
			body ` + blobType + ` NOT NULL, created_at ` + tsType + ` NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS blob_history (
			user_id VARCHAR(32) NOT NULL, revision INTEGER NOT NULL, device_id VARCHAR(40) NOT NULL,
			body ` + blobType + ` NOT NULL, created_at ` + tsType + ` NOT NULL, UNIQUE (user_id, revision))`,
		// Per-account settings, so the channel key can be configured from the admin page instead
		// of only by restarting the process with a flag. The value is a secret: the table holds the
		// transport key verbatim, so the database file itself is the thing to protect.
		// The column is skey, not key: KEY is reserved in MySQL and the DDL runs on all three
		// dialects unchanged.
		`CREATE TABLE IF NOT EXISTS settings (
			skey VARCHAR(64) PRIMARY KEY, value TEXT NOT NULL)`,
	}
	// The channel-layer host inventory (SPEC §5). Deliberately no secret columns: this table
	// only ever receives the whitelisted profile fields the server is allowed to read.
	hostsDDL := `CREATE TABLE IF NOT EXISTS hosts (
			user_id VARCHAR(32) NOT NULL, name VARCHAR(512) NOT NULL, host_group VARCHAR(512) NOT NULL,
			hostname VARCHAR(512) NOT NULL, port INTEGER NOT NULL, username VARCHAR(512) NOT NULL,
			auth_kind VARCHAR(24) NOT NULL DEFAULT '', notes VARCHAR(1024) NOT NULL DEFAULT '',
			jump VARCHAR(512) NOT NULL DEFAULT '', revision INTEGER NOT NULL`
	// 片段清单（SPEC §5.1，用户 2026-10-05 拍板）：和 hosts 同一套边界——只收白名单键，
	// 列名一样避开保留字（group → snippet_group）。body 给到 2048 而不是其余字段的 512：
	// 正文是命令，容量不够就只是显示不全，而"该不该展示这一条"是端侧嗅探过的事（见
	// inventory.go 的 snippetBodyMaxRunes）。口令本体、私钥内容照旧只在内层信封里。
	snippetsDDL := `CREATE TABLE IF NOT EXISTS snippets (
			user_id VARCHAR(32) NOT NULL, name VARCHAR(512) NOT NULL, snippet_group VARCHAR(512) NOT NULL,
			body VARCHAR(2048) NOT NULL, params VARCHAR(512) NOT NULL DEFAULT '',
			updated_at VARCHAR(40) NOT NULL DEFAULT '', revision INTEGER NOT NULL`
	if kind == "mysql" {
		// MySQL has no CREATE INDEX ... IF NOT EXISTS, so the index rides inside the table.
		stmts = append(stmts,
			hostsDDL+", KEY hosts_user_rev (user_id, revision))",
			snippetsDDL+", KEY snippets_user_rev (user_id, revision))")
	} else {
		stmts = append(stmts, hostsDDL+")",
			`CREATE INDEX IF NOT EXISTS hosts_user_rev ON hosts (user_id, revision)`,
			snippetsDDL+")",
			`CREATE INDEX IF NOT EXISTS snippets_user_rev ON snippets (user_id, revision)`)
	}
	return stmts
}

// Migrate 建出（或补列）本方言那一套表。启动时必跑一次：建表全是 IF NOT EXISTS，补列靠"这一列
// 在不在"的探测，同一个库跑第二遍什么都不动 —— 所以容器重启、换镜像、反复滚动都不会毁数据。
func (s *Store) Migrate(ctx context.Context) error {
	// 表已经齐就一句 DDL 都不发。以前这里无条件跑 CREATE TABLE IF NOT EXISTS：那个
	// IF NOT EXISTS 是服务端自己判的，而 PostgreSQL 在走到那句之前就要 schema public 的
	// CREATE 权限 —— 线上"DBA 先建表、应用账号只给读写"的那一档因此直接 42501 起不来
	// （README 里"应用账号不必有建表权限"那条承诺就是这么破的）。
	if missing := s.missingTables(); len(missing) > 0 {
		for _, q := range schemaStatements(s.kind) {
			if _, err := s.exec(q); err != nil {
				return fmt.Errorf("建表失败：%w（方言 %s；库里还缺 %v。这一档要么让 DBA 跑 "+
					"migrations/%s.sql，要么给这个账号建表权限）",
					err, s.kind, missing, s.kind)
			}
		}
	}
	// 已经建过表的库拿不到上面那句里的新列 —— CREATE TABLE IF NOT EXISTS 对存在的表什么都不做，
	// 所以清单每加一格都要单独补一次。补列是升级，不是重建：清单本来就会被下一次推送整体重写。
	// 这一张清单与 models.go 里 hostRow 的对应关系由 TestModelsMatchBaselineDDL 守着。
	for _, column := range []struct{ name, ddl string }{
		{"auth_kind", "VARCHAR(24) NOT NULL DEFAULT ''"},
		{"notes", "VARCHAR(1024) NOT NULL DEFAULT ''"},
		{"jump", "VARCHAR(512) NOT NULL DEFAULT ''"},
	} {
		if s.hasColumn("hosts", column.name) {
			continue
		}
		if _, err := s.exec("ALTER TABLE hosts ADD COLUMN " + column.name + " " + column.ddl); err != nil {
			return fmt.Errorf("升级 hosts 表（加 %s 一列）失败：%w（方言 %s；这一列在 "+
				"migrations/%s.sql 里有，DBA 那一档请按那份补，应用账号不必有 ALTER 权限）",
				column.name, err, s.kind, s.kind)
		}
	}
	return nil
}

// ------------------------------------------------------------------------ accounts

// SetPasswordHash rewrites the admin account's verifier. Nothing else about the account moves:
// the id, the name and the paired devices stay, so a password change does not log the Mac out
// of sync — only the browser sessions are dropped (by the caller, via sessionTable).
func (s *Store) SetPasswordHash(ctx context.Context, userID, pwHash string) error {
	res := s.g.WithContext(ctx).Model(&userRow{}).Where("id = ?", userID).Update("pw_hash", pwHash)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// PasswordHash 只给改密接口核验原口令用。这一列是不可逆校验值，读出来也不会泄漏明文。
func (s *Store) PasswordHash(ctx context.Context, userID string) (string, error) {
	var one userRow
	err := s.g.WithContext(ctx).Select("pw_hash").Where("id = ?", userID).First(&one).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", ErrNotFound
	}
	return one.PwHash, err
}

func (s *Store) CreateUser(ctx context.Context, id, name, pwHash string, now time.Time) error {
	err := s.g.WithContext(ctx).
		Create(&userRow{ID: id, Name: name, PwHash: pwHash, CreatedAt: ts(now)}).Error
	if isDuplicate(err) {
		return ErrExists
	}
	return err
}

// UserByName returns id + password hash. Missing rows are ErrNotFound, never a nil deref.
func (s *Store) UserByName(ctx context.Context, name string) (id, pwHash string, err error) {
	var one userRow
	err = s.g.WithContext(ctx).Where("name = ?", name).First(&one).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", "", ErrNotFound
	}
	return one.ID, one.PwHash, err
}

// ------------------------------------------------------------------------ devices

func (s *Store) AddDevice(ctx context.Context, id, userID, name, tokenHash string, now time.Time) error {
	err := s.g.WithContext(ctx).Create(&deviceRow{
		ID: id, UserID: userID, Name: name, TokenHash: tokenHash, CreatedAt: ts(now),
	}).Error
	if isDuplicate(err) {
		return ErrExists
	}
	return err
}

// DeviceByTokenHash resolves a bearer token to a live device. Tokens are stored hashed, so a
// database dump does not hand out working credentials. 停用过的设备一律当"找不到"：调用方要的
// 就是那一条拒绝，不是"找到了但已停用"这种还得再判一次的状态。
func (s *Store) DeviceByTokenHash(ctx context.Context, hash string) (deviceID, userID string, err error) {
	var one deviceRow
	err = s.g.WithContext(ctx).Where("token_hash = ?", hash).First(&one).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	if one.Revoked != 0 {
		return "", "", ErrNotFound
	}
	return one.ID, one.UserID, nil
}

func (s *Store) TouchDevice(ctx context.Context, deviceID string, now time.Time) error {
	return s.g.WithContext(ctx).Model(&deviceRow{}).Where("id = ?", deviceID).
		Update("last_seen", ts(now)).Error
}

type Device struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"createdAt"`
	LastSeen  *time.Time `json:"lastSeen"`
	Revoked   bool       `json:"revoked"`
}

func (s *Store) ListDevices(ctx context.Context, userID string) ([]Device, error) {
	var rows []deviceRow
	if err := s.g.WithContext(ctx).Where("user_id = ?", userID).Order("created_at").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(rows))
	for _, r := range rows {
		d := Device{ID: r.ID, Name: r.Name, Revoked: r.Revoked != 0}
		// 存的是串，读回来才解析：这一格坏掉只可能是"那行数据本来就脏"，不该把整张表带崩，
		// 所以解不动的串按"没有心跳"处理，界面上显示"从没上线"。
		if at, err := parseTS(r.CreatedAt); err == nil {
			d.CreatedAt = at
		}
		if r.LastSeen != nil {
			if at, err := parseTS(*r.LastSeen); err == nil {
				d.LastSeen = &at
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func (s *Store) RevokeDevice(ctx context.Context, userID, deviceID string) error {
	res := s.g.WithContext(ctx).Model(&deviceRow{}).
		Where("user_id = ? AND id = ?", userID, deviceID).Update("revoked", 1)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ------------------------------------------------------------------------ helpers

func isDuplicate(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "unique") || strings.Contains(text, "duplicate")
}

// ts formats a timestamp for storage. Passing time.Time straight to the driver would let each
// dialect pick its own layout — and then ORDER BY created_at is no longer chronological.
func ts(v time.Time) string { return v.UTC().Format(time.RFC3339Nano) }

func parseTS(text string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, text)
}

// -------------------------------------------------------------------- host inventory

// HostRow is one decrypted profile from the channel layer (SPEC §5). Note what is absent: no
// password, no key material, no vault — those live in the inner envelope the server cannot open,
// and this struct only carries the fields the spec says the server is paid to see.
type HostRow struct {
	Name     string `json:"name"`
	Group    string `json:"group"`
	Hostname string `json:"hostname"`
	Port     int64  `json:"port"`
	Username string `json:"username"`
	// AuthKind is which *method* the profile uses (password / keyboard-interactive /
	// private-key / agent), not anything about the credential: the keychain account and the
	// private key path are read out of the manifest and dropped. Empty means the client didn't
	// tell us, and the console says 未知 rather than guessing.
	AuthKind string `json:"authKind"`
	// Notes is the operator's own remark, uploaded in the clear by design (SPEC §5.1). The
	// client redacts a remark that looks like `password: <secret>` before it ever leaves the Mac,
	// so this column can hold 备注 but never a credential.
	Notes string `json:"notes"`
	// Jump is the bastion this host is reached through ("ops@bastion.example:22"), empty for a
	// direct host. It names the hop; it is not the hop's credential.
	Jump     string `json:"jump"`
	Revision int64  `json:"revision"`
}

// ReplaceHosts swaps the whole per-user inventory in one transaction, mirroring how blobs
// wholesale-replace the manifest: a manifest that dropped a host must leave no stale row behind.
func (s *Store) ReplaceHosts(ctx context.Context, userID string, revision int64, rows []HostRow) error {
	return s.g.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&hostRow{}).Error; err != nil {
			return err
		}
		for _, row := range rows {
			if err := tx.Create(&hostRow{
				UserID: userID, Name: row.Name, Group: row.Group, Hostname: row.Hostname,
				Port: row.Port, Username: row.Username, AuthKind: row.AuthKind, Notes: row.Notes,
				Jump: row.Jump, Revision: revision,
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ListHosts returns the stored inventory for one account, newest revision first.
func (s *Store) ListHosts(ctx context.Context, userID string) ([]HostRow, error) {
	var rows []hostRow
	err := s.g.WithContext(ctx).Where("user_id = ?", userID).Order("revision DESC, name ASC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]HostRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, HostRow{Name: r.Name, Group: r.Group, Hostname: r.Hostname,
			Port: r.Port, Username: r.Username, AuthKind: r.AuthKind, Notes: r.Notes,
			Jump: r.Jump, Revision: r.Revision})
	}
	return out, nil
}

// -------------------------------------------------------------------- snippet inventory

// SnippetRow 是明文 `snippets` 数组里的一行（SPEC §5.1）。注意这里没有的东西：片段 id、
// 没被隐去的完整正文、口令、私钥 —— 那些照旧只在内层端到端信封里。Body 存的是**已经过端侧
// 嗅探**的值：命中疑似口令时客户端自己把整条正文换成了一句"已在本机隐去"，过长则换成
// "未在管理端展示"，所以服务端看到的就是普通字符串，也照原样回吐。
// Params 是正文用到的占位符名（逗号分隔），UpdatedAt 是端侧的 ISO8601 时间串。
type SnippetRow struct {
	Name      string `json:"name"`
	Group     string `json:"group"`
	Body      string `json:"body"`
	Params    string `json:"params"`
	UpdatedAt string `json:"updatedAt"`
	Revision  int64  `json:"revision"`
}

// ReplaceSnippets 与 ReplaceHosts 同理：一次推送整体换一个账号的片段表，被删掉的片段必须
// 不留一行。DELETE 与 INSERT 在同一个事务里，界面上不会读到"半份清单"。
func (s *Store) ReplaceSnippets(ctx context.Context, userID string, revision int64, rows []SnippetRow) error {
	return s.g.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&snippetRow{}).Error; err != nil {
			return err
		}
		for _, row := range rows {
			if err := tx.Create(&snippetRow{
				UserID: userID, Name: row.Name, Group: row.Group, Body: row.Body,
				Params: row.Params, UpdatedAt: row.UpdatedAt, Revision: revision,
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ListSnippets 返回一个账号存过的片段清单，最新修订在前、同修订按名字。
func (s *Store) ListSnippets(ctx context.Context, userID string) ([]SnippetRow, error) {
	var rows []snippetRow
	err := s.g.WithContext(ctx).Where("user_id = ?", userID).Order("revision DESC, name ASC").
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make([]SnippetRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, SnippetRow{Name: r.Name, Group: r.Group, Body: r.Body,
			Params: r.Params, UpdatedAt: r.UpdatedAt, Revision: r.Revision})
	}
	return out, nil
}

// -------------------------------------------------------------------- per-account settings

// SetSetting upserts one key. DELETE-then-INSERT instead of ON CONFLICT / ON DUPLICATE KEY:
// the three dialects spell the same upsert three different ways, and this spelling is all of them.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	return s.g.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("skey = ?", key).Delete(&settingRow{}).Error; err != nil {
			return err
		}
		return tx.Create(&settingRow{SKey: key, Value: value}).Error
	})
}

// GetSetting returns "" for an absent key. Callers treat "not configured" and "empty" alike:
// an unset channel key means fall back to the flag seed, not an error.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var one settingRow
	err := s.g.WithContext(ctx).Select("value").Where("skey = ?", key).First(&one).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", nil
	}
	return one.Value, err
}

func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	return s.g.WithContext(ctx).Where("skey = ?", key).Delete(&settingRow{}).Error
}
