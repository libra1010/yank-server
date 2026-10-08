// GORM 那一层的表形状。
//
// 这些结构体是"库里长什么样"的说法之一：存储层每一条读写照它走，列集合与
// migrations/{mysql,postgres}.sql 那两份全量 DDL 由一条 Go 测试逐表比对（漂了就红）。
// 字段类型是**刻意**选了能和那两份 DDL 互通的写法 ——
// 因为"DBA 先把表建好、再把 CREATE 权限收掉"是一条受支持的安装路径，两条路必须落在同一个形状上：
//
//   · 时间列存 VARCHAR(32) 的 RFC3339 串，不是 TIMESTAMP。三方言拿回来的表示本来就一致
//     （sqlite 给串、mysql/pgsql 给 time.Time），换成 TIMESTAMP 等于把这个问题请回来，
//     而且那是一次改表 + 存量迁移，不是改代码。ORDER BY created_at 靠 UTC RFC3339 的字典序
//     仍然是时间序。
//   · revoked 用 int 不用 bool：手写 DDL 里那一格是 INTEGER，pgsql 把 BOOLEAN 列和 INTEGER 列
//     分得很清，结构体写 bool 就读不出 DBA 那条路上建起来的库。0/1 由调用方自己判。
//   · 列名照库里的写（host_group、snippet_group、skey），不让 GORM 从字段名推导：
//     group 和 key 在 MySQL 里是保留字，这是当初为了三方言逐字相同做的取舍，不能在这一步丢掉。
//   · hosts 与 snippets 两张表没有主键（一次推送整体 DELETE+INSERT），blob_history 的键是
//     (user_id, revision) 复合 —— 都不符合 GORM "单列 ID 主键"的默认想象，所以凡是要定点
//     更新/删除的地方都显式给 Where，不赌它自己拼得出条件。
package main

// 这八个结构体不带 gorm.Model：那一套会塞进 id/created_at/updated_at/deleted_at 五格，
// 而这里的键是各表自己的（user_id、code_hash、skey），时间列存的是串，软删除更是从来没有过。
type userRow struct {
	ID        string `gorm:"column:id;size:32;primaryKey"`
	Name      string `gorm:"column:name;size:190;not null;uniqueIndex"`
	PwHash    string `gorm:"column:pw_hash;size:255;not null"`
	CreatedAt string `gorm:"column:created_at;size:32;not null"`
}

func (userRow) TableName() string { return "users" }

type deviceRow struct {
	ID        string `gorm:"column:id;size:40;primaryKey"`
	UserID    string `gorm:"column:user_id;size:32;not null;index:devices_user_id"`
	Name      string `gorm:"column:name;size:120;not null"`
	TokenHash string `gorm:"column:token_hash;size:64;not null;uniqueIndex"`
	CreatedAt string `gorm:"column:created_at;size:32;not null"`
	// LastSeen 可以为空：一台设备配上来还没见过第二次心跳，这时候管理端要显示"从没上线"，
	// 不是"1 月 1 日 00:00"。指针就是那一格空值。
	LastSeen *string `gorm:"column:last_seen;size:32"`
	Revoked  int     `gorm:"column:revoked;not null;default:0"`
}

func (deviceRow) TableName() string { return "devices" }

type pairCodeRow struct {
	CodeHash string `gorm:"column:code_hash;size:64;primaryKey"`
	UserID   string `gorm:"column:user_id;size:32;not null"`
	ExpiresAt string `gorm:"column:expires_at;size:32;not null"`
	UsedAt    *string `gorm:"column:used_at;size:32"`
}

func (pairCodeRow) TableName() string { return "pair_codes" }

// blobRow 是"当前一版"，一个账号一行，主键就是 user_id。Body 是客户端发来的原始字节，
// 服务端不重排、不解密，所以它必须是能装 0x00 的那种列。
type blobRow struct {
	UserID    string `gorm:"column:user_id;size:32;primaryKey"`
	Revision  int64  `gorm:"column:revision;not null"`
	DeviceID  string `gorm:"column:device_id;size:40;not null"`
	Body      []byte `gorm:"column:body;not null"`
	CreatedAt string `gorm:"column:created_at;size:32;not null"`
}

func (blobRow) TableName() string { return "blobs" }

// historyRow 一个账号一版一行，回滚就按 (user_id, revision) 取那一版。
type historyRow struct {
	UserID    string `gorm:"column:user_id;size:32;primaryKey;priority:1"`
	Revision  int64  `gorm:"column:revision;primaryKey;priority:2"`
	DeviceID  string `gorm:"column:device_id;size:40;not null"`
	Body      []byte `gorm:"column:body;not null"`
	CreatedAt string `gorm:"column:created_at;size:32;not null"`
}

func (historyRow) TableName() string { return "blob_history" }

// settingRow 是每账号一格的可写配置（通道密钥就在这里）。值本身是秘密：库文件本身才是要守的东西。
type settingRow struct {
	SKey  string `gorm:"column:skey;size:64;primaryKey"`
	Value string `gorm:"column:value;type:text;not null"`
}

func (settingRow) TableName() string { return "settings" }

// hostRow 是通道层解出来的那份主机清单（SPEC §5）。注意没有的东西：口令、私钥、vault。
// 这张表没有主键：一次推送是整体 DELETE+INSERT，行本身没有可寻址的身份。
type hostRow struct {
	UserID   string `gorm:"column:user_id;size:32;not null;index:hosts_user_rev,priority:1"`
	Name     string `gorm:"column:name;size:512;not null"`
	Group    string `gorm:"column:host_group;size:512;not null"`
	Hostname string `gorm:"column:hostname;size:512;not null"`
	Port     int64  `gorm:"column:port;not null"`
	Username string `gorm:"column:username;size:512;not null"`
	// AuthKind 是方式名（password / keyboard-interactive / private-key / agent）。
	// 空串是有意义的值："客户端没说"，管理端写"未知"，不猜。
	AuthKind string `gorm:"column:auth_kind;size:24;not null;default:''"`
	Notes    string `gorm:"column:notes;size:1024;not null;default:''"`
	Jump     string `gorm:"column:jump;size:512;not null;default:''"`
	Revision int64  `gorm:"column:revision;not null;index:hosts_user_rev,priority:2"`
}

func (hostRow) TableName() string { return "hosts" }

// snippetRow 是明文片段清单（SPEC §5.1），边界和 hostRow 一样；body 装的是端侧嗅探过的值。
type snippetRow struct {
	UserID    string `gorm:"column:user_id;size:32;not null;index:snippets_user_rev,priority:1"`
	Name      string `gorm:"column:name;size:512;not null"`
	Group     string `gorm:"column:snippet_group;size:512;not null"`
	Body      string `gorm:"column:body;size:2048;not null"`
	Params    string `gorm:"column:params;size:512;not null;default:''"`
	UpdatedAt string `gorm:"column:updated_at;size:40;not null;default:''"`
	Revision  int64  `gorm:"column:revision;not null;index:snippets_user_rev,priority:2"`
}

func (snippetRow) TableName() string { return "snippets" }

// everyModel 是 AutoMigrate 与漂移检测门共用那一张表：新加一张表就加进这里，
// 漏了的话 -ddl 那份文件会在门上红，而不是在线上第一次启动时才炸。
func everyModel() []any {
	return []any{userRow{}, deviceRow{}, pairCodeRow{}, blobRow{}, historyRow{},
		settingRow{}, hostRow{}, snippetRow{}}
}
