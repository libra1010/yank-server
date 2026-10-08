package main

// 清单明文元数据（SPEC §5.1，v2 形状见 §3）。
//
// v2 起，主机与片段两个数组**就是**上传体本身：每行明文的只有白名单那几格，私有部分作为该行
// 自己的不透明密文 `secret` 内联进来，账本在顶层那一格不透明 `meta` 里。没开通道口令时请求体
// 就是这份 §3 形状；开了，它就是通道密文的明文 —— 两条路跑同一份这里代码（SPEC §5）。
// v1（信封＋旁边挂两个数组）只读不写，行里没有 secret/meta 这两格。
//
// 口令的边界没有动，也不可能动：这些数组里只允许出现下面各自白名单里的键（v2 另加一格
// `secret`，服务端只当不透明串）。客户端要是（因为 bug 或被改坏）把凭据明文塞进来，服务端
// 不是"忽略"，而是**整次写入拒绝** —— 悄悄收下明文凭据是最糟的结局，它会让人以为口令还是加密的。
//
// 片段正文不需要服务端再嗅探一次：命中疑似口令时客户端已经把整条正文换成了一句提示，
// 服务端看到的就是普通字符串、照原样存。服务端守的是**键名**，不是值 —— 值端侧已经表过态了。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	errInventoryShape    = errors.New("清单数组形状不合法")
	errSecretInInventory = errors.New("主机清单里不得携带凭据字段")
)

// inventoryWhitelist 是明文清单里允许出现的**键名**，和 Swift 侧 HostInventoryEntry 一字不差。
var inventoryWhitelist = map[string]bool{
	"name": true, "group": true, "hostname": true, "port": true,
	"username": true, "authKind": true, "notes": true, "jump": true,
}

// snippetWhitelist 对着 Swift 侧 SnippetInventoryEntry，就这 5 个键。片段的本体（id 和没被
// 隐去的完整正文）照旧只在端到端信封里，多给一个键就等于多开一条"明文能走到哪"的口子。
var snippetWhitelist = map[string]bool{
	"name": true, "group": true, "body": true, "params": true, "updatedAt": true,
}

// inventoryForbiddenNeedles 扫键名，不扫值：authKind 的值本来就该是 "password" 这种词。
var inventoryForbiddenNeedles = []string{"secret", "password", "passphrase", "vault",
	"material", "token", "key", "credential", "privatekey"}

// rowSecretWireKey 是 v2 每行自带的那格端侧密文（SPEC §3，2026-10-06 拍板）。它是白名单之外的
// **唯一**豁免：只当不透明串收下，不解码、不解析、不落单独的列、不从任何 GET 回吐。v1 包没有
// 这一格，命中凭据词根照旧整次拒收 —— 两代形状各按各的口径判。
const rowSecretWireKey = "secret"

// metaWireKey 是 v2 顶层那格账本（revision/deviceID/别名/墓碑/pending），同样是不透明串：
// 服务端原样随整包字节存进 blobs，自己不读它，也永不替设备回放它。
const metaWireKey = "meta"

// checkInventoryEntryKeys 是两份清单共用的那道键名闸，判定顺序与原来逐字一致：白名单内放过，
// 命中凭据词根的用 errSecretInInventory 拒，其余未知键算形状错误。为什么未知键也要拒而不是忽略：
// 今天不是凭据的键，明天就可能变成某个新字段的藏身处；忽略等于默默收下发送方多给的东西。
// allowSecret 是 v2 那一格行内密文的豁免位（v1 恒为 false）。
func checkInventoryEntryKeys(entry map[string]json.RawMessage, whitelist map[string]bool,
	allowSecret bool) error {
	for k := range entry {
		if whitelist[k] || (allowSecret && k == rowSecretWireKey) {
			continue
		}
		lower := strings.ToLower(k)
		for _, needle := range inventoryForbiddenNeedles {
			if strings.Contains(lower, needle) {
				return fmt.Errorf("%w：%s", errSecretInInventory, k)
			}
		}
		return fmt.Errorf("%w：%s", errInventoryShape, k)
	}
	return nil
}

// takeRowSecret 把行里那格不透明 secret 摘出来：只验"它是不是个字符串"、数它的字面字节数
// （给「服务端收到了什么」那一句用），然后从 entry 里删掉 —— 行结构体从此看不见它，
// 更谈不上落列或回吐。
func takeRowSecret(entry map[string]json.RawMessage) (int, error) {
	raw, ok := entry[rowSecretWireKey]
	if !ok {
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, errInventoryShape
	}
	delete(entry, rowSecretWireKey)
	return len(s), nil
}

// ingestError 记录形状错误出自上传体的哪一格（hosts/snippets/meta），让 handler 还能按数组
// 分别给出原来的那句 400 中文理由，而不是把三份闸并成一句含糊的。
type ingestError struct {
	array string
	err   error
}

func (e *ingestError) Error() string { return e.err.Error() }
func (e *ingestError) Unwrap() error { return e.err }

// uploadFacts 是一次入库在"服务端被允许读到"的那一层看到的全部东西。hosts/snippets 用 nil
// 区分"这一格没带"与"带了但是空清单"（SPEC §5.1：缺席与清空是两件事）。fromManifest 标出
// 这份是 v1 通道清单（profiles[]）解出来的老形状：它不来自两个数组，「收到了什么」那句话
// 因此不能说"带了明文清单"。
type uploadFacts struct {
	hosts        []HostRow
	snippets     []SnippetRow
	v2           bool
	hasMeta      bool
	metaBytes    int
	secretBytes  int
	fromManifest bool
}

// IngestUploadV2 解析 §3 的 v2 上传体 —— 不加密时请求体本身就是它，开通道口令时通道明文也是
// 它，两条路共用这一份代码（SPEC §5「走和不加密传输一模一样的那条路」）。
// 错误分两档：顶层参数筛不过 → errUploadShape（handler 报 415，"根本不是这一代形状"）；
// 数组/meta 那一层的键名或类型问题 → *ingestError（400，整次写入拒绝）。
func IngestUploadV2(body []byte) (*uploadFacts, error) {
	if _, err := ParseUploadV2(body); err != nil {
		return nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, errUploadShape
	}
	facts := &uploadFacts{v2: true}
	if raw, ok := top[inventoryWireKey]; ok {
		rows, secretBytes, err := hostRowsFromArray(raw, true)
		if err != nil {
			return nil, &ingestError{array: "hosts", err: err}
		}
		facts.hosts, facts.secretBytes = rows, secretBytes
	}
	if raw, ok := top[snippetInventoryWireKey]; ok {
		rows, secretBytes, err := snippetRowsFromArray(raw, true)
		if err != nil {
			return nil, &ingestError{array: "snippets", err: err}
		}
		facts.snippets = rows
		facts.secretBytes += secretBytes
	}
	// meta 与 secret 同一条规矩：只验类型，不碰内容。
	if raw, ok := top[metaWireKey]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, &ingestError{array: "meta", err: errInventoryShape}
		}
		facts.hasMeta, facts.metaBytes = true, len(s)
	}
	return facts, nil
}

// ingestChannelPlain 是通道层解开之后那一步的分流：v2 起密文里装的就是 §3 那一整包，直接进
// 同一份 IngestUploadV2；老客户端的通道明文是带着 profiles/secretVault 的清单，走只读的
// HostsFromChannel。
func ingestChannelPlain(plain []byte) (*uploadFacts, error) {
	if IsUploadV2(plain) {
		return IngestUploadV2(plain)
	}
	hosts, err := HostsFromChannel(plain)
	if err != nil {
		return nil, err
	}
	return &uploadFacts{hosts: hosts, fromManifest: true}, nil
}

// hostRowsFromArray 解析一个清单数组。allowSecret 决定行里那一格 v2 密文是否合法；
// 返回的 secretBytes 是各行不透明串的字面字节和（只为「收到了什么」那句话数数，不落库）。
func hostRowsFromArray(raw json.RawMessage, allowSecret bool) ([]HostRow, int, error) {
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, 0, errInventoryShape
	}
	rows := make([]HostRow, 0, len(entries))
	secretBytes := 0
	for _, entry := range entries {
		if err := checkInventoryEntryKeys(entry, inventoryWhitelist, allowSecret); err != nil {
			return nil, 0, err
		}
		n, err := takeRowSecret(entry)
		if err != nil {
			return nil, 0, err
		}
		secretBytes += n
		var row struct {
			Name     string `json:"name"`
			Group    string `json:"group"`
			Hostname string `json:"hostname"`
			Port     int64  `json:"port"`
			Username string `json:"username"`
			AuthKind string `json:"authKind"`
			Notes    string `json:"notes"`
			Jump     string `json:"jump"`
		}
		// 白名单已保证这里只剩合法键；未知键在这一层被拒绝，绝不会被静默丢掉。
		if err := json.Unmarshal(mustJSON(entry), &row); err != nil {
			return nil, 0, errInventoryShape
		}
		rows = append(rows, HostRow{
			Name:     clampChannelField(row.Name),
			Group:    clampChannelField(row.Group),
			Hostname: clampChannelField(row.Hostname),
			Port:     row.Port,
			Username: clampChannelField(row.Username),
			AuthKind: clampAuthKind(row.AuthKind),
			Notes:    clampChannelField(row.Notes),
			Jump:     clampChannelField(row.Jump),
		})
	}
	return rows, secretBytes, nil
}

func snippetRowsFromArray(raw json.RawMessage, allowSecret bool) ([]SnippetRow, int, error) {
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, 0, errInventoryShape
	}
	rows := make([]SnippetRow, 0, len(entries))
	secretBytes := 0
	for _, entry := range entries {
		if err := checkInventoryEntryKeys(entry, snippetWhitelist, allowSecret); err != nil {
			return nil, 0, err
		}
		n, err := takeRowSecret(entry)
		if err != nil {
			return nil, 0, err
		}
		secretBytes += n
		var row struct {
			Name      string `json:"name"`
			Group     string `json:"group"`
			Body      string `json:"body"`
			Params    string `json:"params"`
			UpdatedAt string `json:"updatedAt"`
		}
		// 正文这里只是个字符串：客户端已经嗅探过（命中的整句被换成了"已在本机隐去"），
		// 服务端不再判第二遍——判了也不会更严，只会把客户端的口径改成服务端自己的。
		if err := json.Unmarshal(mustJSON(entry), &row); err != nil {
			return nil, 0, errInventoryShape
		}
		rows = append(rows, SnippetRow{
			Name:      clampChannelField(row.Name),
			Group:     clampChannelField(row.Group),
			Body:      clampSnippetBody(row.Body),
			Params:    clampChannelField(row.Params),
			UpdatedAt: clampRunes(row.UpdatedAt, snippetStampMaxRunes),
		})
	}
	return rows, secretBytes, nil
}

// topLevelInventoryObject 把请求体摊成"顶层键 → 原始值"，不是 JSON 对象就返回 nil：
// 那不是清单的错，交给信封/上传体那条路径去报错。
func topLevelInventoryObject(body []byte) map[string]json.RawMessage {
	if len(body) == 0 || body[0] != '{' {
		return nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}
	return top
}

// InventoryFromEnvelope reads the cleartext `hosts` array out of a **v1** request body (the
// envelope with the arrays hanging beside it). v1 rows carry no per-row `secret` — that key is
// a v2 thing, and here it still trips the credential-word-root screen. A body with no `hosts`
// key at all yields (nil, nil): older clients simply have no inventory yet, which is not an
// error. A key that IS present yields a non-nil slice even when empty — "this client has zero
// hosts now" has to clear the table, otherwise deleting your last host would leave it on the
// server forever.
func InventoryFromEnvelope(body []byte) ([]HostRow, error) {
	top := topLevelInventoryObject(body)
	if top == nil {
		return nil, nil
	}
	raw, ok := top[inventoryWireKey]
	if !ok {
		return nil, nil
	}
	rows, _, err := hostRowsFromArray(raw, false)
	return rows, err
}

const inventoryWireKey = "hosts"

// snippetInventoryWireKey 是信封旁边那个数组的键名，和 Swift 侧 SnippetInventory.wireKey
// 一字不差（改了两边任意一边，后果不是编译错误而是管理页的片段列静默变空，所以
// snippet_inventory_wire_test.go 直接把那份 Swift 源读来对字面量）。
const snippetInventoryWireKey = "snippets"

const (
	// snippetBodyMaxRunes 是 body 那一格（VARCHAR(2048)）的容量护栏，**不**与其余字段的 512
	// 同一档。理由是这两件事不是一回事：名称、分组截掉半截还是那个值，正文是命令 —— 截断过的
	// 命令抄回去跑是另一码事。所以服务端这道护栏只管容量（别让一句兆级字符串把列撑爆、把整次
	// 写入打挂），不管语义；语义上的"过长不给看"由端侧定（SnippetInventory.bodyLimit = 2040，
	// 刻意比这里小：客户端先表态，服务端这道只是谁都没表过态时的兜底）。
	snippetBodyMaxRunes = 2048
	// snippetStampMaxRunes：updated_at 列 VARCHAR(40)。ISO8601 用不满 40，夹一下同样是容量
	// 护栏而不是格式校验 —— 要认格式就得先猜"哪种时间写法算合法"，而这一列只用来排新旧。
	snippetStampMaxRunes = 40
)

// SnippetsFromEnvelope 读 **v1** 请求体旁边那个明文 `snippets` 数组，逐条对齐
// InventoryFromEnvelope 的语义：没有这个键（老客户端）→ (nil, nil)，库里的片段表保持原样、
// 不当错误；键在但形状不对（不是数组、某个值类型不对）→ 形状错误；键在且是空数组 → 非 nil 的
// 空切片，"这个账号删掉了最后一条片段"必须真的清表，否则删除在服务端永久留影。
// v1 行里没有 secret 这一格：未知键里命中凭据词根的那一类照旧走 errSecretInInventory 整次拒绝。
func SnippetsFromEnvelope(body []byte) ([]SnippetRow, error) {
	top := topLevelInventoryObject(body)
	if top == nil {
		return nil, nil
	}
	raw, ok := top[snippetInventoryWireKey]
	if !ok {
		return nil, nil
	}
	rows, _, err := snippetRowsFromArray(raw, false)
	return rows, err
}

// clampSnippetBody 按 rune 夹，理由与 clampChannelField 相同：中文正文不能停在半个字上。
func clampSnippetBody(s string) string { return clampRunes(s, snippetBodyMaxRunes) }

func clampRunes(s string, limit int) string {
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit])
}

// rebuildInventory re-derives the stored inventory from a stored body. Used when a channel key
// is saved after the fact and when a rollback moves the blob forward. 三种形状各按各的口径读，
// 但走的全是入库时同一份代码：通道信封**只从解开后的明文里**拿清单（v2 起外面根本没有明文字节，
// 从外面那层读数组就是 2026-10-06 修掉的那个洞）；v1 信封旁边那两个数组依旧直接读 —— 只读不写。
func (s *Server) rebuildInventory(ctx context.Context, userID string, body []byte, revision int64) {
	switch {
	case IsChannelEnvelope(body):
		key, _ := s.channelKeyFor(ctx, userID)
		if len(key) == 0 {
			return
		}
		plain, err := OpenChannel(key, body)
		if err != nil {
			return
		}
		facts, err := ingestChannelPlain(plain)
		if err == nil {
			s.saveFacts(ctx, userID, revision, facts)
		}
	case IsUploadV2(body):
		if facts, err := IngestUploadV2(body); err == nil {
			s.saveFacts(ctx, userID, revision, facts)
		}
	default:
		// v1。片段这一份**只有**明文数组这一条路：老客户端的片段从来只锁在端到端信封里、
		// 服务端本来就解不开，所以这里没有后备可退，解不出数组就什么都不动（不是清表——
		// 那一次修订根本没上传片段）。
		if snippets, err := SnippetsFromEnvelope(body); err == nil && snippets != nil {
			_ = s.store.ReplaceSnippets(ctx, userID, revision, snippets)
		}
		if hosts, err := InventoryFromEnvelope(body); err == nil && hosts != nil {
			_ = s.store.ReplaceHosts(ctx, userID, revision, hosts)
		}
	}
}

// saveFacts 是重建路径上的落表一步：解析不动就把两张能动的表各自整体换掉。
func (s *Server) saveFacts(ctx context.Context, userID string, revision int64, facts *uploadFacts) {
	if facts.hosts != nil {
		_ = s.store.ReplaceHosts(ctx, userID, revision, facts.hosts)
	}
	if facts.snippets != nil {
		_ = s.store.ReplaceSnippets(ctx, userID, revision, facts.snippets)
	}
}

// mustJSON re-marshals the already-validated key set. Going through the map rather than the
// original bytes keeps the "unknown key" decision in exactly one place (checkInventoryEntryKeys).
func mustJSON(entry map[string]json.RawMessage) []byte {
	out, err := json.Marshal(entry)
	if err != nil {
		return []byte("{}")
	}
	return out
}

// clampAuthKind keeps only the four codes the client is allowed to send. Anything else becomes
// "" and the console says 未知 — guessing "password" would be a lie about someone's server.
func clampAuthKind(kind string) string {
	switch kind {
	case "password", "keyboard-interactive", "private-key", "agent":
		return kind
	default:
		return ""
	}
}
