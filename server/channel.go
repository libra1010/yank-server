package main

// The channel layer (syncd/SPEC.md §5) is an OPTIONAL outer envelope built on a passphrase the
// admin page configures per account. v2 起（2026-10-06）密文里装的是 §3 那一整包：解开外层之后
// 就是和不加密传输完全相同的字节，走同一份 ingest，外层之外**一个明文字节都不许留** —— 从前
// 挂在密文旁边的两份明文数组正是这一档修掉的洞。解开后读得到主机清单与每行的 authKind，
// 但每行的口令/私钥仍是行内那格端到端密文（secretVault/secretMaterial 那一代只读不写），服务端解不开。
// Without a configured passphrase the server treats these bodies exactly like opaque blobs,
// so both envelope kinds coexist.

import (
	"encoding/json"
	"errors"
	"sort"
	"unicode/utf8"
)

const (
	channelLayer         = "channel"
	channelCipherName    = "AES-256-GCM"
	channelKeyBytes      = 32
	channelMaxFieldRunes = 512 // storage guard: VARCHAR(512) columns in every dialect
)

var (
	// errChannelAuth is deliberately vague, mirroring errAuthFailed on the inner envelope: no
	// oracle distinguishing "wrong key" from "malformed body".
	errChannelAuth  = errors.New("通道密钥不匹配或未配置")
	errChannelShape = errors.New("通道信封格式不合法")
	// A client that ships credentials inside the readable manifest crosses the line this feature
	// draws: the server indexes hosts, it does not hold passwords.
	errSecretInChannel = errors.New("加密传输清单里不得携带 secretMaterial")
)

// ChannelKdf names the algorithm and carries exactly what the server needs to redo the
// derivation: the per-envelope salt and the (fixed, non-negotiable) rounds. The retired
// pre-shared-32-bytes form ("raw") is no longer read or written by this version.
type ChannelKdf struct {
	Algorithm      string `json:"algorithm"`
	Salt           []byte `json:"salt,omitempty"`
	Rounds         uint32 `json:"rounds,omitempty"`
	KeyLengthBytes int    `json:"keyLengthBytes,omitempty"`
}

// ChannelEnvelope is the JSON document the client PUTs when 「加密传输（通道密钥）」 is on.
// Field order below IS the marshalled order, matching SPEC §5 key for key. IV and Ciphertext
// ride []byte so encoding/json emits standard padded base64, like the Swift side expects.
type ChannelEnvelope struct {
	FormatVersion int        `json:"formatVersion"`
	Layer         string     `json:"layer"`
	Cipher        string     `json:"cipher"`
	KDF           ChannelKdf `json:"kdf"`
	IV            []byte     `json:"iv"`
	Ciphertext    []byte     `json:"ciphertext"`
}

// IsChannelEnvelope is the cheap structural screen the handler runs before deciding which
// envelope kind it is looking at. It only reads formatVersion + layer, so a legacy PBKDF2
// envelope (which has neither field) is never mistaken for a channel one.
func IsChannelEnvelope(body []byte) bool {
	if len(body) == 0 || len(body) > maxPayloadBytes+64*1024 {
		return false
	}
	var head struct {
		FormatVersion int    `json:"formatVersion"`
		Layer         string `json:"layer"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return false
	}
	return head.Layer == channelLayer && head.FormatVersion == formatVersion
}

// channelWireFields 是通道信封**允许出现在外层的全部键**（SPEC §5：请求体只剩这几个通道自己的
// 字段）。hosts/snippets/meta 或任何别的键挂在密文旁边就是旧形状 —— 整包按格式非法拒掉，
// 绝不"只当没看见"：收下它们等于替旧客户端把"这一档在网络上什么都没遮住"的洞续命。
var channelWireFields = map[string]bool{
	"formatVersion": true, "layer": true, "cipher": true,
	"kdf": true, "iv": true, "ciphertext": true,
}

// OpenChannel decrypts the outer layer. `secret` is the passphrase this account configured on the
// page, verbatim — the 32-byte key is derived from it with the salt the envelope carries.
// Same house rules as ParseEnvelope: screen structure before spending any crypto, and give one
// undifferentiated error on failure.
func OpenChannel(secret, body []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errChannelAuth
	}
	if len(body) == 0 || len(body) > maxPayloadBytes+64*1024 {
		return nil, errChannelShape
	}
	var env ChannelEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, errChannelShape
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(body, &outer); err != nil {
		return nil, errChannelShape
	}
	for k := range outer {
		if !channelWireFields[k] {
			return nil, errChannelShape
		}
	}
	switch {
	case env.FormatVersion != formatVersion:
		return nil, errChannelShape
	case env.Layer != channelLayer:
		return nil, errChannelShape
	case env.Cipher != channelCipherName:
		return nil, errChannelShape
	case env.KDF.Algorithm != channelKdfPassphrase:
		return nil, errChannelShape
	case len(env.IV) != nonceLength:
		return nil, errChannelShape
	case len(env.Ciphertext) < tagLength:
		return nil, errChannelShape
	case len(env.Ciphertext) > maxPayloadBytes+tagLength:
		return nil, errChannelShape
	}
	// 结构筛完才花钱派生：一个乱发的请求体不该让服务端先跑 21 万轮 PBKDF2。
	key, kerr := deriveChannelKey(string(secret), env.KDF.Salt, env.KDF.Rounds)
	if kerr != nil {
		return nil, kerr
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, errChannelShape
	}
	// ciphertext carries ct||tag in one buffer with empty AAD — the exact layout §2 pins and
	// WebCrypto/SQLCipher-style clients hand over wholesale.
	plain, err := aead.Open(nil, env.IV, env.Ciphertext, nil)
	if err != nil {
		return nil, errChannelAuth
	}
	if len(plain) > maxPayloadBytes {
		return nil, errChannelShape
	}
	return plain, nil
}

// HostsFromChannel maps the opened **v1** manifest plaintext onto host rows — 只读不写的那一代：
// v2 起通道明文就是 §3 上传体，走 inventory.go 那份共用 ingest，不会再落到这里。It reads ONLY
// the whitelisted fields (SPEC §5: name/group/hostname/port/username/auth kind) — secretMaterial,
// secretVault and the rest of the document are dropped by the strict struct decode and never
// copied anywhere. revision is stamped by the caller once the blob write tells us the server
// revision.
//
// auth is read as a *kind*, never as a payload: the discriminator name is kept and everything
// inside it (the keychain account, the private key path) is thrown away. That is what lets the
// console say "这台是密码登录 / 那台是私钥" without the server ever holding a credential.
func HostsFromChannel(plain []byte) ([]HostRow, error) {
	var manifest struct {
		Profiles []struct {
			Name     string          `json:"name"`
			Group    string          `json:"group"`
			Hostname string          `json:"hostname"`
			Port     int64           `json:"port"`
			Username string          `json:"username"`
			Auth     json.RawMessage `json:"auth"`
		} `json:"profiles"`
		// A client that puts credentials into the readable part is broken or hostile: refuse the
		// write instead of holding plaintext passwords the server was never meant to see.
		SecretMaterial []json.RawMessage `json:"secretMaterial"`
	}
	if err := json.Unmarshal(plain, &manifest); err != nil {
		return nil, errChannelShape
	}
	if len(manifest.SecretMaterial) > 0 {
		return nil, errSecretInChannel
	}
	rows := make([]HostRow, 0, len(manifest.Profiles))
	for _, p := range manifest.Profiles {
		rows = append(rows, HostRow{
			Name:     clampChannelField(p.Name),
			Group:    clampChannelField(p.Group),
			Hostname: clampChannelField(p.Hostname),
			Port:     p.Port,
			Username: clampChannelField(p.Username),
			AuthKind: authKind(p.Auth),
		})
	}
	return rows, nil
}

// authKind keeps only the case name out of the profile's auth field. Swift encodes a case with
// no associated value ("agent") as a bare string and every other case as a one-key object, so
// both shapes have to be read. An unrecognised or absent auth returns "" — the console then
// says 未知, which is the truth, rather than guessing 密码.
func authKind(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var bare string
	if err := json.Unmarshal(raw, &bare); err == nil {
		return classifyAuth(bare)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil || len(keys) == 0 {
		return ""
	}
	// More than one key should never happen; sorting makes the answer stable instead of whatever
	// order the map iteration picks.
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	return classifyAuth(names[0])
}

// classifyAuth maps Swift's enum case names onto the stable codes the API and the table use.
// The codes are data, not UI copy: the console translates them into 密码/私钥/… itself.
func classifyAuth(discriminator string) string {
	switch discriminator {
	case "password":
		return "password"
	case "keyboardInteractive":
		return "keyboard-interactive"
	case "privateKey":
		return "private-key"
	case "agent":
		return "agent"
	default:
		return ""
	}
}

// clampChannelField keeps hostile or accidental megabyte strings out of the VARCHAR(512)
// columns. Rune-wise truncation so multi-byte names never end in half a character.
func clampChannelField(s string) string {
	if utf8.RuneCountInString(s) <= channelMaxFieldRunes {
		return s
	}
	return string([]rune(s)[:channelMaxFieldRunes])
}
