package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- fixtures

var (
	// chanA 是页面上会被填进去的那句口令；chanB 代表"另一端填错了"。这一层不再有 64 个字符
	// 的 hex/base64——口令短到能念出来，两端凭 6 位指纹核对是不是同一句。
	chanA = "yank-通道-demo"
	chanB = "yank-通道-另一个"

	// SPEC §5 互操作向量：salt 与 iv 固定，Go 和 Swift 必须派生出同一把密钥、写出同一份密文。
	vecSaltHex = "00112233445566778899aabbccddeeff"
	vecIVHex   = "a0a1a2a3a4a5a6a7a8a9aaab"

	// Sentinels for the secret-boundary negative control. They ride along inside the manifest
	// plaintext (exactly where a client might leave them) and must never reach disk in the clear.
	fakePassword = "S3cretFakePw-NEVER-ON-DISK"
	fakeVault    = "VGhlVmF1bHRCbG9iTmV2ZXJSZWFkc0xpbmUtT3JESVNL"
)

// newChanEnv spins a full server on a temp sqlite file whose path the test keeps, so the
// negative-control grep can read the database bytes directly (mirroring tools/syncd-smoke.sh).
// The channel passphrase is configured through the same page API a human uses — there is no
// startup flag any more, so a test that skips that call is testing the keyless server.
func newChanEnv(t *testing.T, passphrase string) (*env, *Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "chan.db")
	store, err := Open("sqlite://" + dbPath)
	if err != nil {
		t.Fatalf("开库失败：%v", err)
	}
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatalf("迁移失败：%v", err)
	}
	srv := httptest.NewServer(NewServer(store).Handler())
	t.Cleanup(func() { srv.Close(); _ = store.Close() })
	e := &env{t: t, srv: srv}
	e.enroll("devops", "a-long-enough-pass")
	e.pairDevice("mac-a")
	if passphrase != "" {
		res, body := e.json("POST", "/api/channel", e.token, map[string]string{"key": passphrase})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("页面配置通道口令失败：%d %s", res.StatusCode, body)
		}
	}
	return e, store, dbPath
}

func manifestJSON(t *testing.T, profiles ...map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"revision":              7,
		"deviceID":              "mac-a",
		"profiles":              profiles,
		"secretAccountsPending": []string{},
		"secretMaterial":        []any{}, // SPEC §5: empty in channel mode
		"secretVault":           fakeVault,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// SPEC §5: the readable manifest must never carry credentials. A buggy or hostile client that
// puts them there is refused outright — the server indexes hosts, it does not hold passwords.
func TestChannelManifestWithSecretMaterialRejected(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	plain, err := json.Marshal(map[string]any{
		"revision": 7, "deviceID": "mac-a", "secretAccountsPending": []string{},
		"secretVault": fakeVault,
		"profiles": []map[string]any{{"id": "A", "name": "nas", "group": "家里",
			"hostname": "nas.lan", "port": 2222, "username": "backup"}},
		"secretMaterial": []map[string]any{{"account": "ssh:nas:backup", "kind": "password",
			"data": fakePassword}},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, body := e.putBlob(sealManifest(t, chanA, plain), "0")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("带 secretMaterial 的信封必须被拒，实际 %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "secretMaterial") {
		t.Errorf("拒绝理由要点明 secretMaterial，实际 %s", body)
	}
	res, _ = e.call("GET", "/api/blob", e.device, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("被拒的写入不该落库，GET /api/blob 实际 %d", res.StatusCode)
	}
	rows, res, _ := getHosts(t, e, e.token)
	if res.StatusCode != http.StatusOK || len(rows) != 0 {
		t.Errorf("被拒的写入不该产生主机行：%d %v", res.StatusCode, rows)
	}
}

// 回退要带着主机索引一起回退，否则 /api/hosts 还在广告刚被撤销的那一版。
func TestRollbackReindexesHosts(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	first := sealManifest(t, chanA, manifestJSON(t,
		map[string]any{"id": "A", "name": "一版", "group": "g", "hostname": "one.lan",
			"port": 22, "username": "root"}))
	second := sealManifest(t, chanA, manifestJSON(t,
		map[string]any{"id": "B", "name": "二版", "group": "g", "hostname": "two.lan",
			"port": 22, "username": "ops"}))
	if res, body := e.putBlob(first, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("第一版写入失败：%d %s", res.StatusCode, body)
	}
	if res, body := e.putBlob(second, "1"); res.StatusCode != http.StatusOK {
		t.Fatalf("第二版写入失败：%d %s", res.StatusCode, body)
	}
	res, body := e.json("POST", "/api/blob/rollback", e.token, map[string]int64{"revision": 1})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("回退失败：%d %s", res.StatusCode, body)
	}
	rows, res, raw := getHosts(t, e, e.token)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("回退后读主机清单失败：%d %s", res.StatusCode, raw)
	}
	if len(rows) != 1 || rows[0].Hostname != "one.lan" {
		t.Fatalf("回退后索引应当回到第一版，实际 %+v", rows)
	}
}

func twoHostManifest(t *testing.T) []byte {
	return manifestJSON(t,
		map[string]any{"id": "A", "name": "生产跳板机", "group": "生产", "hostname": "jump.example.com",
			"port": 22, "username": "devops",
			// A rogue/legacy client leaving a password next to the profile: the server must
			// ignore everything outside the five whitelisted fields.
			"auth": map[string]any{"kind": "password", "password": fakePassword}},
		map[string]any{"id": "B", "name": "nas", "group": "家里", "hostname": "nas.lan",
			"port": 2222, "username": "backup"})
}

func oneHostManifest(t *testing.T) []byte {
	return manifestJSON(t,
		map[string]any{"id": "B", "name": "nas", "group": "家里", "hostname": "nas.lan",
			"port": 2222, "username": "backup"})
}

// sealManifest produces the outer envelope a real client would PUT: fresh random salt + iv, so
// two pushes of the same manifest are different bytes.
func sealManifest(t *testing.T, passphrase string, manifest []byte) []byte {
	t.Helper()
	body, err := SealChannel(passphrase, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func getHosts(t *testing.T, e *env, auth string) ([]HostRow, *http.Response, []byte) {
	t.Helper()
	res, body := e.call("GET", "/api/hosts", auth, nil)
	var rows []HostRow
	if err := json.Unmarshal(body, &rows); err != nil && res.StatusCode == http.StatusOK {
		t.Fatalf("主机清单不是合法 JSON 数组：%v %s", err, body)
	}
	return rows, res, body
}

// diskBytes concatenates the sqlite main file plus its WAL/shm siblings: WAL mode can leave the
// most recent writes in -wal, and a grep that misses it proves nothing.
func diskBytes(t *testing.T, dbPath string) []byte {
	t.Helper()
	var all bytes.Buffer
	for _, suffix := range []string{"", "-wal", "-shm"} {
		raw, err := os.ReadFile(dbPath + suffix)
		if err != nil {
			continue
		}
		all.Write(raw)
	}
	return all.Bytes()
}

// ---------------------------------------------------------------- 口令与指纹

// 口令这一层的下限只挡"空口令＝谁都能解开外层"。中文按字数算，不按字节算。
func TestChannelPassphraseGate(t *testing.T) {
	for _, ok := range []string{"yank-通道-demo", "abcdefgh", "八个字符的中文口令", "  padded-pass  "} {
		if err := CheckChannelPassphrase(ok); err != nil {
			t.Errorf("%q 本该合格，实际 %v", ok, err)
		}
	}
	for _, bad := range []string{"", "   ", "1234567", "五个中文字", strings.Repeat("a", 4096)[:7]} {
		if err := CheckChannelPassphrase(bad); err == nil {
			t.Errorf("%q 本该被拒却通过了", bad)
		} else if !strings.Contains(err.Error(), "通道密钥") {
			t.Errorf("%q 的拒绝理由应指向通道密钥：%v", bad, err)
		}
	}
}

// 指纹是两端唯一能核对"填的是不是同一句"的东西，所以它的字节口径是跨语言契约：Go 与 Swift
// 对同一句口令必须给出同一个 6 位十六进制。空格不参与（页面存的就是 trim 之后的文本）。
func TestChannelFingerprintVector(t *testing.T) {
	if got := ChannelFingerprint(chanA); got != "55C257" {
		t.Errorf("口令 %q 的指纹应逐字节等于互操作向量，实际 %q", chanA, got)
	}
	if ChannelFingerprint(chanA) != ChannelFingerprint("  "+chanA+" ") {
		t.Error("指纹应当忽略首尾空格")
	}
	if ChannelFingerprint(chanA) == ChannelFingerprint(chanB) {
		t.Error("两句不同口令指纹相同：指纹没起作用")
	}
}

// 派生参数是写死的：salt 必须 16 字节、轮数必须 21 万。服务端不能由信封里的字段决定自己算多久。
func TestDeriveChannelKeyParametersAreFixed(t *testing.T) {
	salt := mustHex(t, vecSaltHex)
	want, err := hex.DecodeString("b55eadda8f070618bed732618654bd29a79c66a885145b6e788ee111fdd1f497")
	if err != nil {
		t.Fatal(err)
	}
	got, err := deriveChannelKey(chanA, salt, channelPassphraseRounds)
	if err != nil {
		t.Fatalf("按写死的参数派生失败：%v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("派生密钥与互操作向量不符：%x", got)
	}
	if _, err := deriveChannelKey(chanA, salt[:15], channelPassphraseRounds); !errors.Is(err, errChannelShape) {
		t.Errorf("15 字节 salt 应被拒，实际 %v", err)
	}
	for _, rounds := range []uint32{1, 209_999, 210_001, 10_000_000} {
		if _, err := deriveChannelKey(chanA, salt, rounds); !errors.Is(err, errChannelShape) {
			t.Errorf("轮数 %d 不该被接受，实际 %v", rounds, err)
		}
	}
}

// ---------------------------------------------------------------- seal / open

func TestChannelSealOpenRoundTrip(t *testing.T) {
	plaintext := []byte(`{"revision":3,"profiles":[{"name":"边界情况 é","hostname":"x.example.com"}]}`)
	body, err := SealChannel(chanA, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !IsChannelEnvelope(body) {
		t.Fatal("IsChannelEnvelope 认不出自家封装的信封")
	}
	got, err := OpenChannel([]byte(chanA), body)
	if err != nil {
		t.Fatalf("正确的口令解不开：%v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("明文不一致：%q", got)
	}
	if _, err := OpenChannel([]byte(chanB), body); !errors.Is(err, errChannelAuth) {
		t.Errorf("错误的口令应得 errChannelAuth，实际 %v", err)
	}
	// 没配置就没有派生的输入。这里必须直接拒，绝不能拿空字符串去派生一把"谁都能算"的密钥。
	if _, err := OpenChannel(nil, body); !errors.Is(err, errChannelAuth) {
		t.Errorf("空口令应得 errChannelAuth，实际 %v", err)
	}
	// 篡改一个 base64 字符也必须触发认证失败，而不是悄悄解开成别的字节。
	tampered := append([]byte(nil), body...)
	for i := len(tampered) - 2; i > 0; i-- { // 最后一个字符在引号前，往前找一个字母数字
		if (tampered[i] >= 'a' && tampered[i] <= 'z') || (tampered[i] >= '0' && tampered[i] <= '9') {
			tampered[i] ^= 1
			break
		}
	}
	if _, err := OpenChannel([]byte(chanA), tampered); err == nil {
		t.Error("篡改密文竟然解开了")
	}
}

// 旧形状（两端各粘 32 字节 hex/base64，kdf.algorithm = "raw"）在这一版既不再被写出，也不再被
// 打开。留着它只会让"口令填错"和"对端还在用旧格式"混成同一条错误，而库里根本没有这种信封。
func TestLegacyRawEnvelopeIsRefused(t *testing.T) {
	body := []byte(`{"formatVersion":1,"layer":"channel","cipher":"AES-256-GCM",` +
		`"kdf":{"algorithm":"raw"},"iv":"AAAAAAAAAAAAAAAAAAAAAA==","ciphertext":"AAAAAAAAAAAAAAAA"}`)
	if _, err := OpenChannel([]byte(chanA), body); !errors.Is(err, errChannelShape) {
		t.Errorf("raw 信封应按格式非法拒掉，实际 %v", err)
	}
}

// TestSealChannelWireShape pins the byte-level contract of SPEC §5 that the Swift client codes
// against: exact JSON key set and values, the salt/rounds the peer must reuse, 12 iv bytes, and
// ciphertext = ct‖tag — verified by decrypting with stdlib primitives straight off the decoded
// fields. salt/iv come from the fixed interop vector so a byte mismatch is a real mismatch.
func TestSealChannelWireShape(t *testing.T) {
	plaintext := []byte(`{"revision":1,"profiles":[]}`)
	salt, iv := mustHex(t, vecSaltHex), mustHex(t, vecIVHex)
	body, err := SealChannelPassphrase(chanA, salt, iv, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	if len(keys) != 6 {
		t.Fatalf("字段数不对（%d 个：%v）——SPEC §5 是 6 个", len(keys), keys)
	}
	for _, k := range []string{"formatVersion", "layer", "cipher", "kdf", "iv", "ciphertext"} {
		if _, ok := doc[k]; !ok {
			t.Fatalf("缺少字段 %q：%s", k, body)
		}
	}
	assertLiteral := func(key, want string) {
		t.Helper()
		if !strings.Contains(string(doc[key]), want) {
			t.Errorf("%s 应含 %s，实际 %s", key, want, doc[key])
		}
	}
	assertLiteral("formatVersion", "1")
	assertLiteral("layer", `"channel"`)
	assertLiteral("cipher", `"AES-256-GCM"`)
	var kdf map[string]any
	if err := json.Unmarshal(doc["kdf"], &kdf); err != nil || len(kdf) != 4 ||
		kdf["algorithm"] != channelKdfPassphrase || kdf["rounds"] != float64(channelPassphraseRounds) ||
		kdf["keyLengthBytes"] != float64(channelKeyBytes) {
		t.Fatalf(`kdf 应是口令派生的四个参数，实际 %v (%v)`, kdf, err)
	}
	var carried ChannelKdf
	if err := json.Unmarshal(doc["kdf"], &carried); err != nil || !bytes.Equal(carried.Salt, salt) {
		t.Errorf("kdf.salt 应是信封自带的那 16 字节（%x），实际 %x (%v)", salt, carried.Salt, err)
	}
	wireIV, err := base64.StdEncoding.DecodeString(string(bytesTrim(doc["iv"])))
	if err != nil {
		t.Fatalf("iv 不是标准 base64：%v", err)
	}
	if len(wireIV) != nonceLength || !bytes.Equal(wireIV, iv) {
		t.Errorf("iv 应是互操作向量那 %d 字节（%x），实际 %x", nonceLength, iv, wireIV)
	}
	ct, err := base64.StdEncoding.DecodeString(string(bytesTrim(doc["ciphertext"])))
	if err != nil {
		t.Fatalf("ciphertext 不是标准 base64：%v", err)
	}
	if len(ct) != len(plaintext)+tagLength {
		t.Errorf("ciphertext 应是 明文‖16字节tag，实际 %d 字节（明文 %d）", len(ct), len(plaintext))
	}
	// Manual open: 派生 + 布局都按 SPEC §5 重做一遍，证明这就是 Swift Crypto / WebCrypto 端
	// 会原样产出的字节。
	derived, err := deriveChannelKey(chanA, salt, channelPassphraseRounds)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := aead.Open(nil, iv, ct, nil)
	if err != nil || !bytes.Equal(plain, plaintext) {
		t.Errorf("按 SPEC §5 手工解密失败：%v", err)
	}
	// 固定参数下封装是确定的（互操作向量的前提）；而真实客户端走 SealChannel，每次换 salt 与 iv，
	// 所以同一份清单两次上传的字节必然不同。
	same, _ := SealChannelPassphrase(chanA, salt, iv, plaintext)
	if !bytes.Equal(same, body) {
		t.Error("同一组 salt/iv 两次封装字节不同：派生或布局不稳定")
	}
	other, _ := SealChannel(chanA, plaintext)
	if bytes.Equal(other, body) {
		t.Error("两次封装字节相同：salt/iv 没用新随机数")
	}
	if _, err := OpenChannel([]byte(chanA), other); err != nil {
		t.Errorf("随机参数那一版也该打得开：%v", err)
	}
}

func bytesTrim(raw json.RawMessage) []byte {
	return bytes.Trim(raw, "\"")
}

func TestIsChannelEnvelopeScreening(t *testing.T) {
	if IsChannelEnvelope(nil) || IsChannelEnvelope([]byte(`not json`)) {
		t.Error("空/垃圾输入不应被认成通道信封")
	}
	if IsChannelEnvelope(envelopeBody(t, `{"revision":1}`)) {
		t.Error("清单信封（无 layer 字段）不应被认成通道信封")
	}
	if IsChannelEnvelope([]byte(`{"formatVersion":2,"layer":"channel","cipher":"AES-256-GCM",` +
		`"kdf":{"algorithm":"` + channelKdfPassphrase + `","salt":"AAAAAAAAAAAAAAAAAAAAAA==",` +
		`"rounds":210000,"keyLengthBytes":32},"iv":"AAAAAAAAAAAAAAAAAAAAAA==","ciphertext":"AA=="}`)) {
		t.Error("版本号不符的信封不应被认成通道信封")
	}
	good, _ := SealChannel(chanA, []byte(`{}`))
	if !IsChannelEnvelope(good) {
		t.Error("合法通道信封没被认出来")
	}
}

func TestHostsFromChannelKeepsOnlyWhitelistedFields(t *testing.T) {
	// 512 上限：超长字段截断而不是让入库报错拖垮整个 PUT。
	long := strings.Repeat("超长主机名", 200)
	manifest, err := json.Marshal(map[string]any{
		"revision":    1,
		"secretVault": fakeVault,
		"profiles": []any{map[string]any{
			"name": long, "group": "g", "hostname": "h", "port": 22, "username": "u",
			"auth": map[string]any{"password": fakePassword},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := HostsFromChannel(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("应有 1 行，实际 %d", len(rows))
	}
	if runeLen(rows[0].Name) != channelMaxFieldRunes {
		t.Errorf("超长 name 应截断到 %d，实际 %d", channelMaxFieldRunes, runeLen(rows[0].Name))
	}
	joined := strings.Join([]string{rows[0].Name, rows[0].Group, rows[0].Hostname, rows[0].Username}, "|")
	if strings.Contains(joined, fakePassword) || strings.Contains(joined, fakeVault) {
		t.Error("凭据字段漏进了主机白名单")
	}
	if _, err := HostsFromChannel([]byte(`{"profiles":`)); err == nil {
		t.Error("非法清单 JSON 应报错")
	}
}

func runeLen(s string) int { return len([]rune(s)) }

// ---------------------------------------------------------------- HTTP wiring

func TestChannelPutWrongKeyRejected400(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	wrong := sealManifest(t, chanB, twoHostManifest(t))
	res, body := e.putBlob(wrong, "0")
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("口令不符应 400，实际 %d %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), "通道密钥不匹配或未配置") {
		t.Errorf("400 应带中文理由，实际 %s", body)
	}
	// 不静默退回存储：库里必须还是空的。
	res, _ = e.call("GET", "/api/blob", e.device, nil)
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("被拒的信封不该落库，GET /api/blob 实际 %d", res.StatusCode)
	}
	rows, res, _ := getHosts(t, e, e.token)
	if res.StatusCode != http.StatusOK || len(rows) != 0 {
		t.Errorf("被拒的写入不该产生清单行：%d %v", res.StatusCode, rows)
	}
}

func TestChannelHostsStoredAndReplacedNotAppended(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	first := sealManifest(t, chanA, twoHostManifest(t))
	res, body := e.putBlob(first, "0")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("通道信封写入应成功：%d %s", res.StatusCode, body)
	}
	rows, _, _ := getHosts(t, e, e.token)
	if len(rows) != 2 {
		t.Fatalf("首次应落 2 行，实际 %d：%+v", len(rows), rows)
	}
	if rows[0].Revision != 1 || rows[1].Revision != 1 {
		t.Errorf("行应带服务端版本号 1：%+v", rows)
	}

	second := sealManifest(t, chanA, oneHostManifest(t))
	if res, body = e.putBlob(second, "1"); res.StatusCode != http.StatusOK {
		t.Fatalf("第二版写入失败：%d %s", res.StatusCode, body)
	}
	rows, _, _ = getHosts(t, e, e.token)
	if len(rows) != 1 {
		t.Fatalf("整批覆盖后应只剩 1 行，实际 %d：%+v（追加而非覆盖？）", len(rows), rows)
	}
	if rows[0].Name != "nas" || rows[0].Group != "家里" || rows[0].Hostname != "nas.lan" ||
		rows[0].Port != 2222 || rows[0].Username != "backup" || rows[0].Revision != 2 {
		t.Errorf("行内容与信封不符：%+v", rows[0])
	}
}

func TestHostsEndpointAuthMatrix(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	body := sealManifest(t, chanA, twoHostManifest(t))
	if res, got := e.putBlob(body, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("写入失败：%d %s", res.StatusCode, got)
	}
	// 会话令牌可看。
	rows, res, _ := getHosts(t, e, e.token)
	if res.StatusCode != http.StatusOK || len(rows) != 2 {
		t.Errorf("会话令牌应看到 2 行：%d %v", res.StatusCode, rows)
	}
	// 设备令牌同样可看（与 GET /api/blob 的 requireAny 口径一致）。
	if rows, res, _ = getHosts(t, e, e.device); res.StatusCode != http.StatusOK || len(rows) != 2 {
		t.Errorf("设备令牌应看到 2 行：%d %v", res.StatusCode, rows)
	}
	if res, _ := e.call("GET", "/api/hosts", "", nil); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("匿名应 401，实际 %d", res.StatusCode)
	}
}

func TestChannelEnvelopeOpaqueWithoutKey(t *testing.T) {
	// 没配口令：通道信封照旧当不透明密文存，清单走客户端明文那一份（这里没有，所以是空表）。
	e, _, _ := newChanEnv(t, "")
	body := sealManifest(t, chanA, twoHostManifest(t))
	res, put := e.putBlob(body, "0")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("未配密钥时写入应照常成功：%d %s", res.StatusCode, put)
	}
	res, pulled := e.call("GET", "/api/blob", e.device, nil)
	if !bytes.Equal(pulled, body) {
		t.Errorf("blob 应原样存回去：%s", pulled)
	}
	// 没配通道密钥也照样能看清单（用户拍板）：清单来自客户端明面上上传的 `hosts` 数组，
	// 这份体里没有那个数组，所以是 200 + 空表，而不是 503 把读者挡在门外。
	res, hostsBody := e.call("GET", "/api/hosts", e.token, nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("未配密钥时清单接口应 200，实际 %d", res.StatusCode)
	}
	if strings.TrimSpace(string(hostsBody)) != "[]" {
		t.Errorf("没有明文清单时应回空数组，实际 %s", hostsBody)
	}
}

func TestLegacyEnvelopeCoexistsWithChannelKey(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	// 老式口令信封在一个开了通道密钥的服务上必须分毫如旧：能写、能读回、垃圾仍 415。
	legacy := envelopeBody(t, `{"revision":1}`)
	if res, body := e.putBlob(legacy, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("清单信封应照旧可写：%d %s", res.StatusCode, body)
	}
	res, _ := e.call("PUT", "/api/blob", e.device, []byte(`{"formatVersion":1}`))
	if res.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("垃圾请求体应仍是 415，实际 %d", res.StatusCode)
	}
	// 两种信封交替写入互不干扰；legacy 写入不动 hosts 表。
	channel := sealManifest(t, chanA, twoHostManifest(t))
	if res, body := e.putBlob(channel, "1"); res.StatusCode != http.StatusOK {
		t.Fatalf("通道信封被 legacy 挤掉了：%d %s", res.StatusCode, body)
	}
	rows, _, _ := getHosts(t, e, e.token)
	if len(rows) != 2 {
		t.Fatalf("通道写入后应有 2 行，实际 %+v", rows)
	}
	if res, body := e.putBlob(envelopeBody(t, `{"revision":3}`), "2"); res.StatusCode != http.StatusOK {
		t.Fatalf("混回 legacy 失败：%d %s", res.StatusCode, body)
	}
	rows, _, _ = getHosts(t, e, e.token)
	if len(rows) != 2 {
		t.Errorf("legacy 写入不应清空/追加主机行，实际 %+v", rows)
	}
	res, pulled := e.call("GET", "/api/blob", e.token, nil)
	if res.StatusCode != http.StatusOK || bytes.Equal(pulled, channel) {
		t.Errorf("最新信封应是刚写入的 legacy：%d %s", res.StatusCode, pulled)
	}
}

func TestChannelBlobBytesStoredVerbatim(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	body := sealManifest(t, chanA, twoHostManifest(t))
	if res, got := e.putBlob(body, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("写入失败：%d %s", res.StatusCode, got)
	}
	res, pulled := e.call("GET", "/api/blob", e.device, nil)
	if res.StatusCode != http.StatusOK || !bytes.Equal(pulled, body) {
		t.Errorf("GET /api/blob 应逐字节等于客户端发的内容")
	}
	hist, resBody := e.call("GET", "/api/blob/at/1", e.token, nil)
	if hist.StatusCode != http.StatusOK || !bytes.Equal(resBody, body) {
		t.Errorf("历史第 1 版应逐字节等于写入内容：%d", hist.StatusCode)
	}
}

// TestChannelSecretBoundary is the negative control: everything the server must NOT be able to
// read is planted in the manifest plaintext, then we grep the raw sqlite bytes on disk — same
// strings-grep technique as tools/syncd-smoke.sh, but inverted: now the server does decrypt the
// outer layer, so the proof has to be that only the whitelisted columns ever hit storage.
func TestChannelSecretBoundary(t *testing.T) {
	e, store, dbPath := newChanEnv(t, chanA)
	body := sealManifest(t, chanA, twoHostManifest(t))
	if res, got := e.putBlob(body, "0"); res.StatusCode != http.StatusOK {
		t.Fatalf("写入失败：%d %s", res.StatusCode, got)
	}

	onDisk := diskBytes(t, dbPath)
	for _, secret := range []string{fakePassword, fakeVault} {
		if bytes.Contains(onDisk, []byte(secret)) {
			t.Errorf("秘密 %q 泄露进了数据库文件", secret)
		}
	}

	// hosts 表结构里不能有凭据类列。
	rows, err := store.db.Query("PRAGMA table_info(hosts)")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			t.Fatal(err)
		}
		cols[name] = true
	}
	want := []string{"user_id", "name", "host_group", "hostname", "port", "username",
		"auth_kind", "notes", "jump", "revision"}
	if len(cols) != len(want) {
		t.Errorf("hosts 列集合应是 %v，实际 %v", want, cols)
	}
	for _, c := range want {
		if !cols[c] {
			t.Errorf("缺列 %s", c)
		}
	}
	// auth_kind 是唯一带 "auth" 字样又合法的列：它只存判别名（password / private-key / …），
	// 不存任何凭据。白名单按整名放行，所以将来混进来的 auth_token / authorized_keys
	// 仍然会被下面这条扫出来。
	allowedNamedAuthColumn := map[string]bool{"auth_kind": true}
	for suspicious := range cols {
		if allowedNamedAuthColumn[suspicious] {
			continue
		}
		for _, needle := range []string{"secret", "password", "vault", "key", "material", "auth"} {
			if strings.Contains(strings.ToLower(suspicious), needle) {
				t.Errorf("hosts 表出现了凭据类列 %q", suspicious)
			}
		}
	}

	// API 响应同样不回显任何凭据。
	_, res, hostsBody := getHosts(t, e, e.token)
	if strings.Contains(string(hostsBody), fakePassword) || strings.Contains(string(hostsBody), fakeVault) {
		t.Errorf("GET /api/hosts 回显了凭据：%s", hostsBody)
	}
	_ = res
}
