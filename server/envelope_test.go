package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type vector struct {
	Name         string `json:"name"`
	Passphrase   string `json:"passphrase"`
	Plaintext    string `json:"plaintext"`
	EnvelopeJSON string `json:"envelopeJSON"`
}

type vectorFile struct {
	Note    string   `json:"note"`
	Vectors []vector `json:"vectors"`
}

// loadVectors reads the interoperability vectors this repo commits as an artifact.
// They are produced by the reference client (the closed-source Mac app), never by this
// server —— that asymmetry IS the test: Go verifies bytes Swift emitted on another machine.
// See ../testdata/README.md. A missing file fails the test; skipping silently would make
// this the weakest kind of green.
func loadVectors(t *testing.T) []vector {
	t.Helper()
	path := filepath.Join("..", "testdata", "envelope-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到互操作向量 %s：%v（这是提交进仓的产物，重新生成见 testdata/README.md）",
			path, err)
	}
	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("向量文件解析失败：%v", err)
	}
	if len(file.Vectors) < 3 {
		t.Fatalf("向量太少(%d)，测不出漂移", len(file.Vectors))
	}
	return file.Vectors
}

func TestInteropVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			env, err := ParseEnvelope([]byte(v.EnvelopeJSON))
			if err != nil {
				t.Fatalf("信封解析失败：%v", err)
			}
			plain, err := env.Open(v.Passphrase)
			if err != nil {
				t.Fatalf("解密失败：%v", err)
			}
			if string(plain) != v.Plaintext {
				t.Errorf("明文不符\n 得到 %q\n 期望 %q", plain, v.Plaintext)
			}
			if _, err := env.Open(v.Passphrase + "x"); err == nil {
				t.Error("错口令竟然解开了")
			}
			// Re-seal with the same salt+nonce must reproduce the client's bytes exactly: that
			// is what proves ct||tag layout and the PBKDF2 output, not just "it opened".
			resealed, err := SealWith(v.Passphrase, env.KDF.Salt, env.Nonce, plain, env.KDF.Rounds)
			if err != nil {
				t.Fatalf("重新封装失败：%v", err)
			}
			other, err := ParseEnvelope(resealed)
			if err != nil {
				t.Fatalf("重新封装的信封解析不了：%v", err)
			}
			if string(other.Ciphertext) != string(env.Ciphertext) {
				t.Errorf("重新封装的密文与端侧不一致：\n  %x\n  %x", other.Ciphertext, env.Ciphertext)
			}
		})
	}
}

func TestEnvelopeScreeningBeforeAnyKDF(t *testing.T) {
	good, err := json.Marshal(Envelope{
		FormatVersion: formatVersion,
		KDF:           KdfParams{Algorithm: kdfAlgorithm, Salt: make([]byte, 16), Rounds: 1200000, KeyLengthBytes: 32},
		Cipher:        cipherName,
		Nonce:         make([]byte, 12),
		Ciphertext:    make([]byte, 20),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvelope(good); err != nil {
		t.Fatalf("合法信封被判死：%v", err)
	}
	cases := map[string]Envelope{
		"版本不符":    {FormatVersion: 99},
		"轮次过高":    {FormatVersion: 1, KDF: KdfParams{Algorithm: kdfAlgorithm, Salt: make([]byte, 16), Rounds: maxRounds + 1, KeyLengthBytes: 32}},
		"轮次过低":    {FormatVersion: 1, KDF: KdfParams{Algorithm: kdfAlgorithm, Salt: make([]byte, 16), Rounds: 10, KeyLengthBytes: 32}},
		"salt 太短": {FormatVersion: 1, KDF: KdfParams{Algorithm: kdfAlgorithm, Salt: make([]byte, 4), Rounds: 1200000, KeyLengthBytes: 32}},
		"密钥长度不符":  {FormatVersion: 1, KDF: KdfParams{Algorithm: kdfAlgorithm, Salt: make([]byte, 16), Rounds: 1200000, KeyLengthBytes: 16}},
	}
	for name, bad := range cases {
		body, _ := json.Marshal(bad)
		if _, err := ParseEnvelope(body); err == nil {
			t.Errorf("%s：应该被拒却放过了", name)
		}
	}
}
