// Package main: Yank sync service.
//
// The server never sees plaintext. It stores opaque envelopes (see syncd/SPEC.md) and has no
// key material: the sync passphrase stays on each device and in the browser.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// Wire constants. These must match PassphraseCipher in the Swift client exactly; the interop
// vectors in testdata/envelope-vectors.json are what keeps all three sides honest.
const (
	formatVersion   = 1
	formatVersionV2 = 2 // SPEC §3 (2026-10-06 拍板) 的上传体形状
	cipherName      = "aes-256-gcm"
	kdfAlgorithm    = "pbkdf2-sha512-cc"
	keyLengthBytes  = 32
	nonceLength     = 12
	tagLength       = 16
	minRounds       = 1000
	maxRounds       = 5_000_000
	minSaltBytes    = 8
	maxSaltBytes    = 128
	maxPayloadBytes = 8 * 1024 * 1024
)

// KdfParams is the salt + cost that travels with every envelope, so a device that calibrated a
// different round count still decrypts on a slower peer.
type KdfParams struct {
	Algorithm      string `json:"algorithm"`
	Salt           []byte `json:"salt"`
	Rounds         uint32 `json:"rounds"`
	KeyLengthBytes int    `json:"keyLengthBytes"`
}

// Envelope is the JSON document the client PUTs. Ciphertext carries ct||tag, the usual
// "combined" form minus the leading nonce.
type Envelope struct {
	FormatVersion int       `json:"formatVersion"`
	KDF           KdfParams `json:"kdf"`
	Cipher        string    `json:"cipher"`
	Nonce         []byte    `json:"nonce"`
	Ciphertext    []byte    `json:"ciphertext"`
	CreatedAt     time.Time `json:"createdAt"`
}

var (
	errEnvelopeShape   = errors.New("信封格式不合法")
	errEnvelopeVersion = errors.New("不支持的信封版本")
	errUploadShape     = errors.New("上传体形状不合法")
	errAuthFailed      = errors.New("口令错误或数据被篡改")
)

// UploadV2 is the §3 upload body header — the only part the server is allowed to look at.
// Each row's `secret` and the ledger `meta` stay opaque strings here (inventory.go owns their
// key screening); the server never derives from KDF because it holds no passphrase and will not
// parse a single byte of the row ciphers.
type UploadV2 struct {
	FormatVersion int       `json:"formatVersion"`
	KDF           KdfParams `json:"kdf"`
	Cipher        string    `json:"cipher"`
	CreatedAt     time.Time `json:"createdAt"`
}

// IsUploadV2 is the cheap peek that routes a request body to one of the three ingest paths
// (channel envelope / v2 upload / v1 envelope-with-arrays). formatVersion 2 with no `layer` is
// §3's shape; the plaintext inside a channel envelope answers the same peek, so the opened
// layer runs through the exact same ingest code as the unencrypted case (SPEC §5).
func IsUploadV2(body []byte) bool {
	if len(body) == 0 || body[0] != '{' {
		return false
	}
	var head struct {
		FormatVersion int    `json:"formatVersion"`
		Layer         string `json:"layer"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return false
	}
	return head.FormatVersion == formatVersionV2 && head.Layer == ""
}

// ParseUploadV2 screens the top-level §2 parameters before anything else touches the body.
// Same checks and same order as ParseEnvelope, minus nonce/ciphertext: in v2 the nonce rides
// inside each row's opaque `secret`, and the server is not allowed to open any of them.
func ParseUploadV2(body []byte) (*UploadV2, error) {
	if len(body) == 0 || len(body) > maxPayloadBytes+64*1024 {
		return nil, errUploadShape
	}
	var up UploadV2
	if err := json.Unmarshal(body, &up); err != nil {
		return nil, errUploadShape
	}
	switch {
	case up.FormatVersion != formatVersionV2:
		return nil, errUploadShape
	case up.Cipher != cipherName:
		return nil, errUploadShape
	case up.KDF.Algorithm != kdfAlgorithm:
		return nil, errUploadShape
	case up.KDF.KeyLengthBytes != keyLengthBytes:
		return nil, errUploadShape
	case up.KDF.Rounds < minRounds || up.KDF.Rounds > maxRounds:
		return nil, errUploadShape
	case len(up.KDF.Salt) < minSaltBytes || len(up.KDF.Salt) > maxSaltBytes:
		return nil, errUploadShape
	}
	return &up, nil
}

// ParseEnvelope screens structure and cost BEFORE any key derivation, so a hostile body cannot
// make the server burn minutes on a 5-billion-round PBKDF2.
func ParseEnvelope(body []byte) (*Envelope, error) {
	if len(body) == 0 || len(body) > maxPayloadBytes+64*1024 {
		return nil, errEnvelopeShape
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, errEnvelopeShape
	}
	switch {
	case env.FormatVersion != formatVersion:
		return nil, errEnvelopeVersion
	case env.Cipher != cipherName:
		return nil, errEnvelopeShape
	case env.KDF.Algorithm != kdfAlgorithm:
		return nil, errEnvelopeShape
	case env.KDF.KeyLengthBytes != keyLengthBytes:
		return nil, errEnvelopeShape
	case env.KDF.Rounds < minRounds || env.KDF.Rounds > maxRounds:
		return nil, errEnvelopeShape
	case len(env.KDF.Salt) < minSaltBytes || len(env.KDF.Salt) > maxSaltBytes:
		return nil, errEnvelopeShape
	case len(env.Nonce) != nonceLength:
		return nil, errEnvelopeShape
	case len(env.Ciphertext) < tagLength:
		return nil, errEnvelopeShape
	}
	return &env, nil
}

func deriveKey(passphrase string, env *Envelope) []byte {
	return pbkdf2.Key([]byte(passphrase), env.KDF.Salt, int(env.KDF.Rounds),
		env.KDF.KeyLengthBytes, sha512.New)
}

// Open decrypts. It is only used by tests and by the browser-side tooling: the deployed server
// never derives a key, because it is not given the passphrase.
func (e *Envelope) Open(passphrase string) ([]byte, error) {
	aead, err := newAEAD(deriveKey(passphrase, e))
	if err != nil {
		return nil, err
	}
	// Go's GCM takes ciphertext||tag as one buffer (the trailing argument is AAD, not the tag,
	// which is exactly how the Swift side stores it), so hand the whole field over.
	plain, err := aead.Open(nil, e.Nonce, e.Ciphertext, nil)
	if err != nil {
		// One error for every failure mode: no wrong-password vs corrupt-ciphertext oracle.
		return nil, errAuthFailed
	}
	return plain, nil
}

// SealWith derives and encrypts with a caller-supplied nonce. Production clients use fresh
// randomness; this exists so a test can prove byte-for-byte agreement with another
// implementation rather than merely "it decrypts something".
func SealWith(passphrase string, salt, nonce, plaintext []byte, rounds uint32) ([]byte, error) {
	env := Envelope{
		FormatVersion: formatVersion,
		KDF: KdfParams{Algorithm: kdfAlgorithm, Salt: salt, Rounds: rounds,
			KeyLengthBytes: keyLengthBytes},
		Cipher:    cipherName,
		Nonce:     nonce,
		CreatedAt: time.Now().UTC(),
	}
	aead, err := newAEAD(deriveKey(passphrase, &env))
	if err != nil {
		return nil, err
	}
	env.Ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return json.Marshal(&env)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errEnvelopeShape, err)
	}
	return cipher.NewGCM(block)
}
