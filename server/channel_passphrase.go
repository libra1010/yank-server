package main

// 通道密钥这一层原来要两端各粘一把 32 字节的 hex/base64（64 个字符），既难读又难核对。
// 现在两端各填**一句自己定的口令**：口令经 PBKDF2-HMAC-SHA512 派生出那 32 字节，salt 跟着
// 信封走，所以服务端不用问客户端用了什么随机数就能算出同一把。
//
// 派生参数（salt 16 字节、轮数 21 万、密钥 32 字节）都写死在这一版里：这一层从来不是端到端
// 那道门，SSH 口令与私钥仍在内层口令信封里，服务端解开的只有主机清单那一片。

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	channelKdfPassphrase = "pbkdf2-sha512-cc"
	// rounds 是写死的常量，而且服务端只接受这一个值：派生是这一层唯一花钱的地方，
	// 让信封自带任意 rounds 等于让任何能连上端口的人决定服务端要算多久。
	channelPassphraseRounds = 210_000
	channelSaltBytes        = 16
	// 下限挡的是"空口令＝谁都能解开外层"，不是离线爆破：这一层的口令原样存在服务端库里。
	channelMinPassphraseChars = 8
	// 指纹只是"两端填的是不是同一句"的肉眼核对。带域前缀，免得和别的系统里同一句话撞值。
	channelFingerprintDomain = "yank-channel-v1|"
)

var errChannelPassphrase = errors.New("通道密钥太短：至少 8 个字符")

// CheckChannelPassphrase 是两端保存前都要过的同一道闸。
func CheckChannelPassphrase(text string) error {
	if len([]rune(strings.TrimSpace(text))) < channelMinPassphraseChars {
		return errChannelPassphrase
	}
	return nil
}

// ChannelFingerprint 是 SHA-256(域前缀 + 口令) 的前 3 字节，大写十六进制。
// Swift 端 ChannelCipher.fingerprint 是同一套字节口径，互操作向量按同一句话比。
func ChannelFingerprint(text string) string {
	sum := sha256.Sum256([]byte(channelFingerprintDomain + strings.TrimSpace(text)))
	return strings.ToUpper(hex.EncodeToString(sum[:3]))
}

// deriveChannelKey 是口令变成密钥的**唯一**一处。
func deriveChannelKey(passphrase string, salt []byte, rounds uint32) ([]byte, error) {
	if rounds != channelPassphraseRounds {
		return nil, fmt.Errorf("%w：轮数 %d 不是本版本认的 %d",
			errChannelShape, rounds, channelPassphraseRounds)
	}
	if len(salt) != channelSaltBytes {
		return nil, errChannelShape
	}
	return pbkdf2.Key([]byte(passphrase), salt, int(rounds), channelKeyBytes, sha512.New), nil
}

// SealChannelPassphrase 造一个派生格式的信封体。salt 与 iv 由调用方给，于是互操作向量能
// 逐字节复现，而不是"能解开就算对"。
func SealChannelPassphrase(passphrase string, salt, iv, plaintext []byte) ([]byte, error) {
	key, err := deriveChannelKey(passphrase, salt, channelPassphraseRounds)
	if err != nil {
		return nil, err
	}
	if len(iv) != nonceLength {
		return nil, errChannelShape
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, errChannelShape
	}
	env := ChannelEnvelope{
		FormatVersion: formatVersion,
		Layer:         channelLayer,
		Cipher:        channelCipherName,
		KDF: ChannelKdf{Algorithm: channelKdfPassphrase, Salt: salt,
			Rounds: channelPassphraseRounds, KeyLengthBytes: channelKeyBytes},
		IV:         iv,
		Ciphertext: aead.Seal(nil, iv, plaintext, nil),
	}
	return json.Marshal(&env)
}

// SealChannel 是"客户端该怎么发"的样子：每次封装都换一把新 salt 与新 iv，于是同一份清单两次
// 上传的字节必然不同（这既是随机性的要求，也是 §5 的互操作口径）。
func SealChannel(passphrase string, plaintext []byte) ([]byte, error) {
	return SealChannelPassphrase(passphrase, randomBytes(channelSaltBytes), randomBytes(nonceLength), plaintext)
}
