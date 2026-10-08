package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password hashing parameters. argon2id is the current default choice; these costs put a
// verification at roughly 50-100 ms on a laptop, which is deliberate friction against an
// attacker who copies the database and tries to crack it offline.
const (
	argonTime    = 2
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

var (
	ErrWeakPassword  = errors.New("口令太弱")
	ErrBadCredential = errors.New("账号或口令不正确")
)

func randomBytes(n int) []byte {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// A machine without a working CSPRNG must not run a credential store.
		panic("no entropy available: " + err.Error())
	}
	return buf
}

func randomID(n int) string { return hex.EncodeToString(randomBytes(n)) }

// sha256Hex is used for lookup keys (tokens, pair codes): the database holds something that is
// useless without the value it stands for.
func sha256Hex(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func HashPassword(password string) (string, error) {
	if len([]rune(password)) < 10 {
		return "", ErrWeakPassword
	}
	salt := randomBytes(saltLen)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword parses the stored form and compares in constant time.
func VerifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || parts[1] != "v=19" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewPairCode returns a human-typeable code plus the hash to store. Six characters out of a
// 32-symbol alphabet (no I/O/0/1, this gets read aloud) is ~1.07e9 combinations; the code lives
// five minutes and is consumed the moment an exchange succeeds, so the guessing budget inside one
// window is bounded by the per-IP exchange limiter (10/min), not by the window itself.
func NewPairCode() (display string, hash string) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no I/O/0/1, this gets read aloud
	raw := randomBytes(6)
	var b strings.Builder
	for i, x := range raw {
		if i == 3 {
			b.WriteByte('-')
		}
		b.WriteByte(alphabet[int(x)%len(alphabet)])
	}
	display = b.String()
	// Hash the *normalised* form, because the device sends back what the user typed and
	// NormalizePairCode strips the separator: hashing the dashed display would never match.
	return display, sha256Hex(NormalizePairCode(display))
}

// NormalizePairCode makes entry forgiving without weakening the lookup: only case and separators
// are ignored, never characters inside the code.
func NormalizePairCode(input string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToUpper(input))
}
