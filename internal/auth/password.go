package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters required by the project specification. They are encoded
// in the PHC string, so hashes produced by older/other parameter sets can still
// be verified as long as parseArgon2ID accepts them.
const (
	argonMemoryKiB   = 64 * 1024 // 64 MiB
	argonIterations  = 3
	argonParallelism = 2
	argonSaltLength  = 16 // bytes
	argonKeyLength   = 32 // bytes
)

// Bounds applied when parsing a PHC string. They protect the login path from a
// corrupted or hostile hash that requests an absurd amount of memory/CPU.
const (
	minArgonMemoryKiB   = 8
	maxArgonMemoryKiB   = 1024 * 1024 // 1 GiB
	maxArgonIterations  = 32
	maxArgonParallelism = 64
	minArgonSaltLength  = 8
	maxArgonSaltLength  = 1024
	minArgonKeyLength   = 16
	maxArgonKeyLength   = 1024
	maxPasswordLength   = 1024
	maxGeneratedLength  = 1024
)

// HashPassword hashes password with argon2id (m=64MiB, t=3, p=2, 16-byte salt,
// 32-byte derived key) and returns a PHC encoded string:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 hash>
//
// The returned value is safe to persist; it never contains the plain password.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("密码不能为空")
	}
	if len(password) > maxPasswordLength {
		return "", fmt.Errorf("密码过长（最多 %d 字节）", maxPasswordLength)
	}
	salt, err := randomBytes(argonSaltLength)
	if err != nil {
		return "", fmt.Errorf("生成密码盐失败: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemoryKiB, argonParallelism, argonKeyLength)
	return encodeArgon2ID(salt, key, argonMemoryKiB, argonIterations, argonParallelism), nil
}

// encodeArgon2ID renders a PHC argon2id string. The base64 alphabet is unpadded
// standard base64, as mandated by the PHC specification.
func encodeArgon2ID(salt, key []byte, memory, iterations uint32, parallelism uint8) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// argon2Params is a decoded argon2id PHC string.
type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

// parseArgon2ID strictly decodes and validates a PHC encoded argon2id hash. It
// never panics: any malformed input becomes an error.
func parseArgon2ID(encoded string) (*argon2Params, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, fmt.Errorf("不支持的密码哈希格式（期望 argon2id PHC 字符串）")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, fmt.Errorf("argon2 哈希版本缺失或非法: %w", err)
	}
	if version != argon2.Version {
		return nil, fmt.Errorf("不支持的 argon2 版本 %d（期望 %d）", version, argon2.Version)
	}
	memory, iterations, parallelism, err := parseArgon2Descriptor(parts[3])
	if err != nil {
		return nil, err
	}
	salt, err := decodePHCBase64(parts[4], "盐")
	if err != nil {
		return nil, err
	}
	key, err := decodePHCBase64(parts[5], "哈希")
	if err != nil {
		return nil, err
	}
	if len(salt) < minArgonSaltLength || len(salt) > maxArgonSaltLength {
		return nil, fmt.Errorf("argon2 盐长度非法（%d 字节）", len(salt))
	}
	if len(key) < minArgonKeyLength || len(key) > maxArgonKeyLength {
		return nil, fmt.Errorf("argon2 哈希长度非法（%d 字节）", len(key))
	}
	return &argon2Params{memory: memory, iterations: iterations, parallelism: parallelism, salt: salt, key: key}, nil
}

// parseArgon2Descriptor parses the "m=<int>,t=<int>,p=<int>" PHC section.
func parseArgon2Descriptor(raw string) (memory, iterations uint32, parallelism uint8, err error) {
	fields := strings.Split(raw, ",")
	if len(fields) != 3 {
		return 0, 0, 0, fmt.Errorf("argon2 参数段非法（期望 m=,t=,p=）")
	}
	m, err := parseUintField(fields[0], "m=", 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("argon2 内存参数非法: %w", err)
	}
	t, err := parseUintField(fields[1], "t=", 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("argon2 迭代参数非法: %w", err)
	}
	p, err := parseUintField(fields[2], "p=", 8)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("argon2 并行度参数非法: %w", err)
	}
	if m < minArgonMemoryKiB || m > maxArgonMemoryKiB {
		return 0, 0, 0, fmt.Errorf("argon2 内存参数超出允许范围（%d KiB）", m)
	}
	if t < 1 || t > maxArgonIterations {
		return 0, 0, 0, fmt.Errorf("argon2 迭代参数超出允许范围（%d）", t)
	}
	if p < 1 || p > maxArgonParallelism {
		return 0, 0, 0, fmt.Errorf("argon2 并行度参数超出允许范围（%d）", p)
	}
	return uint32(m), uint32(t), uint8(p), nil
}

func parseUintField(s, prefix string, bitSize int) (uint64, error) {
	if !strings.HasPrefix(s, prefix) {
		return 0, fmt.Errorf("缺少 %q 前缀", prefix)
	}
	return strconv.ParseUint(strings.TrimPrefix(s, prefix), 10, bitSize)
}

func decodePHCBase64(s, what string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("argon2 %s不是合法的 base64: %w", what, err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("argon2 %s为空", what)
	}
	return b, nil
}

// VerifyPassword reports whether password matches encodedHash. It supports
// argon2id PHC strings and bcrypt modular crypt hashes (so administrators can
// migrate from a bcrypt configuration). A malformed encodedHash returns an
// error; a well formed but non-matching hash returns (false, nil).
func VerifyPassword(encodedHash, password string) (bool, error) {
	if encodedHash == "" {
		return false, fmt.Errorf("密码哈希为空")
	}
	if len(password) > maxPasswordLength {
		// No hash produced by HashPassword can match an over-long input.
		return false, nil
	}
	switch {
	case strings.HasPrefix(encodedHash, "$argon2id$"):
		params, err := parseArgon2ID(encodedHash)
		if err != nil {
			return false, err
		}
		sum := argon2.IDKey([]byte(password), params.salt, params.iterations, params.memory, params.parallelism, uint32(len(params.key)))
		return subtle.ConstantTimeCompare(sum, params.key) == 1, nil
	case strings.HasPrefix(encodedHash, "$2"):
		err := bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return false, nil
		case errors.Is(err, bcrypt.ErrPasswordTooLong):
			return false, nil
		default:
			return false, fmt.Errorf("bcrypt 校验失败: %w", err)
		}
	default:
		return false, fmt.Errorf("不支持的密码哈希格式（仅支持 argon2id 与 bcrypt）")
	}
}

// PasswordHashSupported reports whether hash looks like a hash this package can
// verify. It is a cheap syntactic check: neither hashing nor memory allocation
// proportional to the encoded parameters happens here.
func PasswordHashSupported(hash string) bool {
	switch {
	case strings.HasPrefix(hash, "$argon2id$"):
		_, err := parseArgon2ID(hash)
		return err == nil
	case strings.HasPrefix(hash, "$2"):
		// bcrypt.Cost parses the version/cost/salt/hash fields and validates the
		// cost range without computing the hash.
		_, err := bcrypt.Cost([]byte(hash))
		return err == nil
	default:
		return false
	}
}

// GeneratePassword returns a cryptographically random URL-safe password of
// exactly n characters from crypto/rand.
func GeneratePassword(n int) (string, error) {
	if n <= 0 || n > maxGeneratedLength {
		return "", fmt.Errorf("密码长度必须在 1-%d 之间", maxGeneratedLength)
	}
	// 6 bits of entropy per base64 character.
	raw, err := randomBytes((n*6 + 7) / 8)
	if err != nil {
		return "", fmt.Errorf("生成随机密码失败: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if len(encoded) < n {
		return "", fmt.Errorf("生成随机密码失败：随机长度不足")
	}
	return encoded[:n], nil
}

// randomBytes reads n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("随机字节长度必须为正数")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("读取随机数失败: %w", err)
	}
	return b, nil
}

// randomUsername returns a bootstrap username such as "np-a1b2c3".
func randomUsername() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	raw, err := randomBytes(6)
	if err != nil {
		return "", fmt.Errorf("生成随机用户名失败: %w", err)
	}
	var b strings.Builder
	b.WriteString("np-")
	for _, v := range raw {
		b.WriteByte(alphabet[int(v)%len(alphabet)])
	}
	return b.String(), nil
}
