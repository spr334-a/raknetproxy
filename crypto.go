package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = 32
	NonceSize = 12

	// Argon2id parameters - tuned for VPS stability.
	// 16 MB keeps offline brute-force expensive while avoiding OOM when
	// many scanners/probes hit the public Minecraft port at once.
	argonTime    = 3
	argonMemory  = 16 * 1024 // 16 MB
	argonThreads = 2
	argonKeyLen  = 32

	// Salt for password-based key derivation (constant per-protocol).
	// The actual session key is derived via ECDH, this is only for the
	// password-authentication step.
	pskSalt = "MCProxy-PSK-Salt-v2"
)

type Config struct {
	Key []byte
}

var (
	pskCache sync.Map
	pskMu    sync.Mutex
)

// DerivePSK derives a pre-shared key from the password using Argon2id.
// This is used for authentication, not for encrypting traffic.
func DerivePSK(password string) []byte {
	if cached, ok := pskCache.Load(password); ok {
		key := cached.([]byte)
		out := make([]byte, len(key))
		copy(out, key)
		return out
	}

	pskMu.Lock()
	defer pskMu.Unlock()
	if cached, ok := pskCache.Load(password); ok {
		key := cached.([]byte)
		out := make([]byte, len(key))
		copy(out, key)
		return out
	}

	key := argon2.IDKey(
		[]byte(password),
		[]byte(pskSalt),
		argonTime,
		argonMemory,
		argonThreads,
		argonKeyLen,
	)
	actual, _ := pskCache.LoadOrStore(password, key)
	stored := actual.([]byte)
	out := make([]byte, len(stored))
	copy(out, stored)
	return out
}

// DeriveKey is the legacy key derivation (kept for backward compat in non-tunnel paths).
// Do NOT use for new code - use DerivePSK + ECDH instead.
func DeriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// HKDFExpand derives subkeys from a master secret using HKDF-SHA256.
func HKDFExpand(secret []byte, info string, length int) []byte {
	out, _ := hkdf.Key(sha256.New, secret, nil, info, length)
	return out
}

func NewAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func NewChaCha20(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// CounterAEAD wraps an AEAD with a counter-based nonce, eliminating
// random-nonce collision risk. Send and recv directions use separate counters.
type CounterAEAD struct {
	aead     cipher.AEAD
	sendCtr  uint64
	recvCtr  uint64
	sendSalt [4]byte // first 4 bytes of nonce, derived from key
	recvSalt [4]byte
}

func NewCounterAEAD(aead cipher.AEAD, isClient bool) *CounterAEAD {
	c := &CounterAEAD{aead: aead}
	// Differentiate send/recv salt so client and server use different nonce spaces
	if isClient {
		c.sendSalt = [4]byte{'C', 'L', 'I', 'S'}
		c.recvSalt = [4]byte{'S', 'R', 'V', 'S'}
	} else {
		c.sendSalt = [4]byte{'S', 'R', 'V', 'S'}
		c.recvSalt = [4]byte{'C', 'L', 'I', 'S'}
	}
	return c
}

// Seal encrypts using counter-based nonce.
func (c *CounterAEAD) Seal(plaintext []byte) ([]byte, error) {
	ctr := atomic.AddUint64(&c.sendCtr, 1) - 1
	nonce := make([]byte, c.aead.NonceSize())
	copy(nonce[:4], c.sendSalt[:])
	binary.BigEndian.PutUint64(nonce[4:12], ctr)

	// Output: 8-byte counter + ciphertext
	out := make([]byte, 8+len(plaintext)+c.aead.Overhead())
	binary.BigEndian.PutUint64(out[:8], ctr)
	c.aead.Seal(out[8:8], nonce, plaintext, nil)
	return out, nil
}

// Open decrypts data, verifying the counter is within the replay window.
func (c *CounterAEAD) Open(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 8+c.aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	ctr := binary.BigEndian.Uint64(ciphertext[:8])

	// Reject counters older than window (simple sliding window)
	currentRecv := atomic.LoadUint64(&c.recvCtr)
	const replayWindow = 1024
	if currentRecv > replayWindow && ctr < currentRecv-replayWindow {
		return nil, errors.New("counter too old (possible replay)")
	}

	nonce := make([]byte, c.aead.NonceSize())
	copy(nonce[:4], c.recvSalt[:])
	binary.BigEndian.PutUint64(nonce[4:12], ctr)

	plaintext, err := c.aead.Open(nil, nonce, ciphertext[8:], nil)
	if err != nil {
		return nil, err
	}

	// Update high-water mark
	for {
		old := atomic.LoadUint64(&c.recvCtr)
		if ctr <= old {
			break
		}
		if atomic.CompareAndSwapUint64(&c.recvCtr, old, ctr) {
			break
		}
	}
	return plaintext, nil
}

// Encrypt is the legacy random-nonce encryption (kept for compat).
// Prefer CounterAEAD for new code.
func Encrypt(aead cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt.
func Decrypt(aead cipher.AEAD, ciphertext []byte) ([]byte, error) {
	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:nonceSize]
	return aead.Open(nil, nonce, ciphertext[nonceSize:], nil)
}
