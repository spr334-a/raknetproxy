package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
)

// SecureHandshake provides forward-secret authenticated key agreement
// using a pre-shared key (PSK) and X25519 ECDH.
//
// Protocol:
//   Client -> Server: timestamp(8) || client_pub(32) || hmac(psk, timestamp || client_pub)
//   Server -> Client: server_pub(32) || hmac(shared, "server-confirm" || server_pub)
//
// The session key is derived from ECDH(client_priv, server_pub).
// PSK is only used to authenticate the handshake messages, not for traffic encryption.
// This provides forward secrecy: even if PSK is compromised later, past sessions remain secure.

const (
	// Maximum allowed clock skew between client and server (replay protection window)
	maxClockSkew = 30 * time.Second

	// HMAC tag size
	tagSize = 32
)

// ClientHandshake produces the client's first message and returns the
// ephemeral private key (kept by client for finalizing the session).
func ClientHandshakeInit(psk []byte) (msg []byte, privKey [32]byte, err error) {
	// Generate ephemeral X25519 key pair
	if _, err = io.ReadFull(rand.Reader, privKey[:]); err != nil {
		return nil, privKey, err
	}
	// Clamp private key per RFC 7748
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	pubKey, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, privKey, err
	}

	// Build message: timestamp(8) || pubkey(32) || hmac(32)
	msg = make([]byte, 8+32+tagSize)
	binary.BigEndian.PutUint64(msg[:8], uint64(time.Now().UnixMilli()))
	copy(msg[8:40], pubKey)

	mac := hmac.New(sha256.New, psk)
	mac.Write(msg[:40])
	copy(msg[40:], mac.Sum(nil))

	return msg, privKey, nil
}

// ServerHandshakeProcess validates the client's message and produces the server's response.
// Returns the shared session secret and the server's response message.
func ServerHandshakeProcess(psk, clientMsg []byte) (sessionKey []byte, response []byte, err error) {
	if len(clientMsg) != 8+32+tagSize {
		return nil, nil, errors.New("invalid handshake message length")
	}

	// Verify HMAC first (constant-time)
	mac := hmac.New(sha256.New, psk)
	mac.Write(clientMsg[:40])
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, clientMsg[40:]) {
		return nil, nil, errors.New("handshake authentication failed")
	}

	// Verify timestamp (replay protection)
	ts := int64(binary.BigEndian.Uint64(clientMsg[:8]))
	clientTime := time.UnixMilli(ts)
	skew := time.Since(clientTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > maxClockSkew {
		return nil, nil, errors.New("clock skew too large")
	}

	clientPub := clientMsg[8:40]

	// Generate server ephemeral key pair
	var serverPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, serverPriv[:]); err != nil {
		return nil, nil, err
	}
	serverPriv[0] &= 248
	serverPriv[31] &= 127
	serverPriv[31] |= 64

	serverPub, err := curve25519.X25519(serverPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	// Compute shared secret
	shared, err := curve25519.X25519(serverPriv[:], clientPub)
	if err != nil {
		return nil, nil, err
	}

	// Derive session key via HKDF, mixing in both pubkeys
	salt := make([]byte, 0, 64)
	salt = append(salt, clientPub...)
	salt = append(salt, serverPub...)
	sessionKey = hkdfExtract(shared, salt, "MCProxy-Session-v2", 32)

	// Build response: server_pub(32) || hmac(sessionKey, "server-confirm" || server_pub)
	response = make([]byte, 32+tagSize)
	copy(response[:32], serverPub)

	confirm := hmac.New(sha256.New, sessionKey)
	confirm.Write([]byte("server-confirm"))
	confirm.Write(serverPub)
	copy(response[32:], confirm.Sum(nil))

	return sessionKey, response, nil
}

// ClientHandshakeFinalize processes the server response and derives the session key.
func ClientHandshakeFinalize(clientPriv [32]byte, serverMsg []byte) (sessionKey []byte, err error) {
	if len(serverMsg) != 32+tagSize {
		return nil, errors.New("invalid server message length")
	}

	serverPub := serverMsg[:32]

	// Compute shared secret
	shared, err := curve25519.X25519(clientPriv[:], serverPub)
	if err != nil {
		return nil, err
	}

	// Need clientPub to mix into HKDF (regenerate from privkey)
	clientPub, err := curve25519.X25519(clientPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 0, 64)
	salt = append(salt, clientPub...)
	salt = append(salt, serverPub...)
	sessionKey = hkdfExtract(shared, salt, "MCProxy-Session-v2", 32)

	// Verify server confirmation
	confirm := hmac.New(sha256.New, sessionKey)
	confirm.Write([]byte("server-confirm"))
	confirm.Write(serverPub)
	expected := confirm.Sum(nil)
	if !hmac.Equal(expected, serverMsg[32:]) {
		return nil, errors.New("server confirmation failed")
	}

	return sessionKey, nil
}

func hkdfExtract(secret, salt []byte, info string, length int) []byte {
	return HKDFExpand(append(append([]byte{}, salt...), secret...), info, length)
}
