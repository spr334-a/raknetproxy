package socks5

import (
	"bytes"
	"testing"
)

func TestUDPDatagramRoundTrip(t *testing.T) {
	payload := []byte("hello over udp")
	packet := BuildUDPDatagram("example.com", 443, payload)

	addr, port, got, err := ParseUDPDatagram(packet)
	if err != nil {
		t.Fatalf("parse UDP datagram: %v", err)
	}
	if addr != "example.com" {
		t.Fatalf("addr = %q, want example.com", addr)
	}
	if port != 443 {
		t.Fatalf("port = %d, want 443", port)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch")
	}
}
