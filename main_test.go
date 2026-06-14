package main

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/user/mcproxy/pkg/raknet"
)

func TestMultiplexedUDPAssociationsShareServerSession(t *testing.T) {
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echoConn.WriteToUDP(buf[:n], addr)
		}
	}()

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	s := &server{
		conn:     serverConn,
		password: "test-password",
		info:     raknet.DefaultServerInfo(),
		sessions: make(map[string]*clientSession),
		pending:  make(map[string]*pendingSession),
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			s.handlePacket(packet, addr)
		}
	}()

	remoteAddr := serverConn.LocalAddr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := raknet.ClientOpenConnection(clientConn, remoteAddr); err != nil {
		clientConn.Close()
		t.Fatal(err)
	}
	sessionKey, err := raknet.ClientUDPHandshake(clientConn, remoteAddr, "test-password")
	if err != nil {
		clientConn.Close()
		t.Fatal(err)
	}
	tunnel, err := raknet.NewUDPTunnelPreConnected(clientConn, remoteAddr, sessionKey, true)
	if err != nil {
		clientConn.Close()
		t.Fatal(err)
	}
	defer tunnel.Close()

	var readWG sync.WaitGroup
	readWG.Add(1)
	go func() {
		defer readWG.Done()
		buf := make([]byte, 2048)
		for {
			n, err := clientConn.Read(buf)
			if err != nil {
				return
			}
			tunnel.HandlePacket(append([]byte(nil), buf[:n]...))
		}
	}()

	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)
	payloads := map[uint32][]byte{
		101: []byte("association-one"),
		202: []byte("association-two"),
	}
	for associationID, payload := range payloads {
		if err := tunnel.SendDatagramV2(associationID, echoAddr.IP.String(), uint16(echoAddr.Port), payload); err != nil {
			t.Fatal(err)
		}
	}

	replies := make(map[uint32][]byte)
	deadline := time.Now().Add(3 * time.Second)
	for len(replies) < len(payloads) && time.Now().Before(deadline) {
		frameType, data, err := tunnel.Recv(time.Until(deadline))
		if err != nil {
			t.Fatal(err)
		}
		if frameType != raknet.TunnelFrameDatagramV2 {
			continue
		}
		associationID, _, _, payload, err := raknet.ParseDatagramV2(data)
		if err != nil {
			t.Fatal(err)
		}
		replies[associationID] = append([]byte(nil), payload...)
	}
	for associationID, expected := range payloads {
		if !bytes.Equal(replies[associationID], expected) {
			t.Fatalf("association %d reply = %q, want %q", associationID, replies[associationID], expected)
		}
	}

	s.mu.RLock()
	sessionCount := len(s.sessions)
	s.mu.RUnlock()
	if sessionCount != 1 {
		t.Fatalf("server RakNet sessions = %d, want 1", sessionCount)
	}

	for associationID := range payloads {
		if err := tunnel.SendAssociationClose(associationID); err != nil {
			t.Fatal(err)
		}
	}
	tunnel.SendClose()
	tunnel.Close()
	readWG.Wait()
}

func TestTCPOverRakNetRelayTransfersBeyondInitialWindow(t *testing.T) {
	echoListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go func() {
		conn, acceptErr := echoListener.AcceptTCP()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	s := &server{
		conn:     serverConn,
		password: "test-password",
		info:     raknet.DefaultServerInfo(),
		sessions: make(map[string]*clientSession),
		pending:  make(map[string]*pendingSession),
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, readErr := serverConn.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			s.handlePacket(append([]byte(nil), buf[:n]...), addr)
		}
	}()

	remoteAddr := serverConn.LocalAddr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := raknet.ClientOpenConnection(clientConn, remoteAddr); err != nil {
		clientConn.Close()
		t.Fatal(err)
	}
	sessionKey, err := raknet.ClientUDPHandshake(clientConn, remoteAddr, "test-password")
	if err != nil {
		clientConn.Close()
		t.Fatal(err)
	}
	tunnel, err := raknet.NewUDPTunnelPreConnected(clientConn, remoteAddr, sessionKey, true)
	if err != nil {
		clientConn.Close()
		t.Fatal(err)
	}
	defer tunnel.Close()

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 2048)
		for {
			n, readErr := clientConn.Read(buf)
			if readErr != nil {
				return
			}
			tunnel.HandlePacket(append([]byte(nil), buf[:n]...))
		}
	}()

	echoPort := uint16(echoListener.Addr().(*net.TCPAddr).Port)
	if err := tunnel.SendConnectRequest("127.0.0.1", echoPort); err != nil {
		t.Fatal(err)
	}
	frameType, response, err := tunnel.Recv(3 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if frameType != raknet.TunnelFrameConnResp || len(response) != 1 || response[0] != 0 {
		t.Fatalf("connect response = type 0x%02x payload %v", frameType, response)
	}

	payload := bytes.Repeat([]byte("ordered-raknet-data-"), 4096)
	if err := tunnel.SendData(payload); err != nil {
		t.Fatal(err)
	}

	var echoed []byte
	deadline := time.Now().Add(5 * time.Second)
	for len(echoed) < len(payload) {
		frameType, data, recvErr := tunnel.Recv(time.Until(deadline))
		if recvErr != nil {
			t.Fatal(recvErr)
		}
		if frameType == raknet.TunnelFrameData {
			echoed = append(echoed, data...)
		}
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echoed data differs: got %d bytes, want %d", len(echoed), len(payload))
	}

	_ = tunnel.SendClose()
	tunnel.Close()
	<-readDone
}
