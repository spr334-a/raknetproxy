package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/user/mcproxy/pkg/raknet"
)

var (
	listenAddr  = flag.String("listen", "0.0.0.0:19132", "UDP listen address")
	password    = flag.String("password", "", "Shared secret")
	maxSessions = flag.Int("max-sessions", 256, "Maximum active and pending UDP sessions")
)

type clientSession struct {
	tunnel    *raknet.UDPTunnel
	lastSeen  time.Time
	authInit  []byte
	authReply []byte
}

type pendingSession struct {
	lastSeen     time.Time
	processing   bool
	clientID     int64
	requestTime  int64
	acceptedTime int64
	authInit     []byte
	authReply    []byte
	session      *clientSession
}

type server struct {
	conn     *net.UDPConn
	password string
	info     *raknet.ServerInfo
	sessions map[string]*clientSession
	pending  map[string]*pendingSession
	mu       sync.RWMutex
}

func main() {
	flag.Parse()
	if *password == "" {
		log.Fatal("Usage: mcproxy-udp-server -password <secret>")
	}

	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		log.Fatalf("Resolve address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	defer conn.Close()

	log.Printf("MCProxy UDP server listening on %s", *listenAddr)
	log.Printf("Disguised as Bedrock Edition server (RakNet)")

	s := &server{
		conn:     conn,
		password: *password,
		info:     raknet.DefaultServerInfo(),
		sessions: make(map[string]*clientSession),
		pending:  make(map[string]*pendingSession),
	}

	// Cleanup stale sessions
	go s.cleanupLoop()

	s.readLoop()
}

func (s *server) readLoop() {
	buf := make([]byte, 2048)
	for {
		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go s.handlePacket(data, remoteAddr)
	}
}

func (s *server) handlePacket(data []byte, addr *net.UDPAddr) {
	if len(data) < 1 {
		return
	}

	key := addr.String()

	switch {
	case data[0] == raknet.IDUnconnectedPing:
		s.handlePing(data, addr)

	case data[0] == raknet.IDOpenConnectionRequest1:
		s.handleOpenConn1(data, addr)

	case data[0] == raknet.IDOpenConnectionRequest2:
		s.handleOpenConn2(data, addr)

	case data[0] >= 0x80 && data[0] <= 0x8D:
		if frame, ok := raknet.ParseFrameSetPayload(data); ok && !frame.Split && len(frame.Payload) > 0 {
			switch frame.Payload[0] {
			case raknet.IDConnectionRequest:
				_, _, authInit, valid := raknet.ParseConnectionRequest(frame.Payload)
				if valid && len(authInit) == 72 {
					if _, err := s.conn.WriteToUDP(raknet.BuildAck(frame.SequenceNumber), addr); err != nil {
						log.Printf("[%s] RakNet connection request ACK send failed: %v", addr, err)
						return
					}
					s.handleConnectionRequest(frame.Payload, addr)
					return
				}
			case raknet.IDNewIncomingConnection:
				if _, _, valid := raknet.ParseNewIncomingConnection(frame.Payload); valid &&
					s.handleNewIncomingConnection(frame.Payload, addr) {
					if _, err := s.conn.WriteToUDP(raknet.BuildAck(frame.SequenceNumber), addr); err != nil {
						log.Printf("[%s] RakNet new incoming ACK send failed: %v", addr, err)
					}
					return
				}
			}
		}

		// Encrypted frame set - route to session
		s.mu.Lock()
		session, exists := s.sessions[key]
		if exists {
			session.lastSeen = time.Now()
		}
		s.mu.Unlock()

		if !exists {
			return
		}
		session.tunnel.HandlePacket(data)

	case data[0] == raknet.IDAck || data[0] == raknet.IDNack:
		// ACK/NACK
		s.mu.Lock()
		session, exists := s.sessions[key]
		if exists {
			session.lastSeen = time.Now()
		}
		s.mu.Unlock()
		if exists {
			session.tunnel.HandlePacket(data)
		}
	}
}

func (s *server) handleConnectionRequest(data []byte, addr *net.UDPAddr) {
	clientID, requestTime, authInit, ok := raknet.ParseConnectionRequest(data)
	if !ok {
		return
	}

	key := addr.String()
	s.mu.Lock()
	if session := s.sessions[key]; session != nil {
		if bytes.Equal(session.authInit, authInit) {
			reply := append([]byte(nil), session.authReply...)
			session.lastSeen = time.Now()
			s.mu.Unlock()
			if _, err := s.conn.WriteToUDP(reply, addr); err != nil {
				log.Printf("[%s] Connection accepted resend failed: %v", addr, err)
			}
			return
		}
		s.mu.Unlock()
		return
	}

	pending := s.pending[key]
	if pending == nil {
		s.mu.Unlock()
		return
	}
	if bytes.Equal(pending.authInit, authInit) && len(pending.authReply) > 0 {
		reply := append([]byte(nil), pending.authReply...)
		pending.lastSeen = time.Now()
		s.mu.Unlock()
		if _, err := s.conn.WriteToUDP(reply, addr); err != nil {
			log.Printf("[%s] Connection accepted resend failed: %v", addr, err)
		}
		return
	}
	if pending.processing {
		s.mu.Unlock()
		return
	}
	pending.processing = true
	pending.lastSeen = time.Now()
	s.mu.Unlock()

	sessionKey, response, err := raknet.ServerUDPHandshakeReceive(s.password, authInit)
	if err != nil {
		log.Printf("[%s] ECDH handshake failed: %v", addr, err)
		s.mu.Lock()
		if s.pending[key] == pending {
			delete(s.pending, key)
		}
		s.mu.Unlock()
		return
	}

	acceptedTime := raknet.Timestamp()
	replyPayload := raknet.BuildConnectionRequestAccepted(addr, requestTime, acceptedTime, response)
	replyPacket := raknet.BuildReliableOrderedFrameSet(0, 0, 0, 0, replyPayload)

	tunnel, err := raknet.NewUDPTunnel(s.conn, addr, sessionKey, false)
	if err != nil {
		log.Printf("[%s] Failed to create tunnel: %v", addr, err)
		s.mu.Lock()
		if s.pending[key] == pending {
			pending.processing = false
		}
		s.mu.Unlock()
		return
	}

	session := &clientSession{
		tunnel:    tunnel,
		lastSeen:  time.Now(),
		authInit:  append([]byte(nil), authInit...),
		authReply: append([]byte(nil), replyPacket...),
	}

	s.mu.Lock()
	if s.pending[key] != pending {
		s.mu.Unlock()
		tunnel.Close()
		return
	}
	pending.processing = false
	pending.clientID = clientID
	pending.requestTime = requestTime
	pending.acceptedTime = acceptedTime
	pending.authInit = append([]byte(nil), authInit...)
	pending.authReply = append([]byte(nil), replyPacket...)
	pending.session = session
	pending.lastSeen = time.Now()
	s.mu.Unlock()

	if _, err := s.conn.WriteToUDP(replyPacket, addr); err != nil {
		log.Printf("[%s] Connection accepted send failed: %v", addr, err)
	}
}

func (s *server) handleNewIncomingConnection(data []byte, addr *net.UDPAddr) bool {
	requestTime, acceptedTime, ok := raknet.ParseNewIncomingConnection(data)
	if !ok {
		return false
	}

	key := addr.String()
	s.mu.Lock()
	if s.sessions[key] != nil {
		s.sessions[key].lastSeen = time.Now()
		s.mu.Unlock()
		return true
	}
	pending := s.pending[key]
	if pending == nil || pending.session == nil ||
		pending.requestTime != requestTime || pending.acceptedTime != acceptedTime {
		s.mu.Unlock()
		return false
	}
	session := pending.session
	delete(s.pending, key)
	s.sessions[key] = session
	s.mu.Unlock()

	log.Printf("[%s] RakNet connected and authenticated via ECDH", addr)
	go s.handleTunnel(session, addr)
	return true
}

func (s *server) handlePing(data []byte, addr *net.UDPAddr) {
	pingTime, ok := raknet.ParseUnconnectedPing(data)
	if !ok {
		return
	}
	pong := raknet.BuildUnconnectedPong(pingTime, s.info.ServerID, s.info)
	s.conn.WriteToUDP(pong, addr)
}

func (s *server) handleOpenConn1(data []byte, addr *net.UDPAddr) {
	mtu, ok := raknet.ParseOpenConnectionRequest1(data)
	if !ok {
		return
	}
	reply := raknet.BuildOpenConnectionReply1(s.info.ServerID, mtu)
	if _, err := s.conn.WriteToUDP(reply, addr); err != nil {
		log.Printf("[%s] OpenConnectionReply1 send failed: %v", addr, err)
	}
}

func (s *server) handleOpenConn2(data []byte, addr *net.UDPAddr) {
	_, _, mtu, ok := raknet.ParseOpenConnectionRequest2(data)
	if !ok {
		return
	}

	// Mark as pending before sending reply2. The client can send the ECDH
	// packet immediately after receiving reply2, so doing this afterward creates
	// a race where a valid ECDH init is dropped as "unexpected".
	s.mu.Lock()
	key := addr.String()
	_, alreadyPending := s.pending[key]
	_, alreadyActive := s.sessions[key]
	if !alreadyPending && !alreadyActive && len(s.sessions)+len(s.pending) >= *maxSessions {
		s.mu.Unlock()
		log.Printf("[%s] RakNet session rejected: too many sessions", addr)
		return
	}
	if alreadyActive {
		s.mu.Unlock()
		return
	}
	if alreadyPending {
		s.pending[key].lastSeen = time.Now()
	} else {
		s.pending[key] = &pendingSession{lastSeen: time.Now()}
	}
	s.mu.Unlock()

	reply := raknet.BuildOpenConnectionReply2(s.info.ServerID, addr, mtu)
	if _, err := s.conn.WriteToUDP(reply, addr); err != nil {
		log.Printf("[%s] OpenConnectionReply2 send failed: %v", addr, err)
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
		return
	}

	log.Printf("[%s] RakNet connection established, awaiting ECDH handshake", addr)
}

func (s *server) handleTunnel(session *clientSession, addr *net.UDPAddr) {
	tunnel := session.tunnel
	defer s.removeSession(addr.String(), session)

	// Read first request. Existing TCP-over-UDP clients send CONNECT; true UDP
	// relay clients send DATAGRAM frames after SOCKS5 UDP ASSOCIATE.
	frameType, data, err := tunnel.Recv(10 * time.Second)
	if err != nil {
		log.Printf("[%s] No tunnel request", addr)
		return
	}
	if frameType == raknet.TunnelFrameDatagram || frameType == raknet.TunnelFrameDatagramV2 {
		s.handleUDPRelay(session, addr, frameType, data)
		return
	}
	if frameType != raknet.TunnelFrameConnect {
		log.Printf("[%s] Unexpected first frame: 0x%02x", addr, frameType)
		return
	}

	destAddr, destPort, err := raknet.ParseConnectRequest(data)
	if err != nil {
		log.Printf("[%s] Bad connect request: %v", addr, err)
		tunnel.SendConnectResponse(false)
		return
	}

	target := fmt.Sprintf("%s:%d", destAddr, destPort)
	log.Printf("[%s] CONNECT %s", addr, target)

	// Connect to target
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[%s] Connect failed: %v", addr, err)
		tunnel.SendConnectResponse(false)
		return
	}
	defer targetConn.Close()

	tunnel.SendConnectResponse(true)
	log.Printf("[%s] Tunnel to %s established", addr, target)

	// Start keep-alive
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if tunnel.IsClosed() {
					return
				}
				tunnel.SendKeepAlive()
			case <-tunnel.Done():
				return
			}
		}
	}()

	// Relay: target -> tunnel
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				if werr := tunnel.SendData(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		tunnel.SendClose()
		done <- struct{}{}
	}()

	// Relay: tunnel -> target
	go func() {
		for {
			frameType, payload, err := tunnel.RecvBlocking()
			if err != nil {
				break
			}
			switch frameType {
			case raknet.TunnelFrameData:
				if _, err := targetConn.Write(payload); err != nil {
					goto end
				}
			case raknet.TunnelFrameKeepAlive:
				continue
			case raknet.TunnelFrameClose:
				goto end
			}
		}
	end:
		done <- struct{}{}
	}()

	<-done
	tunnel.Close()
	<-done
	log.Printf("[%s] Tunnel closed: %s", addr, target)
}

type udpTarget struct {
	conn          *net.UDPConn
	associationID uint32
	multiplexed   bool
	lastSeen      time.Time
}

func (s *server) handleUDPRelay(session *clientSession, addr *net.UDPAddr, firstType byte, first []byte) {
	tunnel := session.tunnel
	targets := make(map[string]*udpTarget)
	var targetsMu sync.Mutex
	defer func() {
		targetsMu.Lock()
		for _, target := range targets {
			target.conn.Close()
		}
		targetsMu.Unlock()
	}()

	log.Printf("[%s] UDP relay established", addr)

	closeAssociation := func(associationID uint32) {
		targetsMu.Lock()
		for key, target := range targets {
			if target.multiplexed && target.associationID == associationID {
				target.conn.Close()
				delete(targets, key)
			}
		}
		targetsMu.Unlock()
	}

	sendToTarget := func(frameType byte, frame []byte) {
		var (
			associationID uint32
			destAddr      string
			destPort      uint16
			payload       []byte
			err           error
			multiplexed   bool
		)
		if frameType == raknet.TunnelFrameDatagramV2 {
			multiplexed = true
			associationID, destAddr, destPort, payload, err = raknet.ParseDatagramV2(frame)
		} else {
			destAddr, destPort, payload, err = raknet.ParseDatagram(frame)
		}
		if err != nil {
			log.Printf("[%s] Bad UDP datagram: %v", addr, err)
			return
		}
		if len(payload) == 0 {
			return
		}
		destination := net.JoinHostPort(destAddr, fmt.Sprintf("%d", destPort))
		key := destination
		if multiplexed {
			key = fmt.Sprintf("%d/%s", associationID, destination)
		}

		targetsMu.Lock()
		target := targets[key]
		if target == nil {
			raddr, err := net.ResolveUDPAddr("udp", destination)
			if err != nil {
				targetsMu.Unlock()
				log.Printf("[%s] Resolve UDP target failed %s: %v", addr, destination, err)
				return
			}
			conn, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				targetsMu.Unlock()
				log.Printf("[%s] Dial UDP target failed %s: %v", addr, destination, err)
				return
			}
			target = &udpTarget{
				conn:          conn,
				associationID: associationID,
				multiplexed:   multiplexed,
				lastSeen:      time.Now(),
			}
			targets[key] = target
			go relayUDPTarget(tunnel, destination, target)
		} else {
			target.lastSeen = time.Now()
		}
		targetsMu.Unlock()

		if _, err := target.conn.Write(payload); err != nil {
			log.Printf("[%s] UDP write failed %s: %v", addr, key, err)
		}
	}

	sendToTarget(firstType, first)

	idle := time.NewTimer(2 * time.Minute)
	defer idle.Stop()
	cleanup := time.NewTicker(30 * time.Second)
	defer cleanup.Stop()
	type receivedFrame struct {
		frameType byte
		data      []byte
		err       error
	}
	frameCh := make(chan receivedFrame, 1)
	go func() {
		for {
			frameType, data, err := tunnel.RecvBlocking()
			select {
			case frameCh <- receivedFrame{frameType: frameType, data: data, err: err}:
			case <-tunnel.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case frame := <-frameCh:
			if frame.err != nil {
				log.Printf("[%s] UDP relay ended", addr)
				return
			}
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(2 * time.Minute)

			switch frame.frameType {
			case raknet.TunnelFrameDatagram, raknet.TunnelFrameDatagramV2:
				sendToTarget(frame.frameType, frame.data)
			case raknet.TunnelFrameAssocClose:
				associationID, err := raknet.ParseAssociationClose(frame.data)
				if err == nil {
					closeAssociation(associationID)
				}
			case raknet.TunnelFrameKeepAlive:
			case raknet.TunnelFrameClose:
				log.Printf("[%s] UDP relay closed", addr)
				return
			}
		case <-cleanup.C:
			cutoff := time.Now().Add(-2 * time.Minute)
			targetsMu.Lock()
			for key, target := range targets {
				if target.lastSeen.Before(cutoff) {
					target.conn.Close()
					delete(targets, key)
				}
			}
			targetsMu.Unlock()
		case <-idle.C:
			log.Printf("[%s] UDP relay idle timeout", addr)
			return
		case <-tunnel.Done():
			return
		}
	}
}

func relayUDPTarget(tunnel *raknet.UDPTunnel, key string, target *udpTarget) {
	buf := make([]byte, 64*1024)
	for {
		n, err := target.conn.Read(buf)
		if n > 0 {
			host, portStr, splitErr := net.SplitHostPort(key)
			if splitErr == nil {
				var port int
				fmt.Sscanf(portStr, "%d", &port)
				var sendErr error
				if target.multiplexed {
					sendErr = tunnel.SendDatagramV2(target.associationID, host, uint16(port), buf[:n])
				} else {
					sendErr = tunnel.SendDatagram(host, uint16(port), buf[:n])
				}
				if sendErr != nil {
					log.Printf("UDP relay response send failed %s: %v", key, sendErr)
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *server) removeSession(key string, expected *clientSession) {
	s.mu.Lock()
	if session, ok := s.sessions[key]; ok {
		if expected == nil || session == expected {
			session.tunnel.Close()
			delete(s.sessions, key)
		}
	}
	s.mu.Unlock()
}

func (s *server) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for key, session := range s.sessions {
			if now.Sub(session.lastSeen) > 60*time.Second {
				session.tunnel.Close()
				delete(s.sessions, key)
				log.Printf("[%s] Session expired", key)
			}
		}
		for key, pending := range s.pending {
			if now.Sub(pending.lastSeen) > 30*time.Second {
				if pending.session != nil {
					pending.session.tunnel.Close()
				}
				delete(s.pending, key)
				log.Printf("[%s] Pending session expired", key)
			}
		}
		s.mu.Unlock()
	}
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "MCProxy UDP Server - Bedrock Edition (RakNet) Disguised Proxy\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage:\n")
		flag.PrintDefaults()
	}
}
