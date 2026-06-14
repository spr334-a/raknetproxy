package raknet

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/user/mcproxy/pkg/crypto"
)

const (
	TunnelFrameData       = 0x01
	TunnelFrameKeepAlive  = 0x02
	TunnelFrameClose      = 0x03
	TunnelFrameAuth       = 0x04
	TunnelFrameConnect    = 0x05
	TunnelFrameConnResp   = 0x06
	TunnelFrameHandshake  = 0x07
	TunnelFrameDatagram   = 0x08
	TunnelFrameDatagramV2 = 0x09
	TunnelFrameAssocClose = 0x0A
	TunnelFrameDataOrder  = 0x0B

	AuthToken = "MCProxyUDP"

	maxPayloadSize = 1350

	initialCongestionWindow  = 10 * maxPayloadSize
	minimumCongestionWindow  = 2 * maxPayloadSize
	initialRetransmitTimeout = time.Second
	minimumRetransmitTimeout = 200 * time.Millisecond
	maximumRetransmitTimeout = 5 * time.Second
	maxRetransmissions       = 8
	maxReceivedSequences     = 4096
	maxOrderedFrames         = 1024
)

// UDPTunnel wraps encrypted data in RakNet frame sets over UDP.
type UDPTunnel struct {
	conn         *net.UDPConn
	remoteAddr   *net.UDPAddr
	caead        *crypto.CounterAEAD
	seqNum       uint32
	msgIdx       uint32
	splitID      uint32
	mu           sync.Mutex
	splitMu      sync.Mutex
	splits       map[uint16]*splitBuffer
	closed       int32
	recvCh       chan []byte
	done         chan struct{}
	preConnected bool
	ownsConn     bool

	ccMu          sync.Mutex
	pending       map[uint32]*sentPacket
	cwnd          int
	ssthresh      int
	bytesInFlight int
	smoothedRTT   time.Duration
	rttVariance   time.Duration
	latestRTT     time.Duration
	hasRTT        bool
	lastReduction time.Time
	nextSend      time.Time
	ccWake        chan struct{}

	recvMu          sync.Mutex
	received        map[uint32]struct{}
	receivedOrder   []uint32
	highestReceived uint32
	receiveStarted  bool

	dataSeq        uint32
	dataMu         sync.Mutex
	nextDataSeq    uint32
	orderedPending map[uint32][]byte
}

type splitBuffer struct {
	parts [][]byte
	count uint32
}

type sentPacket struct {
	data          []byte
	size          int
	sentAt        time.Time
	transmissions int
}

func NewUDPTunnel(conn *net.UDPConn, remoteAddr *net.UDPAddr, sessionKey []byte, isClient bool) (*UDPTunnel, error) {
	return newUDPTunnel(conn, remoteAddr, sessionKey, isClient, 1)
}

func newUDPTunnel(conn *net.UDPConn, remoteAddr *net.UDPAddr, sessionKey []byte, isClient bool, initialSequence uint32) (*UDPTunnel, error) {
	aead, err := crypto.NewChaCha20(sessionKey)
	if err != nil {
		return nil, err
	}
	tunnel := &UDPTunnel{
		conn:           conn,
		remoteAddr:     remoteAddr,
		caead:          crypto.NewCounterAEAD(aead, isClient),
		seqNum:         initialSequence,
		msgIdx:         initialSequence,
		splits:         make(map[uint16]*splitBuffer),
		recvCh:         make(chan []byte, 1024),
		done:           make(chan struct{}),
		pending:        make(map[uint32]*sentPacket),
		cwnd:           initialCongestionWindow,
		ssthresh:       int(^uint(0) >> 1),
		ccWake:         make(chan struct{}, 1),
		received:       make(map[uint32]struct{}),
		orderedPending: make(map[uint32][]byte),
	}
	go tunnel.retransmitLoop()
	return tunnel, nil
}

func NewUDPTunnelPreConnected(conn *net.UDPConn, remoteAddr *net.UDPAddr, sessionKey []byte, isClient bool) (*UDPTunnel, error) {
	t, err := newUDPTunnel(conn, remoteAddr, sessionKey, isClient, 2)
	if err != nil {
		return nil, err
	}
	t.preConnected = true
	t.ownsConn = true
	return t, nil
}

// Send encrypts and sends data as a RakNet frame set.
func (t *UDPTunnel) Send(frameType byte, payload []byte) error {
	t.mu.Lock()

	frame := make([]byte, 1+len(payload))
	frame[0] = frameType
	copy(frame[1:], payload)

	encrypted, err := t.caead.Seal(frame)
	if err != nil {
		t.mu.Unlock()
		return err
	}

	maxFramePayload := maxPayloadSize - 30
	var packets []struct {
		sequence uint32
		data     []byte
	}
	if len(encrypted) <= maxFramePayload {
		seq := (atomic.AddUint32(&t.seqNum, 1) - 1) & 0xFFFFFF
		msg := atomic.AddUint32(&t.msgIdx, 1) - 1
		pkt := BuildReliableFrameSet(seq, msg, encrypted)
		packets = append(packets, struct {
			sequence uint32
			data     []byte
		}{sequence: seq, data: pkt})
	} else {
		fragments := splitPayload(encrypted, maxFramePayload)
		splitID := uint16(atomic.AddUint32(&t.splitID, 1) - 1)
		msg := atomic.AddUint32(&t.msgIdx, 1) - 1
		splitCount := uint32(len(fragments))
		for i, frag := range fragments {
			seq := (atomic.AddUint32(&t.seqNum, 1) - 1) & 0xFFFFFF
			pkt := BuildReliableSplitFrameSet(seq, msg, splitID, splitCount, uint32(i), frag)
			packets = append(packets, struct {
				sequence uint32
				data     []byte
			}{sequence: seq, data: pkt})
		}
	}
	t.mu.Unlock()

	for _, packet := range packets {
		if err := t.sendReliablePacket(packet.sequence, packet.data); err != nil {
			return err
		}
	}
	return nil
}

// SendData sends tunnel data.
func (t *UDPTunnel) SendData(data []byte) error {
	sequence := atomic.AddUint32(&t.dataSeq, 1) - 1
	payload := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(payload, sequence)
	copy(payload[4:], data)
	return t.Send(TunnelFrameDataOrder, payload)
}

func (t *UDPTunnel) sendReliablePacket(sequence uint32, packet []byte) error {
	size := len(packet)
	for {
		if t.IsClosed() {
			return errors.New("tunnel closed")
		}

		t.ccMu.Lock()
		if _, exists := t.pending[sequence]; exists {
			t.ccMu.Unlock()
			return errors.New("sequence number still in flight")
		}
		if t.bytesInFlight == 0 || t.bytesInFlight+size <= t.cwnd {
			pacingDelay := t.reservePacingDelayLocked(size)
			t.ccMu.Unlock()
			if pacingDelay > 0 {
				timer := time.NewTimer(pacingDelay)
				select {
				case <-timer.C:
				case <-t.done:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return errors.New("tunnel closed")
				}
			}

			now := time.Now()
			t.ccMu.Lock()
			if t.bytesInFlight != 0 && t.bytesInFlight+size > t.cwnd {
				t.ccMu.Unlock()
				continue
			}
			t.pending[sequence] = &sentPacket{
				data:          append([]byte(nil), packet...),
				size:          size,
				sentAt:        now,
				transmissions: 1,
			}
			t.bytesInFlight += size
			t.ccMu.Unlock()

			if err := t.writeWire(packet); err != nil {
				t.removePending(sequence)
				return err
			}
			return nil
		}
		t.ccMu.Unlock()

		select {
		case <-t.ccWake:
		case <-t.done:
			return errors.New("tunnel closed")
		}
	}
}

func (t *UDPTunnel) reservePacingDelayLocked(size int) time.Duration {
	if !t.hasRTT || t.cwnd <= 0 {
		return 0
	}
	spacing := time.Duration(int64(t.smoothedRTT) * int64(size) / int64(t.cwnd))
	if spacing > 2*time.Millisecond {
		spacing = 2 * time.Millisecond
	}
	now := time.Now()
	sendAt := now
	if t.nextSend.After(now) {
		sendAt = t.nextSend
	}
	t.nextSend = sendAt.Add(spacing)
	return sendAt.Sub(now)
}

func (t *UDPTunnel) writeWire(packet []byte) error {
	var err error
	if t.preConnected {
		_, err = t.conn.Write(packet)
	} else {
		_, err = t.conn.WriteToUDP(packet, t.remoteAddr)
	}
	return err
}

func (t *UDPTunnel) writeControl(packet []byte) {
	if t.preConnected {
		t.conn.Write(packet)
	} else {
		t.conn.WriteToUDP(packet, t.remoteAddr)
	}
}

func (t *UDPTunnel) removePending(sequence uint32) {
	t.ccMu.Lock()
	if packet := t.pending[sequence]; packet != nil {
		delete(t.pending, sequence)
		t.bytesInFlight -= packet.size
		if t.bytesInFlight < 0 {
			t.bytesInFlight = 0
		}
	}
	t.ccMu.Unlock()
	t.signalCongestionWake()
}

func (t *UDPTunnel) signalCongestionWake() {
	select {
	case t.ccWake <- struct{}{}:
	default:
	}
}

// SendKeepAlive sends a keep-alive frame.
func (t *UDPTunnel) SendKeepAlive() error {
	return t.Send(TunnelFrameKeepAlive, nil)
}

// SendClose sends a close frame.
func (t *UDPTunnel) SendClose() error {
	return t.Send(TunnelFrameClose, nil)
}

func (t *UDPTunnel) SendDatagram(addr string, port uint16, payload []byte) error {
	data, err := EncodeDatagram(addr, port, payload)
	if err != nil {
		return err
	}
	return t.Send(TunnelFrameDatagram, data)
}

func (t *UDPTunnel) SendDatagramV2(associationID uint32, addr string, port uint16, payload []byte) error {
	data, err := EncodeDatagramV2(associationID, addr, port, payload)
	if err != nil {
		return err
	}
	return t.Send(TunnelFrameDatagramV2, data)
}

func (t *UDPTunnel) SendAssociationClose(associationID uint32) error {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, associationID)
	return t.Send(TunnelFrameAssocClose, data)
}

func EncodeDatagram(addr string, port uint16, payload []byte) ([]byte, error) {
	if len(addr) > 255 {
		return nil, errors.New("datagram address too long")
	}
	data := make([]byte, 0, 1+len(addr)+2+len(payload))
	data = append(data, byte(len(addr)))
	data = append(data, []byte(addr)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	data = append(data, portBuf...)
	data = append(data, payload...)
	return data, nil
}

func ParseDatagram(data []byte) (string, uint16, []byte, error) {
	if len(data) < 4 {
		return "", 0, nil, errors.New("datagram too short")
	}
	addrLen := int(data[0])
	if len(data) < 1+addrLen+2 {
		return "", 0, nil, errors.New("datagram truncated")
	}
	addr := string(data[1 : 1+addrLen])
	port := binary.BigEndian.Uint16(data[1+addrLen : 1+addrLen+2])
	return addr, port, data[1+addrLen+2:], nil
}

func EncodeDatagramV2(associationID uint32, addr string, port uint16, payload []byte) ([]byte, error) {
	datagram, err := EncodeDatagram(addr, port, payload)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 4+len(datagram))
	binary.BigEndian.PutUint32(data, associationID)
	copy(data[4:], datagram)
	return data, nil
}

func ParseDatagramV2(data []byte) (uint32, string, uint16, []byte, error) {
	if len(data) < 4 {
		return 0, "", 0, nil, errors.New("multiplexed datagram too short")
	}
	associationID := binary.BigEndian.Uint32(data[:4])
	if associationID == 0 {
		return 0, "", 0, nil, errors.New("invalid association id")
	}
	addr, port, payload, err := ParseDatagram(data[4:])
	if err != nil {
		return 0, "", 0, nil, err
	}
	return associationID, addr, port, payload, nil
}

func ParseAssociationClose(data []byte) (uint32, error) {
	if len(data) != 4 {
		return 0, errors.New("invalid association close")
	}
	associationID := binary.BigEndian.Uint32(data)
	if associationID == 0 {
		return 0, errors.New("invalid association id")
	}
	return associationID, nil
}

// HandlePacket processes an incoming UDP packet.
// Returns true if it was a tunnel packet (vs RakNet control).
func (t *UDPTunnel) HandlePacket(data []byte) bool {
	if len(data) < 1 {
		return false
	}

	switch {
	case data[0] >= 0x80 && data[0] <= 0x8D:
		// Frame set - extract payload
		frame, ok := ParseFrameSetPayload(data)
		if !ok {
			return false
		}

		sequence := frame.SequenceNumber & 0xFFFFFF
		t.writeControl(BuildAck(sequence))
		accepted, missing := t.acceptSequence(sequence)
		for _, missingSequence := range missing {
			t.writeControl(BuildNack(missingSequence))
		}
		if !accepted {
			return true
		}

		payload := frame.Payload
		if frame.Split {
			payload, ok = t.handleSplitFrame(frame)
			if !ok {
				return true
			}
		}

		// Decrypt with counter-based AEAD after split reassembly.
		decrypted, err := t.caead.Open(payload)
		if err != nil {
			return false
		}

		t.deliverFrame(decrypted)
		return true

	case data[0] == IDAck:
		sequences, ok := ParseControlSequences(data, 4096)
		if !ok {
			return false
		}
		t.handleAcknowledgements(sequences)
		return true

	case data[0] == IDNack:
		sequences, ok := ParseControlSequences(data, 4096)
		if !ok {
			return false
		}
		for _, sequence := range sequences {
			t.retransmit(sequence, true)
		}
		return true
	}

	return false
}

func (t *UDPTunnel) acceptSequence(sequence uint32) (bool, []uint32) {
	sequence &= 0xFFFFFF
	t.recvMu.Lock()
	defer t.recvMu.Unlock()

	if _, duplicate := t.received[sequence]; duplicate {
		return false, nil
	}

	var missing []uint32
	if !t.receiveStarted {
		t.receiveStarted = true
		t.highestReceived = sequence
	} else if sequenceAfter(sequence, t.highestReceived) {
		distance := sequenceDistance(sequence, t.highestReceived)
		if distance > 1 && distance <= 33 {
			missing = make([]uint32, 0, distance-1)
			for offset := uint32(1); offset < distance; offset++ {
				candidate := (t.highestReceived + offset) & 0xFFFFFF
				if _, received := t.received[candidate]; !received {
					missing = append(missing, candidate)
				}
			}
		}
		t.highestReceived = sequence
	}

	t.received[sequence] = struct{}{}
	t.receivedOrder = append(t.receivedOrder, sequence)
	if len(t.receivedOrder) > maxReceivedSequences {
		oldest := t.receivedOrder[0]
		t.receivedOrder = t.receivedOrder[1:]
		delete(t.received, oldest)
	}
	return true, missing
}

func sequenceDistance(later, earlier uint32) uint32 {
	return (later - earlier) & 0xFFFFFF
}

func sequenceAfter(candidate, reference uint32) bool {
	distance := sequenceDistance(candidate, reference)
	return distance != 0 && distance < 0x800000
}

func (t *UDPTunnel) deliverFrame(frame []byte) {
	if len(frame) < 1 {
		return
	}
	if frame[0] != TunnelFrameDataOrder {
		t.enqueueFrame(frame)
		return
	}
	if len(frame) < 5 {
		return
	}

	sequence := binary.BigEndian.Uint32(frame[1:5])
	data := append([]byte(nil), frame[5:]...)
	var ready [][]byte

	t.dataMu.Lock()
	distance := sequence - t.nextDataSeq
	switch {
	case distance == 0:
		ready = append(ready, data)
		t.nextDataSeq++
		for {
			pending, ok := t.orderedPending[t.nextDataSeq]
			if !ok {
				break
			}
			delete(t.orderedPending, t.nextDataSeq)
			ready = append(ready, pending)
			t.nextDataSeq++
		}
	case distance < 0x80000000 && len(t.orderedPending) < maxOrderedFrames:
		if _, exists := t.orderedPending[sequence]; !exists {
			t.orderedPending[sequence] = data
		}
	}
	t.dataMu.Unlock()

	for _, payload := range ready {
		orderedFrame := make([]byte, 1+len(payload))
		orderedFrame[0] = TunnelFrameData
		copy(orderedFrame[1:], payload)
		t.enqueueFrame(orderedFrame)
	}
}

func (t *UDPTunnel) enqueueFrame(frame []byte) {
	select {
	case t.recvCh <- frame:
	case <-t.done:
	}
}

func (t *UDPTunnel) handleAcknowledgements(sequences []uint32) {
	now := time.Now()
	ackedBytes := 0
	var rttSample time.Duration

	t.ccMu.Lock()
	for _, sequence := range sequences {
		packet := t.pending[sequence&0xFFFFFF]
		if packet == nil {
			continue
		}
		delete(t.pending, sequence&0xFFFFFF)
		t.bytesInFlight -= packet.size
		ackedBytes += packet.size
		if packet.transmissions == 1 {
			rttSample = now.Sub(packet.sentAt)
			if rttSample <= 0 {
				rttSample = time.Microsecond
			}
		}
	}
	if t.bytesInFlight < 0 {
		t.bytesInFlight = 0
	}
	if rttSample > 0 {
		t.updateRTTLocked(rttSample)
	}
	if ackedBytes > 0 {
		if t.cwnd < t.ssthresh {
			t.cwnd += ackedBytes
		} else {
			increase := maxPayloadSize * ackedBytes / t.cwnd
			if increase < 1 {
				increase = 1
			}
			t.cwnd += increase
		}
	}
	t.ccMu.Unlock()
	if ackedBytes > 0 {
		t.signalCongestionWake()
	}
}

func (t *UDPTunnel) updateRTTLocked(sample time.Duration) {
	t.latestRTT = sample
	if !t.hasRTT {
		t.smoothedRTT = sample
		t.rttVariance = sample / 2
		t.hasRTT = true
		return
	}
	delta := t.smoothedRTT - sample
	if delta < 0 {
		delta = -delta
	}
	t.rttVariance = (3*t.rttVariance + delta) / 4
	t.smoothedRTT = (7*t.smoothedRTT + sample) / 8
}

func (t *UDPTunnel) retransmitTimeoutLocked(transmissions int) time.Duration {
	timeout := initialRetransmitTimeout
	if t.hasRTT {
		variation := 4 * t.rttVariance
		if variation < 10*time.Millisecond {
			variation = 10 * time.Millisecond
		}
		timeout = t.smoothedRTT + variation
		if timeout < minimumRetransmitTimeout {
			timeout = minimumRetransmitTimeout
		}
	}
	if transmissions > 1 {
		shift := transmissions - 1
		if shift > 3 {
			shift = 3
		}
		timeout *= time.Duration(1 << shift)
	}
	if timeout > maximumRetransmitTimeout {
		timeout = maximumRetransmitTimeout
	}
	return timeout
}

func (t *UDPTunnel) retransmitLoop() {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			var expired []uint32
			t.ccMu.Lock()
			for sequence, packet := range t.pending {
				if now.Sub(packet.sentAt) >= t.retransmitTimeoutLocked(packet.transmissions) {
					expired = append(expired, sequence)
				}
			}
			t.ccMu.Unlock()
			for _, sequence := range expired {
				t.retransmit(sequence, false)
			}
		case <-t.done:
			return
		}
	}
}

func (t *UDPTunnel) retransmit(sequence uint32, fast bool) {
	sequence &= 0xFFFFFF
	now := time.Now()

	t.ccMu.Lock()
	packet := t.pending[sequence]
	if packet == nil {
		t.ccMu.Unlock()
		return
	}
	if packet.transmissions >= maxRetransmissions {
		t.ccMu.Unlock()
		t.Close()
		return
	}
	if fast && now.Sub(packet.sentAt) < 10*time.Millisecond {
		t.ccMu.Unlock()
		return
	}

	reductionInterval := t.smoothedRTT
	if reductionInterval < minimumRetransmitTimeout {
		reductionInterval = minimumRetransmitTimeout
	}
	if t.lastReduction.IsZero() || now.Sub(t.lastReduction) >= reductionInterval {
		t.ssthresh = t.cwnd / 2
		if t.ssthresh < minimumCongestionWindow {
			t.ssthresh = minimumCongestionWindow
		}
		t.cwnd = t.ssthresh
		t.lastReduction = now
	}
	packet.sentAt = now
	packet.transmissions++
	data := append([]byte(nil), packet.data...)
	t.ccMu.Unlock()

	if err := t.writeWire(data); err != nil {
		t.Close()
	}
}

func (t *UDPTunnel) handleSplitFrame(frame FramePayload) ([]byte, bool) {
	if frame.SplitCount == 0 || frame.SplitCount > 256 || frame.SplitIndex >= frame.SplitCount {
		return nil, false
	}

	t.splitMu.Lock()
	defer t.splitMu.Unlock()

	buf := t.splits[frame.SplitID]
	if buf == nil || len(buf.parts) != int(frame.SplitCount) {
		buf = &splitBuffer{parts: make([][]byte, int(frame.SplitCount))}
		t.splits[frame.SplitID] = buf
	}
	if buf.parts[frame.SplitIndex] != nil {
		return nil, false
	}
	part := make([]byte, len(frame.Payload))
	copy(part, frame.Payload)
	buf.parts[frame.SplitIndex] = part
	buf.count++
	if buf.count != frame.SplitCount {
		return nil, false
	}

	var payload []byte
	for _, part := range buf.parts {
		if part == nil {
			return nil, false
		}
		payload = append(payload, part...)
	}
	delete(t.splits, frame.SplitID)
	return payload, true
}

// Recv receives a decrypted frame. Returns frame type and payload.
func (t *UDPTunnel) Recv(timeout time.Duration) (byte, []byte, error) {
	select {
	case frame := <-t.recvCh:
		if len(frame) < 1 {
			return 0, nil, errors.New("empty frame")
		}
		return frame[0], frame[1:], nil
	case <-time.After(timeout):
		return 0, nil, errors.New("recv timeout")
	case <-t.done:
		return 0, nil, errors.New("tunnel closed")
	}
}

// RecvBlocking receives without timeout (blocks until data or close).
func (t *UDPTunnel) RecvBlocking() (byte, []byte, error) {
	select {
	case frame := <-t.recvCh:
		if len(frame) < 1 {
			return 0, nil, errors.New("empty frame")
		}
		return frame[0], frame[1:], nil
	case <-t.done:
		return 0, nil, errors.New("tunnel closed")
	}
}

func (t *UDPTunnel) Close() {
	if atomic.CompareAndSwapInt32(&t.closed, 0, 1) {
		close(t.done)
		t.signalCongestionWake()
		if t.ownsConn {
			t.conn.Close()
		}
	}
}

func (t *UDPTunnel) IsClosed() bool {
	return atomic.LoadInt32(&t.closed) == 1
}

func (t *UDPTunnel) Done() <-chan struct{} {
	return t.done
}

func (t *UDPTunnel) RemoteAddr() *net.UDPAddr {
	return t.remoteAddr
}

// SendConnectRequest sends target address through UDP tunnel.
func (t *UDPTunnel) SendConnectRequest(addr string, port uint16) error {
	data := make([]byte, 0, 256)
	data = append(data, byte(len(addr)))
	data = append(data, []byte(addr)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	data = append(data, portBuf...)
	return t.Send(TunnelFrameConnect, data)
}

// ParseConnectRequest extracts address from connect frame.
func ParseConnectRequest(data []byte) (string, uint16, error) {
	if len(data) < 4 {
		return "", 0, errors.New("connect request too short")
	}
	addrLen := int(data[0])
	if len(data) < 1+addrLen+2 {
		return "", 0, errors.New("connect request truncated")
	}
	addr := string(data[1 : 1+addrLen])
	port := binary.BigEndian.Uint16(data[1+addrLen : 1+addrLen+2])
	return addr, port, nil
}

// SendConnectResponse sends connection result.
func (t *UDPTunnel) SendConnectResponse(success bool) error {
	code := byte(0x00)
	if !success {
		code = 0x01
	}
	return t.Send(TunnelFrameConnResp, []byte{code})
}

func splitPayload(data []byte, maxSize int) [][]byte {
	if len(data) <= maxSize {
		return [][]byte{data}
	}
	var parts [][]byte
	for len(data) > 0 {
		end := maxSize
		if end > len(data) {
			end = len(data)
		}
		parts = append(parts, data[:end])
		data = data[end:]
	}
	return parts
}
