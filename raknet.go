package raknet

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// RakNet packet IDs (Bedrock Edition uses these)
const (
	IDUnconnectedPing         = 0x01
	IDUnconnectedPong         = 0x1C
	IDOpenConnectionRequest1  = 0x05
	IDOpenConnectionReply1    = 0x06
	IDOpenConnectionRequest2  = 0x07
	IDOpenConnectionReply2    = 0x08
	IDConnectionRequest       = 0x09
	IDConnectionRequestAccept = 0x10
	IDNewIncomingConnection   = 0x13
	IDFrameSet                = 0x84 // 0x80-0x8D are all frame sets
	IDNack                    = 0xA0
	IDAck                     = 0xC0
)

// RakNet magic bytes (used in unconnected messages)
var RakNetMagic = []byte{
	0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
	0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78,
}

const (
	MTUSize                  = 1400
	RakNetProtocol           = 11
	BedrockPort              = 19132
	rakNetSystemAddressCount = 10
)

// ServerInfo represents the MOTD response for a Bedrock server
type ServerInfo struct {
	Edition    string // MCPE or MCEE
	MOTD       string
	Protocol   int
	Version    string
	Players    int
	MaxPlayers int
	ServerID   int64
	WorldName  string
	Gamemode   string
	Port       int
}

func DefaultServerInfo() *ServerInfo {
	id := make([]byte, 8)
	rand.Read(id)
	return &ServerInfo{
		Edition:    "MCPE",
		MOTD:       "Dedicated Server",
		Protocol:   685,
		Version:    "1.21.0",
		Players:    1,
		MaxPlayers: 20,
		ServerID:   int64(binary.BigEndian.Uint64(id)),
		WorldName:  "Bedrock level",
		Gamemode:   "Survival",
		Port:       BedrockPort,
	}
}

func (si *ServerInfo) String() string {
	return fmt.Sprintf("%s;%s;%d;%s;%d;%d;%d;%s;%s;1;%d;",
		si.Edition, si.MOTD, si.Protocol, si.Version,
		si.Players, si.MaxPlayers, si.ServerID,
		si.WorldName, si.Gamemode, si.Port)
}

// BuildUnconnectedPing creates a standard RakNet server-list ping.
func BuildUnconnectedPing(pingTime int64) []byte {
	var buf bytes.Buffer
	buf.WriteByte(IDUnconnectedPing)
	binary.Write(&buf, binary.BigEndian, pingTime)
	buf.Write(RakNetMagic)
	return buf.Bytes()
}

// BuildUnconnectedPong creates a response to an unconnected ping
func BuildUnconnectedPong(pingTime int64, serverID int64, info *ServerInfo) []byte {
	var buf bytes.Buffer
	buf.WriteByte(IDUnconnectedPong)
	binary.Write(&buf, binary.BigEndian, pingTime)
	binary.Write(&buf, binary.BigEndian, serverID)
	buf.Write(RakNetMagic)
	motd := info.String()
	binary.Write(&buf, binary.BigEndian, uint16(len(motd)))
	buf.WriteString(motd)
	return buf.Bytes()
}

// ParseUnconnectedPong extracts the echoed ping timestamp.
func ParseUnconnectedPong(data []byte) (int64, bool) {
	if len(data) < 35 || data[0] != IDUnconnectedPong {
		return 0, false
	}
	if !bytes.Equal(data[17:33], RakNetMagic) {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(data[1:9])), true
}

// ParseUnconnectedPing extracts the ping time from a ping packet
func ParseUnconnectedPing(data []byte) (int64, bool) {
	if len(data) < 25 || data[0] != IDUnconnectedPing {
		return 0, false
	}
	pingTime := int64(binary.BigEndian.Uint64(data[1:9]))
	// Verify magic at offset 9
	if !bytes.Equal(data[9:25], RakNetMagic) {
		return 0, false
	}
	return pingTime, true
}

// BuildOpenConnectionReply1 responds to connection request 1
func BuildOpenConnectionReply1(serverID int64, mtu uint16) []byte {
	var buf bytes.Buffer
	buf.WriteByte(IDOpenConnectionReply1)
	buf.Write(RakNetMagic)
	binary.Write(&buf, binary.BigEndian, serverID)
	buf.WriteByte(0x00) // security = false
	binary.Write(&buf, binary.BigEndian, mtu)
	return buf.Bytes()
}

// ParseOpenConnectionRequest1 extracts MTU from request
func ParseOpenConnectionRequest1(data []byte) (uint16, bool) {
	if len(data) < 18 || data[0] != IDOpenConnectionRequest1 {
		return 0, false
	}
	// Magic at 1:17, protocol at 17, rest is padding for MTU detection
	if !bytes.Equal(data[1:17], RakNetMagic) {
		return 0, false
	}
	mtu := uint16(len(data) + 28) // +28 for UDP/IP header
	if mtu > MTUSize {
		mtu = MTUSize
	}
	return mtu, true
}

// BuildOpenConnectionReply2 responds to connection request 2
func BuildOpenConnectionReply2(serverID int64, clientAddr *net.UDPAddr, mtu uint16) []byte {
	var buf bytes.Buffer
	buf.WriteByte(IDOpenConnectionReply2)
	buf.Write(RakNetMagic)
	binary.Write(&buf, binary.BigEndian, serverID)
	writeAddress(&buf, clientAddr)
	binary.Write(&buf, binary.BigEndian, mtu)
	buf.WriteByte(0x00) // encryption = false
	return buf.Bytes()
}

// ParseOpenConnectionRequest2 extracts info from request 2
func ParseOpenConnectionRequest2(data []byte) (int64, *net.UDPAddr, uint16, bool) {
	if len(data) < 34 || data[0] != IDOpenConnectionRequest2 {
		return 0, nil, 0, false
	}
	if !bytes.Equal(data[1:17], RakNetMagic) {
		return 0, nil, 0, false
	}
	// Server address starts at 17
	addr, offset := readAddress(data[17:])
	if addr == nil {
		return 0, nil, 0, false
	}
	pos := 17 + offset
	if pos+10 > len(data) {
		return 0, nil, 0, false
	}
	mtu := binary.BigEndian.Uint16(data[pos : pos+2])
	clientID := int64(binary.BigEndian.Uint64(data[pos+2 : pos+10]))
	return clientID, addr, mtu, true
}

// BuildConnectionRequest creates the first connected RakNet message. RakNet
// defines all bytes after the encryption flag as an optional password, which
// gives the authenticated key exchange a standards-compliant carrier.
func BuildConnectionRequest(clientID, requestTime int64, password []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(IDConnectionRequest)
	binary.Write(&buf, binary.BigEndian, clientID)
	binary.Write(&buf, binary.BigEndian, requestTime)
	buf.WriteByte(0x00)
	buf.Write(password)
	return buf.Bytes()
}

func ParseConnectionRequest(data []byte) (clientID, requestTime int64, password []byte, ok bool) {
	if len(data) < 18 || data[0] != IDConnectionRequest {
		return 0, 0, nil, false
	}
	clientID = int64(binary.BigEndian.Uint64(data[1:9]))
	requestTime = int64(binary.BigEndian.Uint64(data[9:17]))
	if data[17] != 0x00 {
		return 0, 0, nil, false
	}
	password = append([]byte(nil), data[18:]...)
	return clientID, requestTime, password, true
}

// BuildConnectionRequestAccepted creates a normal RakNet acceptance message.
// authReply is trailing application data; RakNet peers that do not understand
// it ignore it, while MCProxy uses it to finish the authenticated key exchange.
func BuildConnectionRequestAccepted(clientAddr *net.UDPAddr, requestTime, acceptedTime int64, authReply []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(IDConnectionRequestAccept)
	writeAddress(&buf, clientAddr)
	binary.Write(&buf, binary.BigEndian, uint16(0))
	writeSystemAddresses(&buf)
	binary.Write(&buf, binary.BigEndian, requestTime)
	binary.Write(&buf, binary.BigEndian, acceptedTime)
	buf.Write(authReply)
	return buf.Bytes()
}

func ParseConnectionRequestAccepted(data []byte) (requestTime, acceptedTime int64, authReply []byte, ok bool) {
	if len(data) < 1 || data[0] != IDConnectionRequestAccept {
		return 0, 0, nil, false
	}
	pos, ok := skipAddress(data, 1)
	if !ok || pos+2 > len(data) {
		return 0, 0, nil, false
	}
	pos += 2
	for i := 0; i < rakNetSystemAddressCount; i++ {
		pos, ok = skipAddress(data, pos)
		if !ok {
			return 0, 0, nil, false
		}
	}
	if pos+16 > len(data) {
		return 0, 0, nil, false
	}
	requestTime = int64(binary.BigEndian.Uint64(data[pos : pos+8]))
	acceptedTime = int64(binary.BigEndian.Uint64(data[pos+8 : pos+16]))
	authReply = append([]byte(nil), data[pos+16:]...)
	return requestTime, acceptedTime, authReply, true
}

func BuildNewIncomingConnection(serverAddr *net.UDPAddr, requestTime, acceptedTime int64) []byte {
	var buf bytes.Buffer
	buf.WriteByte(IDNewIncomingConnection)
	writeAddress(&buf, serverAddr)
	writeSystemAddresses(&buf)
	binary.Write(&buf, binary.BigEndian, requestTime)
	binary.Write(&buf, binary.BigEndian, acceptedTime)
	return buf.Bytes()
}

func ParseNewIncomingConnection(data []byte) (requestTime, acceptedTime int64, ok bool) {
	if len(data) < 1 || data[0] != IDNewIncomingConnection {
		return 0, 0, false
	}
	pos, ok := skipAddress(data, 1)
	if !ok {
		return 0, 0, false
	}
	for i := 0; i < rakNetSystemAddressCount; i++ {
		pos, ok = skipAddress(data, pos)
		if !ok {
			return 0, 0, false
		}
	}
	if pos+16 != len(data) {
		return 0, 0, false
	}
	requestTime = int64(binary.BigEndian.Uint64(data[pos : pos+8]))
	acceptedTime = int64(binary.BigEndian.Uint64(data[pos+8 : pos+16]))
	return requestTime, acceptedTime, true
}

func writeSystemAddresses(buf *bytes.Buffer) {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	for i := 0; i < rakNetSystemAddressCount; i++ {
		writeAddress(buf, addr)
	}
}

func skipAddress(data []byte, pos int) (int, bool) {
	if pos >= len(data) {
		return 0, false
	}
	_, n := readAddress(data[pos:])
	if n == 0 {
		return 0, false
	}
	return pos + n, true
}

// FrameSet wraps payload data in a RakNet frame set packet
type FrameSet struct {
	SequenceNumber uint32 // 24-bit LE
	Frames         []Frame
}

type Frame struct {
	Reliability byte
	Length      uint16 // in bits
	MessageIdx  uint32 // 24-bit LE
	Data        []byte
}

type FramePayload struct {
	SequenceNumber uint32
	Payload        []byte
	Split          bool
	SplitCount     uint32
	SplitID        uint16
	SplitIndex     uint32
}

func BuildFrameSet(seqNum uint32, data []byte) []byte {
	var buf bytes.Buffer

	// Frame set header (0x84)
	buf.WriteByte(IDFrameSet)

	// Sequence number (24-bit LE)
	buf.WriteByte(byte(seqNum))
	buf.WriteByte(byte(seqNum >> 8))
	buf.WriteByte(byte(seqNum >> 16))

	// Frame: reliability=0 (unreliable), no fragment
	flags := byte(0x00) // unreliable, no split
	buf.WriteByte(flags)

	// Length in bits (16-bit BE)
	binary.Write(&buf, binary.BigEndian, uint16(len(data)*8))

	// Payload
	buf.Write(data)

	return buf.Bytes()
}

func BuildReliableFrameSet(seqNum, msgIdx uint32, data []byte) []byte {
	var buf bytes.Buffer

	buf.WriteByte(IDFrameSet)

	// Sequence number (24-bit LE)
	buf.WriteByte(byte(seqNum))
	buf.WriteByte(byte(seqNum >> 8))
	buf.WriteByte(byte(seqNum >> 16))

	// Frame: reliability=2 (reliable), no split
	flags := byte(0x40) // reliable (010 in top 3 bits)
	buf.WriteByte(flags)

	// Length in bits
	binary.Write(&buf, binary.BigEndian, uint16(len(data)*8))

	// Message index (24-bit LE)
	buf.WriteByte(byte(msgIdx))
	buf.WriteByte(byte(msgIdx >> 8))
	buf.WriteByte(byte(msgIdx >> 16))

	buf.Write(data)

	return buf.Bytes()
}

func BuildReliableOrderedFrameSet(seqNum, msgIdx, orderIdx uint32, orderChannel byte, data []byte) []byte {
	var buf bytes.Buffer

	buf.WriteByte(IDFrameSet)

	// Sequence number (24-bit LE)
	buf.WriteByte(byte(seqNum))
	buf.WriteByte(byte(seqNum >> 8))
	buf.WriteByte(byte(seqNum >> 16))

	// Frame: reliability=3 (reliable ordered), no split
	buf.WriteByte(0x60)

	// Length in bits
	binary.Write(&buf, binary.BigEndian, uint16(len(data)*8))

	// Message and ordering indices (24-bit LE)
	buf.WriteByte(byte(msgIdx))
	buf.WriteByte(byte(msgIdx >> 8))
	buf.WriteByte(byte(msgIdx >> 16))
	buf.WriteByte(byte(orderIdx))
	buf.WriteByte(byte(orderIdx >> 8))
	buf.WriteByte(byte(orderIdx >> 16))
	buf.WriteByte(orderChannel)

	buf.Write(data)
	return buf.Bytes()
}

func BuildReliableSplitFrameSet(seqNum, msgIdx uint32, splitID uint16, splitCount, splitIndex uint32, data []byte) []byte {
	var buf bytes.Buffer

	buf.WriteByte(IDFrameSet)

	// Sequence number (24-bit LE)
	buf.WriteByte(byte(seqNum))
	buf.WriteByte(byte(seqNum >> 8))
	buf.WriteByte(byte(seqNum >> 16))

	// Frame: reliability=2 (reliable), split flag set
	flags := byte(0x50)
	buf.WriteByte(flags)

	// Length in bits
	binary.Write(&buf, binary.BigEndian, uint16(len(data)*8))

	// Message index (24-bit LE)
	buf.WriteByte(byte(msgIdx))
	buf.WriteByte(byte(msgIdx >> 8))
	buf.WriteByte(byte(msgIdx >> 16))

	// Split metadata
	binary.Write(&buf, binary.BigEndian, splitCount)
	binary.Write(&buf, binary.BigEndian, splitID)
	binary.Write(&buf, binary.BigEndian, splitIndex)

	buf.Write(data)

	return buf.Bytes()
}

// ParseFrameSet extracts payload from a frame set packet
func ParseFrameSet(data []byte) (uint32, []byte, bool) {
	frame, ok := ParseFrameSetPayload(data)
	if !ok || frame.Split {
		return 0, nil, false
	}
	return frame.SequenceNumber, frame.Payload, true
}

func ParseFrameSetPayload(data []byte) (FramePayload, bool) {
	if len(data) < 7 {
		return FramePayload{}, false
	}
	if data[0] < 0x80 || data[0] > 0x8D {
		return FramePayload{}, false
	}

	// Sequence number (24-bit LE)
	seqNum := uint32(data[1]) | uint32(data[2])<<8 | uint32(data[3])<<16

	// Frame flags
	flags := data[4]
	reliability := (flags >> 5) & 0x07
	hasSplit := flags&0x10 != 0

	// Length in bits
	if len(data) < 7 {
		return FramePayload{}, false
	}
	bitLen := binary.BigEndian.Uint16(data[5:7])
	byteLen := int(bitLen+7) / 8

	offset := 7

	// If reliable (2,3,4,6,7), has message index
	if reliability >= 2 && reliability != 5 {
		offset += 3 // 24-bit message index
	}

	// If ordered (1,3,4,7), has order index + channel
	if reliability == 1 || reliability == 3 || reliability == 4 || reliability == 7 {
		offset += 4 // 24-bit order index + 1 byte channel
	}

	frame := FramePayload{SequenceNumber: seqNum}
	if hasSplit {
		if offset+10 > len(data) {
			return FramePayload{}, false
		}
		frame.Split = true
		frame.SplitCount = binary.BigEndian.Uint32(data[offset : offset+4])
		frame.SplitID = binary.BigEndian.Uint16(data[offset+4 : offset+6])
		frame.SplitIndex = binary.BigEndian.Uint32(data[offset+6 : offset+10])
		offset += 10
	}

	if offset+byteLen > len(data) {
		return FramePayload{}, false
	}

	frame.Payload = data[offset : offset+byteLen]
	return frame, true
}

// BuildAck creates an ACK packet for a sequence number
func BuildAck(seqNum uint32) []byte {
	return buildControlSequence(IDAck, seqNum)
}

// BuildNack requests immediate retransmission of a missing sequence.
func BuildNack(seqNum uint32) []byte {
	return buildControlSequence(IDNack, seqNum)
}

func buildControlSequence(packetID byte, seqNum uint32) []byte {
	var buf bytes.Buffer
	buf.WriteByte(packetID)
	// Record count
	binary.Write(&buf, binary.BigEndian, uint16(1))
	// Single range (not range)
	buf.WriteByte(0x01) // single
	// Sequence (24-bit LE)
	buf.WriteByte(byte(seqNum))
	buf.WriteByte(byte(seqNum >> 8))
	buf.WriteByte(byte(seqNum >> 16))
	return buf.Bytes()
}

func AckContainsSequence(data []byte, seqNum uint32) bool {
	if len(data) < 3 || data[0] != IDAck {
		return false
	}
	sequences, ok := ParseControlSequences(data, 4096)
	if !ok {
		return false
	}
	seqNum &= 0xFFFFFF
	for _, sequence := range sequences {
		if sequence == seqNum {
			return true
		}
	}
	return false
}

// ParseControlSequences expands ACK/NACK records with a caller-provided bound.
func ParseControlSequences(data []byte, maxSequences int) ([]uint32, bool) {
	if len(data) < 3 || (data[0] != IDAck && data[0] != IDNack) || maxSequences <= 0 {
		return nil, false
	}
	count := int(binary.BigEndian.Uint16(data[1:3]))
	pos := 3
	sequences := make([]uint32, 0, count)
	for i := 0; i < count; i++ {
		if pos >= len(data) {
			return nil, false
		}
		single := data[pos] != 0
		pos++
		if pos+3 > len(data) {
			return nil, false
		}
		start := uint32(data[pos]) | uint32(data[pos+1])<<8 | uint32(data[pos+2])<<16
		pos += 3
		if single {
			if len(sequences) >= maxSequences {
				return nil, false
			}
			sequences = append(sequences, start)
			continue
		}
		if pos+3 > len(data) {
			return nil, false
		}
		end := uint32(data[pos]) | uint32(data[pos+1])<<8 | uint32(data[pos+2])<<16
		pos += 3
		if end < start || uint64(end-start)+1 > uint64(maxSequences-len(sequences)) {
			return nil, false
		}
		for sequence := start; sequence <= end; sequence++ {
			sequences = append(sequences, sequence)
		}
	}
	return sequences, pos == len(data)
}

// Timestamp returns current time in milliseconds
func Timestamp() int64 {
	return time.Now().UnixMilli()
}

func writeAddress(buf *bytes.Buffer, addr *net.UDPAddr) {
	ip4 := addr.IP.To4()
	if ip4 != nil {
		buf.WriteByte(0x04) // IPv4
		// RakNet inverts IP bytes
		buf.WriteByte(^ip4[0])
		buf.WriteByte(^ip4[1])
		buf.WriteByte(^ip4[2])
		buf.WriteByte(^ip4[3])
		binary.Write(buf, binary.BigEndian, uint16(addr.Port))
	} else {
		buf.WriteByte(0x06)                             // IPv6
		binary.Write(buf, binary.BigEndian, uint16(23)) // AF_INET6
		binary.Write(buf, binary.BigEndian, uint16(addr.Port))
		binary.Write(buf, binary.BigEndian, uint32(0)) // flow info
		buf.Write(addr.IP.To16())
		binary.Write(buf, binary.BigEndian, uint32(0)) // scope id
	}
}

func readAddress(data []byte) (*net.UDPAddr, int) {
	if len(data) < 1 {
		return nil, 0
	}
	switch data[0] {
	case 0x04:
		if len(data) < 7 {
			return nil, 0
		}
		ip := net.IPv4(^data[1], ^data[2], ^data[3], ^data[4])
		port := binary.BigEndian.Uint16(data[5:7])
		return &net.UDPAddr{IP: ip, Port: int(port)}, 7
	case 0x06:
		if len(data) < 25 {
			return nil, 0
		}
		port := binary.BigEndian.Uint16(data[3:5])
		ip := make(net.IP, 16)
		copy(ip, data[9:25])
		return &net.UDPAddr{IP: ip, Port: int(port)}, 25
	}
	return nil, 0
}
