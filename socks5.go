package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	Version5 = 0x05

	AuthNone     = 0x00
	AuthPassword = 0x02
	AuthNoAccept = 0xFF

	CmdConnect      = 0x01
	CmdUDPAssociate = 0x03

	AtypIPv4   = 0x01
	AtypDomain = 0x03
	AtypIPv6   = 0x04

	RepSuccess          = 0x00
	RepGeneralFailure   = 0x01
	RepNotAllowed       = 0x02
	RepNetworkUnreach   = 0x03
	RepHostUnreach      = 0x04
	RepConnRefused      = 0x05
	RepTTLExpired       = 0x06
	RepCmdNotSupported  = 0x07
	RepAddrNotSupported = 0x08
)

type Request struct {
	Command  byte
	DestAddr string
	DestPort uint16
}

type AuthConfig struct {
	Username string
	Password string
}

type HandshakeOptions struct {
	Auth     AuthConfig
	AllowUDP bool
}

func Handshake(conn io.ReadWriter) (*Request, error) {
	return HandshakeWithAuth(conn, AuthConfig{})
}

func HandshakeWithAuth(conn io.ReadWriter, auth AuthConfig) (*Request, error) {
	return HandshakeWithOptions(conn, HandshakeOptions{Auth: auth})
}

func HandshakeWithOptions(conn io.ReadWriter, options HandshakeOptions) (*Request, error) {
	// Read version and auth methods
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != Version5 {
		return nil, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, err
	}

	// Select authentication method
	requireAuth := options.Auth.Username != "" || options.Auth.Password != ""
	selected := byte(AuthNone)
	if requireAuth {
		selected = AuthNoAccept
		for _, m := range methods {
			if m == AuthPassword {
				selected = AuthPassword
				break
			}
		}
	} else {
		selected = AuthNone
	}

	if _, err := conn.Write([]byte{Version5, selected}); err != nil {
		return nil, err
	}
	if selected == AuthNoAccept {
		return nil, errors.New("no acceptable auth method")
	}

	if selected == AuthPassword {
		if err := handlePasswordAuth(conn, options.Auth); err != nil {
			return nil, err
		}
	}

	// Read connect request
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return nil, err
	}
	if reqHeader[0] != Version5 {
		return nil, errors.New("invalid SOCKS5 request version")
	}
	if reqHeader[1] != CmdConnect && !(options.AllowUDP && reqHeader[1] == CmdUDPAssociate) {
		sendReply(conn, RepCmdNotSupported)
		return nil, fmt.Errorf("unsupported command: %d", reqHeader[1])
	}

	var destAddr string
	switch reqHeader[3] {
	case AtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		destAddr = net.IP(addr).String()
	case AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		destAddr = string(domain)
	case AtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		destAddr = net.IP(addr).String()
	default:
		sendReply(conn, RepAddrNotSupported)
		return nil, fmt.Errorf("unsupported address type: %d", reqHeader[3])
	}

	var port uint16
	if err := binary.Read(conn, binary.BigEndian, &port); err != nil {
		return nil, err
	}

	return &Request{Command: reqHeader[1], DestAddr: destAddr, DestPort: port}, nil
}

func handlePasswordAuth(conn io.ReadWriter, auth AuthConfig) error {
	// RFC 1929: VER(1)=0x01 ULEN(1) UNAME PLEN(1) PASSWD
	h := make([]byte, 2)
	if _, err := io.ReadFull(conn, h); err != nil {
		return err
	}
	if h[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return errors.New("invalid auth version")
	}
	uLen := int(h[1])
	uname := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		return err
	}
	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return err
	}
	pLen := int(pLenBuf[0])
	pass := make([]byte, pLen)
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	if string(uname) != auth.Username || string(pass) != auth.Password {
		conn.Write([]byte{0x01, 0x01})
		return errors.New("socks authentication failed")
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func SendSuccess(conn io.Writer, bindAddr string, bindPort uint16) error {
	return sendReplyFull(conn, RepSuccess, bindAddr, bindPort)
}

func SendFailure(conn io.Writer, rep byte) error {
	return sendReply(conn, rep)
}

func sendReply(conn io.Writer, rep byte) error {
	reply := []byte{Version5, rep, 0x00, AtypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

func sendReplyFull(conn io.Writer, rep byte, addr string, port uint16) error {
	reply := []byte{Version5, rep, 0x00, AtypIPv4}
	ip := net.ParseIP(addr)
	if ip != nil && ip.To4() != nil {
		reply = append(reply, ip.To4()...)
	} else {
		reply = append(reply, 0, 0, 0, 0)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	reply = append(reply, portBuf...)
	_, err := conn.Write(reply)
	return err
}

func EncodeAddress(addr string, port uint16) []byte {
	ip := net.ParseIP(addr)
	var buf []byte
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, AtypIPv4)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, AtypIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		buf = append(buf, AtypDomain)
		buf = append(buf, byte(len(addr)))
		buf = append(buf, []byte(addr)...)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	buf = append(buf, portBuf...)
	return buf
}

func DecodeAddress(data []byte) (string, uint16, int, error) {
	if len(data) < 1 {
		return "", 0, 0, errors.New("empty address data")
	}
	var addr string
	var offset int

	switch data[0] {
	case AtypIPv4:
		if len(data) < 7 {
			return "", 0, 0, errors.New("short IPv4 address")
		}
		addr = net.IP(data[1:5]).String()
		offset = 5
	case AtypDomain:
		if len(data) < 2 {
			return "", 0, 0, errors.New("short domain address")
		}
		dLen := int(data[1])
		if len(data) < 2+dLen+2 {
			return "", 0, 0, errors.New("short domain address")
		}
		addr = string(data[2 : 2+dLen])
		offset = 2 + dLen
	case AtypIPv6:
		if len(data) < 19 {
			return "", 0, 0, errors.New("short IPv6 address")
		}
		addr = net.IP(data[1:17]).String()
		offset = 17
	default:
		return "", 0, 0, fmt.Errorf("unknown address type: %d", data[0])
	}

	port := binary.BigEndian.Uint16(data[offset : offset+2])
	return addr, port, offset + 2, nil
}

func ParseUDPDatagram(data []byte) (string, uint16, []byte, error) {
	if len(data) < 4 {
		return "", 0, nil, errors.New("short UDP datagram")
	}
	if data[0] != 0x00 || data[1] != 0x00 {
		return "", 0, nil, errors.New("invalid UDP datagram reserved bytes")
	}
	if data[2] != 0x00 {
		return "", 0, nil, errors.New("fragmented UDP datagram is not supported")
	}
	addr, port, offset, err := DecodeAddress(data[3:])
	if err != nil {
		return "", 0, nil, err
	}
	return addr, port, data[3+offset:], nil
}

func BuildUDPDatagram(addr string, port uint16, payload []byte) []byte {
	out := make([]byte, 0, 3+1+len(addr)+2+len(payload))
	out = append(out, 0x00, 0x00, 0x00)
	out = append(out, EncodeAddress(addr, port)...)
	out = append(out, payload...)
	return out
}

func FormatAddr(addr string, port uint16) string {
	return net.JoinHostPort(addr, strconv.Itoa(int(port)))
}
