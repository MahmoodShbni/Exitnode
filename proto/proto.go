// Package proto defines the lightweight encapsulation used between the
// Windows client and the Linux relay. There is NO encryption and NO
// handshake on purpose — only the few bytes needed to route packets and
// drop duplicates. Overhead is ~15 bytes per packet.
package proto

import (
	"encoding/binary"
	"errors"
	"net"
)

// Magic marks our packets so the relay can ignore stray UDP noise.
const Magic uint16 = 0xE1A6

// Flags
const (
	FlagData byte = 0x01
)

// HeaderSize is the fixed header length in bytes.
//
//	magic(2) | flags(1) | seq(4) | ip(4) | port(2) | localPort(2) = 15
const HeaderSize = 15

// Packet is a decoded encapsulated message.
//
// Outbound (client -> relay):
//   - Addr/Port   = final game-server destination (e.g. the CS2 server)
//   - LocalPort   = the client's original source UDP port (flow id)
//
// Inbound (relay -> client):
//   - Addr/Port   = the game server the reply came from
//   - LocalPort   = which client flow this reply belongs to
type Packet struct {
	Flags     byte
	Seq       uint32
	Addr      net.IP
	Port      uint16
	LocalPort uint16
	Payload   []byte
}

// Encode serializes p into a freshly allocated buffer.
func Encode(p *Packet) []byte {
	buf := make([]byte, HeaderSize+len(p.Payload))
	binary.BigEndian.PutUint16(buf[0:2], Magic)
	buf[2] = p.Flags
	binary.BigEndian.PutUint32(buf[3:7], p.Seq)
	ip4 := p.Addr.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}
	copy(buf[7:11], ip4)
	binary.BigEndian.PutUint16(buf[11:13], p.Port)
	binary.BigEndian.PutUint16(buf[13:15], p.LocalPort)
	copy(buf[HeaderSize:], p.Payload)
	return buf
}

// Decode parses a buffer. The returned Payload aliases the input slice,
// so copy it if you need to retain it past the next read.
func Decode(buf []byte) (*Packet, error) {
	if len(buf) < HeaderSize {
		return nil, errors.New("proto: packet too short")
	}
	if binary.BigEndian.Uint16(buf[0:2]) != Magic {
		return nil, errors.New("proto: bad magic")
	}
	return &Packet{
		Flags:     buf[2],
		Seq:       binary.BigEndian.Uint32(buf[3:7]),
		Addr:      net.IPv4(buf[7], buf[8], buf[9], buf[10]),
		Port:      binary.BigEndian.Uint16(buf[11:13]),
		LocalPort: binary.BigEndian.Uint16(buf[13:15]),
		Payload:   buf[HeaderSize:],
	}, nil
}
