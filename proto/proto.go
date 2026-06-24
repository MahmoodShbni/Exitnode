// Package proto defines the lightweight encapsulation used between the
// Windows client and the Linux relay. There is NO encryption and NO
// handshake on purpose — only the few bytes needed to route packets and
// drop duplicates. Overhead is ~15 bytes per packet.
package proto

import (
	"errors"
	"net"
)

// Magic marks our packets so the relay can ignore stray UDP noise.
const Magic uint16 = 0xE1A6

var (
	errShort = errors.New("proto: packet too short")
	errMagic = errors.New("proto: bad magic")
)

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

	addrBuf [4]byte // backing array for Addr in DecodeInto (avoids alloc)
}

// Encode serializes p into a freshly allocated buffer.
func Encode(p *Packet) []byte {
	return EncodeInto(make([]byte, HeaderSize+len(p.Payload)), p)
}

// Decode parses a buffer into a freshly allocated Packet. The returned
// Payload aliases the input slice.
func Decode(buf []byte) (*Packet, error) {
	p := &Packet{}
	if err := DecodeInto(buf, p); err != nil {
		return nil, err
	}
	return p, nil
}
