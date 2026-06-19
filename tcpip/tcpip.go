// Package tcpip builds and parses raw IPv4+TCP packets for the "fake-TCP"
// transport. These packets carry real TCP headers (so UDP-blocking firewalls
// let them through) but we drive them ourselves with datagram semantics:
// fire-and-forget, no retransmission, no in-order delivery, no head-of-line
// blocking. The TCP header is a costume, not a reliability layer.
package tcpip

import (
	"encoding/binary"
	"net"
)

// TCP flag bits.
const (
	FlagFIN = 1 << 0
	FlagSYN = 1 << 1
	FlagRST = 1 << 2
	FlagPSH = 1 << 3
	FlagACK = 1 << 4
)

const (
	ipHdrLen  = 20
	tcpHdrLen = 20
)

// Segment is a parsed IPv4+TCP packet.
type Segment struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8
	Window  uint16
	Payload []byte
}

// Build assembles a full IPv4+TCP packet (with valid checksums) carrying
// payload. No TCP options are emitted (header is a fixed 20 bytes).
func Build(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16, payload []byte) []byte {
	total := ipHdrLen + tcpHdrLen + len(payload)
	b := make([]byte, total)

	// --- IPv4 header ---
	b[0] = 0x45 // version 4, IHL 5
	b[1] = 0x00
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[4:6], 0)      // id
	binary.BigEndian.PutUint16(b[6:8], 0x4000) // don't fragment
	b[8] = 64                                  // TTL
	b[9] = 6                                   // protocol = TCP
	copy(b[12:16], srcIP.To4())
	copy(b[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(b[10:12], checksum(b[:ipHdrLen]))

	// --- TCP header ---
	t := b[ipHdrLen:]
	binary.BigEndian.PutUint16(t[0:2], srcPort)
	binary.BigEndian.PutUint16(t[2:4], dstPort)
	binary.BigEndian.PutUint32(t[4:8], seq)
	binary.BigEndian.PutUint32(t[8:12], ack)
	t[12] = 5 << 4 // data offset = 5 words, reserved 0
	t[13] = flags
	binary.BigEndian.PutUint16(t[14:16], window)
	binary.BigEndian.PutUint16(t[16:18], 0) // checksum placeholder
	binary.BigEndian.PutUint16(t[18:20], 0) // urgent pointer

	copy(t[tcpHdrLen:], payload)
	binary.BigEndian.PutUint16(t[16:18], tcpChecksum(srcIP, dstIP, t[:tcpHdrLen+len(payload)]))
	return b
}

// Parse decodes a full IPv4+TCP packet. ok is false if the buffer is too
// short or not IPv4/TCP. Payload aliases raw.
func Parse(raw []byte) (Segment, bool) {
	var s Segment
	if len(raw) < ipHdrLen {
		return s, false
	}
	if raw[0]>>4 != 4 || raw[9] != 6 {
		return s, false // not IPv4 or not TCP
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl < ipHdrLen || len(raw) < ihl+tcpHdrLen {
		return s, false
	}
	s.SrcIP = net.IPv4(raw[12], raw[13], raw[14], raw[15])
	s.DstIP = net.IPv4(raw[16], raw[17], raw[18], raw[19])

	t := raw[ihl:]
	dataOff := int(t[12]>>4) * 4
	if dataOff < tcpHdrLen || len(t) < dataOff {
		return s, false
	}
	s.SrcPort = binary.BigEndian.Uint16(t[0:2])
	s.DstPort = binary.BigEndian.Uint16(t[2:4])
	s.Seq = binary.BigEndian.Uint32(t[4:8])
	s.Ack = binary.BigEndian.Uint32(t[8:12])
	s.Flags = t[13]
	s.Window = binary.BigEndian.Uint16(t[14:16])
	s.Payload = t[dataOff:]
	return s, true
}

// checksum is the standard one's-complement IP checksum.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum over the pseudo-header + segment.
func tcpChecksum(srcIP, dstIP net.IP, seg []byte) uint16 {
	s := srcIP.To4()
	d := dstIP.To4()
	var sum uint32
	sum += uint32(s[0])<<8 | uint32(s[1])
	sum += uint32(s[2])<<8 | uint32(s[3])
	sum += uint32(d[0])<<8 | uint32(d[1])
	sum += 6 // protocol
	sum += uint32(len(seg))
	for i := 0; i+1 < len(seg); i += 2 {
		sum += uint32(seg[i])<<8 | uint32(seg[i+1])
	}
	if len(seg)%2 == 1 {
		sum += uint32(seg[len(seg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
