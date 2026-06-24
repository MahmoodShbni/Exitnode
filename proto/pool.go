package proto

import (
	"encoding/binary"
	"net"
	"sync"
)

// bufPool recycles packet-sized byte buffers so the per-packet hot path does
// not allocate (which would create GC pressure → latency jitter). Buffers are
// stored by pointer to avoid an allocation on Put.
var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 65535)
		return &b
	},
}

// GetBuf returns a recycled buffer (len 0, cap 65535).
func GetBuf() *[]byte { return bufPool.Get().(*[]byte) }

// PutBuf returns a buffer to the pool. Do not use it afterwards.
func PutBuf(b *[]byte) {
	*b = (*b)[:0]
	bufPool.Put(b)
}

// EncodeInto serializes p into dst (reusing its backing array when it is big
// enough) and returns the filled slice. Pair with GetBuf/PutBuf to avoid
// allocations.
func EncodeInto(dst []byte, p *Packet) []byte {
	need := HeaderSize + len(p.Payload)
	if cap(dst) < need {
		dst = make([]byte, need)
	} else {
		dst = dst[:need]
	}
	binary.BigEndian.PutUint16(dst[0:2], Magic)
	dst[2] = p.Flags
	binary.BigEndian.PutUint32(dst[3:7], p.Seq)
	ip4 := p.Addr.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}
	copy(dst[7:11], ip4)
	binary.BigEndian.PutUint16(dst[11:13], p.Port)
	binary.BigEndian.PutUint16(dst[13:15], p.LocalPort)
	copy(dst[HeaderSize:], p.Payload)
	return dst
}

// DecodeInto parses buf into the caller-provided Packet (no allocation).
// Packet.Addr is written into p.addrBuf to avoid allocating a net.IP, and
// Payload aliases buf.
func DecodeInto(buf []byte, p *Packet) error {
	if len(buf) < HeaderSize {
		return errShort
	}
	if binary.BigEndian.Uint16(buf[0:2]) != Magic {
		return errMagic
	}
	p.Flags = buf[2]
	p.Seq = binary.BigEndian.Uint32(buf[3:7])
	p.addrBuf = [4]byte{buf[7], buf[8], buf[9], buf[10]}
	p.Addr = p.addrBuf[:]
	p.Port = binary.BigEndian.Uint16(buf[11:13])
	p.LocalPort = binary.BigEndian.Uint16(buf[13:15])
	p.Payload = buf[HeaderSize:]
	return nil
}
