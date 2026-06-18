package proto

import "sync"

// Dedup drops packets whose sequence number has already been seen.
// It keeps the last `size` sequence numbers in a ring; anything older
// than the ring is treated as new again (acceptable for a live stream
// where old packets are useless anyway).
//
// This is the heart of redundancy: send each packet N times, the first
// copy to arrive is forwarded, the rest are dropped here.
type Dedup struct {
	mu   sync.Mutex
	size int
	seen map[uint32]struct{}
	ring []uint32
	pos  int
	full bool
}

// NewDedup creates a window of the given size. 4096 is a sane default
// for fast-paced UDP traffic.
func NewDedup(size int) *Dedup {
	if size <= 0 {
		size = 4096
	}
	return &Dedup{
		size: size,
		seen: make(map[uint32]struct{}, size),
		ring: make([]uint32, size),
	}
}

// Seen records seq and reports whether it was already present.
// true  => duplicate, caller should drop the packet.
// false => first time, caller should process it.
func (d *Dedup) Seen(seq uint32) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.seen[seq]; ok {
		return true
	}

	// Evict the slot we are about to overwrite.
	if d.full {
		delete(d.seen, d.ring[d.pos])
	}
	d.ring[d.pos] = seq
	d.seen[seq] = struct{}{}
	d.pos++
	if d.pos == d.size {
		d.pos = 0
		d.full = true
	}
	return false
}
