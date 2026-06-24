//go:build windows

package main

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"relay/proto"
	"relay/tcpip"

	divert "github.com/imgk/divert-go"
)

// faketcpClient sends/receives our frames as raw TCP-shaped packets via
// WinDivert, so networks that block UDP but allow TCP still pass them.
//
// It does NOT implement real TCP: no retransmission, no ordering, no
// congestion control. Just a believable 3-way handshake plus plausibly
// advancing seq/ack so stateful firewalls accept the flow. Each frame is a
// single PSH|ACK segment, fire-and-forget (UDP semantics on the wire as TCP).
//
// Inbound packets from the relay are captured (and consumed) by our own
// WinDivert handle, so the Windows kernel never sees them and never sends a
// RST that would tear the fake connection down.
type faketcpClient struct {
	h         *divert.Handle
	localIP   net.IP
	relayIP   net.IP
	localPort uint16
	relayPort uint16
	getIface  ifaceProvider

	mu          sync.Mutex
	synSeq      uint32 // fixed seq used for (retransmitted) SYN
	ourSeq      uint32 // our data seq (after handshake)
	theirSeq    uint32 // next expected seq from relay (our ack)
	established bool

	estCh      chan struct{}
	estOnce    sync.Once
	incoming   chan *[]byte // pooled payload buffers
	pendingAck atomic.Bool  // a data ACK is due (coalesced by ackLoop)
}

// ifaceProvider returns the current default outbound interface indices,
// learned from the game-capture handle. ok is false until known.
type ifaceProvider func() (ifIdx, subIfIdx uint32, ok bool)

var errNoIface = errors.New("faketcp: outbound interface not known yet")

func newFaketcpClient(relayIP net.IP, relayPort uint16, getIface ifaceProvider) (*faketcpClient, error) {
	// Discover our source IP toward the relay.
	probe, err := net.Dial("udp", fmt.Sprintf("%s:%d", relayIP, relayPort))
	if err != nil {
		return nil, err
	}
	localIP := probe.LocalAddr().(*net.UDPAddr).IP.To4()
	probe.Close()
	if localIP == nil {
		return nil, errors.New("faketcp: could not determine local IPv4")
	}

	localPort := uint16(40000 + rand.Intn(20000))
	// Capture inbound TCP from the relay to our chosen port; consume it so
	// the kernel never RSTs. Slightly higher priority keeps it ahead.
	filter := fmt.Sprintf("inbound and tcp and ip.SrcAddr == %s and tcp.SrcPort == %d and tcp.DstPort == %d",
		relayIP, relayPort, localPort)
	h, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault+1, divert.FlagDefault)
	if err != nil {
		return nil, err
	}

	t := &faketcpClient{
		h:         h,
		localIP:   localIP,
		relayIP:   relayIP,
		localPort: localPort,
		relayPort: relayPort,
		getIface:  getIface,
		synSeq:    rand.Uint32(),
		estCh:     make(chan struct{}),
		incoming:  make(chan *[]byte, 8192),
	}
	go t.readLoop()
	go t.handshakeLoop()
	go t.ackLoop()
	return t, nil
}

// inject builds and sends one outbound TCP-shaped packet.
func (t *faketcpClient) inject(seq, ack uint32, flags uint8, payload []byte) error {
	ifIdx, subIfIdx, ok := t.getIface()
	if !ok {
		return errNoIface
	}
	raw := tcpip.Build(t.localIP, t.relayIP, t.localPort, t.relayPort, seq, ack, flags, 65535, payload)

	var a divert.Address
	a.SetLayer(divert.LayerNetwork)
	a.SetEvent(divert.EventNetworkPacket)
	a.Flags = flagIPChecksum | flagTCPChecksum // outbound (Outbound bit kept 0 -> set below)
	a.Flags |= flagOutbound
	ne := a.Network()
	ne.InterfaceIndex = ifIdx
	ne.SubInterfaceIndex = subIfIdx

	_, err := t.h.Send(raw, &a)
	return err
}

// handshakeLoop retransmits SYN until the relay completes the handshake.
func (t *faketcpClient) handshakeLoop() {
	for {
		t.mu.Lock()
		est := t.established
		t.mu.Unlock()
		if est {
			return
		}
		_ = t.inject(t.synSeq, 0, tcpip.FlagSYN, nil) // ignore err (iface may be pending)
		time.Sleep(300 * time.Millisecond)
	}
}

func (t *faketcpClient) markEstablished() {
	t.mu.Lock()
	t.established = true
	t.mu.Unlock()
	t.estOnce.Do(func() { close(t.estCh) })
}

func (t *faketcpClient) readLoop() {
	buf := make([]byte, 65535)
	var addr divert.Address
	for {
		n, err := t.h.Recv(buf, &addr)
		if err != nil {
			continue
		}
		seg, ok := tcpip.Parse(buf[:n])
		if !ok {
			continue
		}
		switch {
		case seg.Flags&tcpip.FlagRST != 0:
			// Ignore; firewall/relay reset. handshakeLoop keeps trying.
			continue
		case seg.Flags&tcpip.FlagSYN != 0 && seg.Flags&tcpip.FlagACK != 0:
			// SYN-ACK. If we're already established, a duplicate SYN-ACK
			// must NOT rewind our sequence numbers (that would corrupt a
			// live session). Just re-ACK so the relay stops resending.
			t.mu.Lock()
			if t.established {
				seq := t.ourSeq
				ack := t.theirSeq
				t.mu.Unlock()
				_ = t.inject(seq, ack, tcpip.FlagACK, nil)
				continue
			}
			t.theirSeq = seg.Seq + 1
			t.ourSeq = t.synSeq + 1
			ack := t.theirSeq
			seq := t.ourSeq
			t.mu.Unlock()
			_ = t.inject(seq, ack, tcpip.FlagACK, nil)
			t.markEstablished()
		default:
			if len(seg.Payload) > 0 {
				t.mu.Lock()
				if !t.established {
					t.ourSeq = t.synSeq + 1
				}
				// Advance our ack only on forward progress (tolerate reorder).
				next := seg.Seq + uint32(len(seg.Payload))
				if tcpip.SeqGT(next, t.theirSeq) {
					t.theirSeq = next
				}
				t.mu.Unlock()
				// Coalesce ACKs: mark one due; ackLoop sends a single ACK
				// per tick instead of one per packet (less handle contention).
				t.pendingAck.Store(true)

				pb := proto.GetBuf()
				*pb = append((*pb)[:0], seg.Payload...)
				select {
				case t.incoming <- pb:
				default: // drop if backed up
					proto.PutBuf(pb)
				}
				t.markEstablished()
			}
		}
	}
}

func (t *faketcpClient) Send(frame []byte) error {
	// Wait (briefly) for the handshake on the first frames.
	t.mu.Lock()
	est := t.established
	t.mu.Unlock()
	if !est {
		select {
		case <-t.estCh:
		case <-time.After(2 * time.Second):
			// proceed anyway; some firewalls accept data mid-handshake
		}
	}

	t.mu.Lock()
	seq := t.ourSeq
	ack := t.theirSeq
	t.ourSeq += uint32(len(frame))
	t.mu.Unlock()
	return t.inject(seq, ack, tcpip.FlagPSH|tcpip.FlagACK, frame)
}

func (t *faketcpClient) Recv(buf []byte) (int, error) {
	pb, ok := <-t.incoming
	if !ok {
		return 0, errors.New("faketcp: closed")
	}
	n := copy(buf, *pb)
	proto.PutBuf(pb)
	return n, nil
}

// ackLoop sends at most one coalesced ACK per tick when data has arrived,
// instead of acking every packet (which would hammer the WinDivert handle).
func (t *faketcpClient) ackLoop() {
	tk := time.NewTicker(10 * time.Millisecond)
	defer tk.Stop()
	for range tk.C {
		if !t.pendingAck.CompareAndSwap(true, false) {
			continue
		}
		t.mu.Lock()
		seq := t.ourSeq
		ack := t.theirSeq
		t.mu.Unlock()
		_ = t.inject(seq, ack, tcpip.FlagACK, nil)
	}
}

func (t *faketcpClient) Close() error {
	return t.h.Close()
}
