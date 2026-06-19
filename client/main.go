//go:build windows

// Command relay-client is the Windows side. It uses WinDivert 2.x (via the
// imgk/divert-go binding) to grab the game's outbound UDP, tunnel it through
// your relay, and re-inject the replies so the game thinks they came straight
// from the server. TCP and every other process keep their normal path.
//
// Two mutually exclusive selection modes (pick exactly one):
//
//	-game <IP>      capture UDP destined to this game-server IP
//	-proc <name>    capture UDP owned by this process, e.g. cs2.exe
//
// Requirements next to the .exe (from the official WinDivert 2.2 release):
//   - WinDivert.dll
//   - WinDivert64.sys
//
// Run as Administrator.
//
// Build:
//
//	GOOS=windows GOARCH=amd64 go build -o relay-client.exe ./client
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"relay/proto"

	divert "github.com/imgk/divert-go"
)

// WinDivert 2.x address Flags bit layout (one byte).
const (
	flagSniffed     = 1 << 0
	flagOutbound    = 1 << 1
	flagLoopback    = 1 << 2
	flagImpostor    = 1 << 3
	flagIPv6        = 1 << 4
	flagIPChecksum  = 1 << 5
	flagTCPChecksum = 1 << 6
	flagUDPChecksum = 1 << 7
)

var (
	relayAddr  = flag.String("relay", "", "relay server address host:port (required)")
	gameIP     = flag.String("game", "", "IP mode: game server IP to capture, e.g. 1.2.3.4")
	procName   = flag.String("proc", "", "process mode: executable name to capture, e.g. cs2.exe")
	protocol   = flag.String("protocol", "udp", "client<->relay transport: udp | faketcp")
	redundancy = flag.Int("redundancy", 2, "send each game packet this many times to the relay")
	dedupSize  = flag.Int("dedup", 4096, "duplicate-detection window for replies")
)

// lastIface holds the most recent default outbound interface indices learned
// from the game-capture handle, packed as (ifIdx<<32 | subIfIdx) plus a valid
// bit. fake-TCP needs these to inject its outbound packets.
var lastIface struct {
	val   atomic.Uint64
	valid atomic.Bool
}

func storeIface(ifIdx, subIfIdx uint32) {
	lastIface.val.Store(uint64(ifIdx)<<32 | uint64(subIfIdx))
	lastIface.valid.Store(true)
}

func currentIface() (ifIdx, subIfIdx uint32, ok bool) {
	if !lastIface.valid.Load() {
		return 0, 0, false
	}
	v := lastIface.val.Load()
	return uint32(v >> 32), uint32(v), true
}

// flowTemplate remembers the addressing of an outbound packet so we can
// reconstruct the matching inbound packet for re-injection.
type flowTemplate struct {
	localIP   net.IP
	localPort uint16
	gameIP    net.IP // actual destination seen on the wire
	gamePort  uint16
	ifIdx     uint32
	subIfIdx  uint32
}

var (
	seqCounter uint32
	tmplMu     sync.RWMutex
	templates  = map[uint16]*flowTemplate{} // keyed by local source port
)

func main() {
	flag.Parse()
	if *relayAddr == "" {
		log.Fatal("missing -relay host:port")
	}
	// Exactly one of -game / -proc.
	switch {
	case *gameIP == "" && *procName == "":
		log.Fatal("choose a mode: either -game <ip> or -proc <name>")
	case *gameIP != "" && *procName != "":
		log.Fatal("-game and -proc are mutually exclusive; pick one")
	}

	raddr, err := net.ResolveUDPAddr("udp", *relayAddr)
	if err != nil {
		log.Fatalf("resolve relay: %v", err)
	}

	// Pick the client<->relay transport.
	var transport relayTransport
	switch *protocol {
	case "udp":
		transport, err = newUDPTransport(raddr)
	case "faketcp":
		transport, err = newFaketcpClient(raddr.IP.To4(), uint16(raddr.Port), currentIface)
	default:
		log.Fatalf("invalid -protocol %q (use udp or faketcp)", *protocol)
	}
	if err != nil {
		log.Fatalf("open %s transport: %v", *protocol, err)
	}
	defer transport.Close()

	// Build the capture filter and the per-packet relay decision.
	var filter string
	var decide func(srcPort uint16) bool

	if *gameIP != "" {
		gIP := net.ParseIP(*gameIP).To4()
		if gIP == nil {
			log.Fatal("invalid -game IP (IPv4 only)")
		}
		// Filter already restricts to the game IP, so always relay.
		filter = fmt.Sprintf("outbound and udp and ip.DstAddr == %s", *gameIP)
		decide = func(uint16) bool { return true }
		log.Printf("IP mode: relaying UDP to %s via %s (%s, redundancy=%d)", *gameIP, *relayAddr, *protocol, *redundancy)
	} else {
		// Process mode: capture ALL outbound UDP, then relay only the
		// target process's ports. Our own tunnel packets to the relay are
		// captured too, but decide() returns false for them (they aren't
		// owned by the target process) so they're passed straight through.
		filter = "outbound and udp"
		tracker := newProcTracker(*procName)
		go tracker.run()
		decide = tracker.Has
		log.Printf("process mode: relaying UDP of %q via %s (%s, redundancy=%d)", *procName, *relayAddr, *protocol, *redundancy)
	}

	h, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Fatalf("open WinDivert (run as Administrator? WinDivert 2.x dll/sys present?): %v", err)
	}
	defer h.Close()

	dedup := proto.NewDedup(*dedupSize)
	go replyLoop(h, transport, dedup)
	captureLoop(h, transport, decide)
}

// captureLoop reads outbound UDP. Packets the decider accepts are tunneled
// to the relay; everything else is re-injected unchanged (pass-through).
func captureLoop(h *divert.Handle, transport relayTransport, decide func(uint16) bool) {
	buf := make([]byte, 65535)
	var addr divert.Address
	for {
		n, err := h.Recv(buf, &addr)
		if err != nil {
			log.Printf("recv: %v", err)
			continue
		}
		raw := buf[:n]
		ihl := int(raw[0]&0x0f) * 4
		if len(raw) < ihl+8 {
			_, _ = h.Send(raw, &addr) // malformed/short: pass through
			continue
		}
		srcPort := binary.BigEndian.Uint16(raw[ihl : ihl+2])

		// Record the default outbound interface for fake-TCP injection.
		ne := addr.Network()
		storeIface(ne.InterfaceIndex, ne.SubInterfaceIndex)

		if !decide(srcPort) {
			// Not our target traffic: send it back out untouched.
			if _, err := h.Send(raw, &addr); err != nil {
				log.Printf("passthrough: %v", err)
			}
			continue
		}

		srcIP := net.IPv4(raw[12], raw[13], raw[14], raw[15])
		dstIP := net.IPv4(raw[16], raw[17], raw[18], raw[19])
		dstPort := binary.BigEndian.Uint16(raw[ihl+2 : ihl+4])
		payload := raw[ihl+8:]

		tmplMu.Lock()
		templates[srcPort] = &flowTemplate{
			localIP:   srcIP,
			localPort: srcPort,
			gameIP:    dstIP,
			gamePort:  dstPort,
			ifIdx:     ne.InterfaceIndex,
			subIfIdx:  ne.SubInterfaceIndex,
		}
		tmplMu.Unlock()

		seq := atomic.AddUint32(&seqCounter, 1)
		enc := proto.Encode(&proto.Packet{
			Flags:     proto.FlagData,
			Seq:       seq,
			Addr:      dstIP,
			Port:      dstPort,
			LocalPort: srcPort,
			Payload:   payload,
		})
		for i := 0; i < *redundancy; i++ {
			if err := transport.Send(enc); err != nil {
				log.Printf("to relay: %v", err)
				break
			}
		}
		// Original is dropped (not re-sent): the relay delivers it.
	}
}

// replyLoop reads encapsulated replies and injects them as inbound.
func replyLoop(h *divert.Handle, transport relayTransport, dedup *proto.Dedup) {
	buf := make([]byte, 65535)
	for {
		n, err := transport.Recv(buf)
		if err != nil {
			log.Printf("from relay: %v", err)
			continue
		}
		pkt, err := proto.Decode(buf[:n])
		if err != nil {
			continue
		}
		if dedup.Seen(pkt.Seq) {
			continue
		}

		tmplMu.RLock()
		tmpl := templates[pkt.LocalPort]
		tmplMu.RUnlock()
		if tmpl == nil {
			continue
		}

		raw := buildInbound(tmpl, pkt.Payload)

		var a divert.Address
		a.SetLayer(divert.LayerNetwork)
		a.SetEvent(divert.EventNetworkPacket)
		// Inbound (Outbound bit cleared); checksums are valid in-packet.
		a.Flags = flagIPChecksum | flagUDPChecksum
		ne := a.Network()
		ne.InterfaceIndex = tmpl.ifIdx
		ne.SubInterfaceIndex = tmpl.subIfIdx

		if _, err := h.Send(raw, &a); err != nil {
			log.Printf("inject: %v", err)
		}
	}
}

// buildInbound crafts an IPv4+UDP packet that looks like it came FROM the
// game server TO the local client, carrying payload, with valid checksums.
func buildInbound(t *flowTemplate, payload []byte) []byte {
	const ihl = 20
	udpLen := 8 + len(payload)
	total := ihl + udpLen
	b := make([]byte, total)

	// IPv4 header
	b[0] = 0x45
	b[1] = 0x00
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[4:6], 0)
	binary.BigEndian.PutUint16(b[6:8], 0)
	b[8] = 64                       // TTL
	b[9] = 17                       // UDP
	copy(b[12:16], t.gameIP.To4())  // src = game server
	copy(b[16:20], t.localIP.To4()) // dst = local
	binary.BigEndian.PutUint16(b[10:12], ipChecksum(b[:ihl]))

	// UDP header
	binary.BigEndian.PutUint16(b[20:22], t.gamePort)
	binary.BigEndian.PutUint16(b[22:24], t.localPort)
	binary.BigEndian.PutUint16(b[24:26], uint16(udpLen))
	binary.BigEndian.PutUint16(b[26:28], 0) // checksum placeholder
	copy(b[28:], payload)

	csum := udpChecksum(t.gameIP, t.localIP, b[20:])
	binary.BigEndian.PutUint16(b[26:28], csum)
	return b
}

func ipChecksum(h []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(h); i += 2 {
		sum += uint32(h[i])<<8 | uint32(h[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udpChecksum computes the UDP checksum over the pseudo-header + udp segment.
func udpChecksum(srcIP, dstIP net.IP, udp []byte) uint16 {
	s := srcIP.To4()
	d := dstIP.To4()
	var sum uint32
	sum += uint32(s[0])<<8 | uint32(s[1])
	sum += uint32(s[2])<<8 | uint32(s[3])
	sum += uint32(d[0])<<8 | uint32(d[1])
	sum += uint32(d[2])<<8 | uint32(d[3])
	sum += uint32(17)
	sum += uint32(len(udp))
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(udp[i])<<8 | uint32(udp[i+1])
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	c := ^uint16(sum)
	if c == 0 {
		c = 0xffff
	}
	return c
}
