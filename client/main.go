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
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

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
	gameFile   = flag.String("game-file", "", "IP mode: file with one game server IPv4 per line")
	procName   = flag.String("proc", "", "process mode: executable name to capture, e.g. cs2.exe")
	protocol   = flag.String("protocol", "udp", "client<->relay transport: udp | faketcp")
	redundancy = flag.Int("redundancy", 2, "send each game packet this many times to the relay")
	redunDelay = flag.Duration("redundancy-delay", 0, "spacing between redundant copies (e.g. 300us) to survive burst loss")
	dedupSize  = flag.Int("dedup", 4096, "duplicate-detection window for replies")
	sockBuf    = flag.Int("sockbuf", 4<<20, "UDP socket read/write buffer in bytes")
	gogc       = flag.Int("gogc", 100, "GC target percent (higher = fewer GC pauses, more memory)")
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
	// templates is indexed directly by local source port (uint16): O(1),
	// lock-free, zero-allocation lookups on the hot path.
	templates [65536]atomic.Pointer[flowTemplate]
)

// matches reports whether t already describes this flow (so we can skip
// reallocating/storing a template on every packet in steady state).
func (t *flowTemplate) matches(srcIP, dstIP net.IP, dstPort uint16, ifIdx, subIfIdx uint32) bool {
	return t != nil &&
		t.gamePort == dstPort && t.ifIdx == ifIdx && t.subIfIdx == subIfIdx &&
		t.localIP.Equal(srcIP) && t.gameIP.Equal(dstIP)
}

func main() {
	flag.Parse()
	debug.SetGCPercent(*gogc)
	if *relayAddr == "" {
		log.Fatal("missing -relay host:port")
	}
	// Exactly one mode: IP (-game and/or -game-file) OR process (-proc).
	hasGame := *gameIP != "" || *gameFile != ""
	hasProc := *procName != ""
	if hasGame == hasProc {
		log.Fatal("choose exactly one mode: -game <ip> / -game-file <path>, OR -proc <name>")
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
	// decide(srcPort, dstIP) reports whether a captured packet should be
	// relayed (vs passed straight through).
	var filter string
	var decide func(srcPort uint16, dstIP net.IP) bool

	if hasGame {
		set, dotted, err := loadGameIPs(*gameIP, *gameFile)
		if err != nil {
			log.Fatalf("game IPs: %v", err)
		}
		if len(set) == 0 {
			log.Fatal("no valid game IPs given")
		}
		// Small lists: let the kernel pre-filter with an OR of addresses.
		// Large lists: capture all outbound UDP and match in user space
		// (avoids hitting WinDivert's filter-length limits).
		const orFilterMax = 60
		if len(dotted) <= orFilterMax {
			parts := make([]string, len(dotted))
			for i, ip := range dotted {
				parts[i] = "ip.DstAddr == " + ip
			}
			filter = "outbound and udp and (" + strings.Join(parts, " or ") + ")"
		} else {
			filter = "outbound and udp"
		}
		decide = func(_ uint16, dstIP net.IP) bool {
			_, ok := set[ipToU32(dstIP)]
			return ok
		}
		log.Printf("IP mode: relaying UDP to %d server IP(s) via %s (%s, redundancy=%d)",
			len(set), *relayAddr, *protocol, *redundancy)
	} else {
		// Process mode: capture ALL outbound UDP, then relay only the
		// target process's ports. Our own tunnel packets to the relay are
		// captured too, but decide() returns false for them (they aren't
		// owned by the target process) so they're passed straight through.
		filter = "outbound and udp"
		tracker := newProcTracker(*procName)
		go tracker.run()
		decide = func(srcPort uint16, _ net.IP) bool { return tracker.Has(srcPort) }
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

// captureLoop reads outbound UDP. Packets the decider accepts are encoded and
// sent straight to the relay (synchronously, lowest latency); everything else
// is re-injected unchanged (pass-through).
func captureLoop(h *divert.Handle, transport relayTransport, decide func(uint16, net.IP) bool) {
	buf := make([]byte, 65535)
	var addr divert.Address
	var pkt proto.Packet
	pkt.Flags = proto.FlagData
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
		dstIP := raw[16:20] // 4-byte slice, no allocation

		// Record the default outbound interface for fake-TCP injection.
		ne := addr.Network()
		storeIface(ne.InterfaceIndex, ne.SubInterfaceIndex)

		if !decide(srcPort, dstIP) {
			// Not our target traffic: send it back out untouched.
			if _, err := h.Send(raw, &addr); err != nil {
				log.Printf("passthrough: %v", err)
			}
			continue
		}

		srcIP := raw[12:16]
		dstPort := binary.BigEndian.Uint16(raw[ihl+2 : ihl+4])
		payload := raw[ihl+8:]

		// Update the flow template only when it actually changes, so steady
		// state allocates nothing.
		if cur := templates[srcPort].Load(); !cur.matches(srcIP, dstIP, dstPort, ne.InterfaceIndex, ne.SubInterfaceIndex) {
			templates[srcPort].Store(&flowTemplate{
				localIP:   append(net.IP(nil), srcIP...),
				localPort: srcPort,
				gameIP:    append(net.IP(nil), dstIP...),
				gamePort:  dstPort,
				ifIdx:     ne.InterfaceIndex,
				subIfIdx:  ne.SubInterfaceIndex,
			})
		}

		pkt.Seq = atomic.AddUint32(&seqCounter, 1)
		pkt.Addr = dstIP
		pkt.Port = dstPort
		pkt.LocalPort = srcPort
		pkt.Payload = payload

		pb := proto.GetBuf()
		*pb = proto.EncodeInto(*pb, &pkt)
		// Send redundant copies immediately in this goroutine. With
		// -redundancy-delay 0 (default) this matches the original low-latency
		// behavior; a non-zero delay spaces copies to survive burst loss.
		for i := 0; i < *redundancy; i++ {
			if err := transport.Send(*pb); err != nil {
				log.Printf("to relay: %v", err)
				break
			}
			if i < *redundancy-1 && *redunDelay > 0 {
				time.Sleep(*redunDelay)
			}
		}
		proto.PutBuf(pb)
		// Original is dropped (not re-sent): the relay delivers it.
	}
}

// replyLoop reads encapsulated replies and injects them as inbound.
func replyLoop(h *divert.Handle, transport relayTransport, dedup *proto.Dedup) {
	buf := make([]byte, 65535)
	var pkt proto.Packet
	var a divert.Address
	for {
		n, err := transport.Recv(buf)
		if err != nil {
			log.Printf("from relay: %v", err)
			continue
		}
		if err := proto.DecodeInto(buf[:n], &pkt); err != nil {
			continue
		}
		if dedup.Seen(pkt.Seq) {
			continue
		}

		tmpl := templates[pkt.LocalPort].Load()
		if tmpl == nil {
			continue
		}

		pb := proto.GetBuf()
		*pb = buildInboundInto((*pb)[:cap(*pb)], tmpl, pkt.Payload)

		a.SetLayer(divert.LayerNetwork)
		a.SetEvent(divert.EventNetworkPacket)
		// Inbound (Outbound bit cleared); checksums are valid in-packet.
		a.Flags = flagIPChecksum | flagUDPChecksum
		ne := a.Network()
		ne.InterfaceIndex = tmpl.ifIdx
		ne.SubInterfaceIndex = tmpl.subIfIdx

		if _, err := h.Send(*pb, &a); err != nil {
			log.Printf("inject: %v", err)
		}
		proto.PutBuf(pb)
	}
}

// buildInbound crafts an IPv4+UDP packet that looks like it came FROM the
// game server TO the local client, carrying payload, with valid checksums.
func buildInbound(t *flowTemplate, payload []byte) []byte {
	return buildInboundInto(make([]byte, 28+len(payload)), t, payload)
}

// buildInboundInto writes the packet into dst (reusing its array when large
// enough) and returns the filled slice.
func buildInboundInto(dst []byte, t *flowTemplate, payload []byte) []byte {
	const ihl = 20
	udpLen := 8 + len(payload)
	total := ihl + udpLen
	if cap(dst) < total {
		dst = make([]byte, total)
	}
	b := dst[:total]

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

// ipToU32 packs an IPv4 address into a uint32 for set membership tests.
func ipToU32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

// loadGameIPs builds the set of game-server IPv4s to relay, from an optional
// single -game IP plus an optional file (one IPv4 per line; blank lines and
// lines starting with '#' are ignored). It returns the set keyed by uint32
// and the list of dotted strings (for building a WinDivert filter).
func loadGameIPs(single, path string) (map[uint32]struct{}, []string, error) {
	set := make(map[uint32]struct{})
	var dotted []string

	add := func(s string) error {
		ip := net.ParseIP(s).To4()
		if ip == nil {
			return fmt.Errorf("invalid IPv4: %q", s)
		}
		k := ipToU32(ip)
		if _, ok := set[k]; !ok {
			set[k] = struct{}{}
			dotted = append(dotted, ip.String())
		}
		return nil
	}

	if single != "" {
		if err := add(single); err != nil {
			return nil, nil, err
		}
	}

	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		line := 0
		for sc.Scan() {
			line++
			s := strings.TrimSpace(sc.Text())
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			// allow "ip # comment" and "ip:port" forms
			s = strings.TrimSpace(strings.SplitN(s, "#", 2)[0])
			if h, _, err := net.SplitHostPort(s); err == nil {
				s = h
			}
			if err := add(s); err != nil {
				return nil, nil, fmt.Errorf("%s line %d: %w", path, line, err)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, nil, err
		}
	}

	return set, dotted, nil
}
