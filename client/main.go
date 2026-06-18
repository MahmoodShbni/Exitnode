//go:build windows

// Command relay-client is the Windows side. It uses WinDivert to grab
// ONLY the outbound UDP that goes to the game server, tunnels it through
// your relay, and re-injects the replies so the game thinks they came
// straight from the server.
//
// TCP and every other process are never touched — they keep using the
// normal internet path.
//
// Requirements next to the .exe:
//   - WinDivert.dll
//   - WinDivert64.sys   (driver, auto-loaded; needs Administrator)
//
// Build (from Linux or Windows):
//   GOOS=windows GOARCH=amd64 go build -o relay-client.exe ./client
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

	"github.com/williamfhe/godivert"
)

var (
	relayAddr  = flag.String("relay", "", "relay server address host:port (required)")
	gameIP     = flag.String("game", "", "game server IP to capture, e.g. 1.2.3.4 (required)")
	redundancy = flag.Int("redundancy", 2, "send each game packet this many times to the relay")
	dedupSize  = flag.Int("dedup", 4096, "duplicate-detection window for replies")
)

// flowTemplate remembers the addressing of an outbound packet so we can
// reconstruct the matching inbound packet for re-injection.
type flowTemplate struct {
	localIP   net.IP
	localPort uint16
	gameIP    net.IP
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
	if *relayAddr == "" || *gameIP == "" {
		log.Fatal("usage: relay-client -relay host:port -game <game-server-ip>")
	}
	gIP := net.ParseIP(*gameIP).To4()
	if gIP == nil {
		log.Fatal("invalid -game IP (IPv4 only)")
	}

	// Socket to the relay. We send encapsulated packets here and read replies.
	raddr, err := net.ResolveUDPAddr("udp", *relayAddr)
	if err != nil {
		log.Fatalf("resolve relay: %v", err)
	}
	relayConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Fatalf("dial relay: %v", err)
	}
	_ = relayConn.SetReadBuffer(4 << 20)
	_ = relayConn.SetWriteBuffer(4 << 20)

	// Capture ONLY outbound UDP headed to the game server.
	// Note: WinDivert filters on packet fields, not process. We narrow to
	// the game IP; that is enough because no other process talks to it.
	filter := fmt.Sprintf("outbound and udp and ip.DstAddr == %s", *gameIP)
	wd, err := godivert.NewWinDivertHandle(filter)
	if err != nil {
		log.Fatalf("open WinDivert (run as Administrator?): %v", err)
	}
	defer wd.Close()

	dedup := proto.NewDedup(*dedupSize)

	log.Printf("relaying %s UDP via %s (redundancy=%d)", *gameIP, *relayAddr, *redundancy)

	// Reply path: relay -> here -> re-inject into the stack as inbound.
	go replyLoop(wd, relayConn, dedup)

	// Capture path: game -> here -> relay.
	captureLoop(wd, relayConn, gIP)
}

// captureLoop reads outbound game packets and tunnels them to the relay.
func captureLoop(wd *godivert.WinDivertHandle, relayConn *net.UDPConn, gameIP net.IP) {
	for {
		pkt, err := wd.Recv()
		if err != nil {
			log.Printf("recv: %v", err)
			continue
		}

		raw := pkt.Raw
		ihl := int(raw[0]&0x0f) * 4
		if len(raw) < ihl+8 {
			_ = sendOriginal(wd, pkt)
			continue
		}
		srcIP := net.IPv4(raw[12], raw[13], raw[14], raw[15])
		srcPort := binary.BigEndian.Uint16(raw[ihl : ihl+2])
		dstPort := binary.BigEndian.Uint16(raw[ihl+2 : ihl+4])
		payload := raw[ihl+8:]

		// Remember how to rebuild the reply for this flow.
		tmplMu.Lock()
		templates[srcPort] = &flowTemplate{
			localIP:   srcIP,
			localPort: srcPort,
			gameIP:    gameIP,
			gamePort:  dstPort,
			ifIdx:     pkt.Addr.IfIdx,
			subIfIdx:  pkt.Addr.SubIfIdx,
		}
		tmplMu.Unlock()

		seq := atomic.AddUint32(&seqCounter, 1)
		enc := proto.Encode(&proto.Packet{
			Flags:     proto.FlagData,
			Seq:       seq,
			Addr:      gameIP,
			Port:      dstPort,
			LocalPort: srcPort,
			Payload:   payload,
		})

		// Redundancy: fire the same packet (same seq) N times at the relay.
		for i := 0; i < *redundancy; i++ {
			if _, err := relayConn.Write(enc); err != nil {
				log.Printf("to relay: %v", err)
				break
			}
		}
		// Do NOT re-send the original out the normal path — the relay
		// delivers it. The captured packet is simply dropped here.
	}
}

// replyLoop reads encapsulated replies and injects them as inbound.
func replyLoop(wd *godivert.WinDivertHandle, relayConn *net.UDPConn, dedup *proto.Dedup) {
	buf := make([]byte, 65535)
	for {
		n, err := relayConn.Read(buf)
		if err != nil {
			log.Printf("from relay: %v", err)
			continue
		}
		pkt, err := proto.Decode(buf[:n])
		if err != nil {
			continue
		}
		if dedup.Seen(pkt.Seq) {
			continue // duplicate copy from redundancy
		}

		tmplMu.RLock()
		tmpl := templates[pkt.LocalPort]
		tmplMu.RUnlock()
		if tmpl == nil {
			continue // no matching flow seen yet
		}

		raw := buildInbound(tmpl, pkt.Payload)
		inbound := &godivert.Packet{
			Raw: raw,
			// Data bit0 = direction; 1 => inbound. Reuse the capturing
			// interface indices so the injected packet routes correctly.
			Addr:      &godivert.WinDivertAddress{IfIdx: tmpl.ifIdx, SubIfIdx: tmpl.subIfIdx, Data: 0x1},
			PacketLen: uint(len(raw)),
		}
		if _, err := wd.Send(inbound); err != nil {
			log.Printf("inject: %v", err)
		}
	}
}

// buildInbound crafts an IPv4+UDP packet that looks like it came FROM the
// game server TO the local client, carrying payload. UDP checksum is set
// to 0, which is legal for IPv4 and accepted by the stack.
func buildInbound(t *flowTemplate, payload []byte) []byte {
	const ihl = 20
	udpLen := 8 + len(payload)
	total := ihl + udpLen
	b := make([]byte, total)

	// --- IPv4 header ---
	b[0] = 0x45 // version 4, IHL 5
	b[1] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[4:6], 0) // id
	binary.BigEndian.PutUint16(b[6:8], 0) // flags/frag
	b[8] = 64                              // TTL
	b[9] = 17                              // protocol = UDP
	// src = game server, dst = local
	copy(b[12:16], t.gameIP.To4())
	copy(b[16:20], t.localIP.To4())
	binary.BigEndian.PutUint16(b[10:12], ipChecksum(b[:ihl]))

	// --- UDP header ---
	binary.BigEndian.PutUint16(b[20:22], t.gamePort)  // src port = game
	binary.BigEndian.PutUint16(b[22:24], t.localPort) // dst port = local
	binary.BigEndian.PutUint16(b[24:26], uint16(udpLen))
	binary.BigEndian.PutUint16(b[26:28], 0) // checksum 0 = disabled (legal for IPv4)

	copy(b[28:], payload)
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

// sendOriginal re-emits a captured packet unchanged (used when we decide
// not to tunnel it).
func sendOriginal(wd *godivert.WinDivertHandle, pkt *godivert.Packet) error {
	_, err := wd.Send(pkt)
	return err
}
