//go:build windows

// Command relay-client is the Windows side.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"relay/proto"

	divert "github.com/imgk/divert-go"
	"golang.org/x/sys/windows"
)

const (
	flagSniffed     = 1 << 0
	flagOutbound    = 1 << 1
	flagLoopback    = 1 << 2
	flagImpostor    = 1 << 3
	flagIPv6        = 1 << 4
	flagIPChecksum  = 1 << 5
	flagTCPChecksum = 1 << 6
	flagUDPChecksum = 1 << 7

	// Constants for GetExtendedUdpTable
	AF_INET             = 2
	UDP_TABLE_OWNER_PID = 1
)

var (
	modiphlpapi             = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

var (
	relayAddr  = flag.String("relay", "", "relay server address host:port (required)")
	gameIP     = flag.String("game", "", "game server IP to capture (e.g. 1.2.3.4)")
	exeName    = flag.String("exe", "", "process name to capture (e.g. cs2.exe)")
	redundancy = flag.Int("redundancy", 2, "send each game packet this many times to the relay")
	dedupSize  = flag.Int("dedup", 4096, "duplicate-detection window for replies")
)

// flowTemplate now only needs to remember local machine bindings.
// Remote game IP/Port are dynamic!
type flowTemplate struct {
	localIP   net.IP
	localPort uint16
	ifIdx     uint32
	subIfIdx  uint32
}

var (
	seqCounter uint32
	tmplMu     sync.RWMutex
	templates  = map[uint16]*flowTemplate{}

	gamePorts atomic.Pointer[map[uint16]bool]
)

func main() {
	flag.Parse()
	if *relayAddr == "" {
		log.Fatal("error: -relay address is required")
	}

	// Mutual Exclusivity: Only ONE mode should be active
	if (*gameIP == "" && *exeName == "") || (*gameIP != "" && *exeName != "") {
		log.Fatal("usage error: strictly provide EITHER -game <ip> OR -exe <process.exe>")
	}

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

	var filter string
	if *gameIP != "" {
		// --- Mode 1: Static IP Binding ---
		gIP := net.ParseIP(*gameIP).To4()
		if gIP == nil {
			log.Fatal("invalid -game IP (IPv4 only)")
		}
		filter = fmt.Sprintf("outbound and udp and ip.DstAddr == %s", *gameIP)
		log.Printf("[Mode: IP] relalying traffic bound ONLY to %s via %s (redundancy=%d)", *gameIP, *relayAddr, *redundancy)
	} else {
		// --- Mode 2: Process-Aware Binding ---
		filter = "outbound and udp"
		empty := make(map[uint16]bool)
		gamePorts.Store(&empty)
		go syncGamePorts(*exeName)
		log.Printf("[Mode: Process] relaying ALL udp traffic for '%s' via %s (redundancy=%d)", *exeName, *relayAddr, *redundancy)
	}

	h, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Fatalf("open WinDivert: %v", err)
	}
	defer h.Close()

	dedup := proto.NewDedup(*dedupSize)
	go replyLoop(h, relayConn, dedup)
	captureLoop(h, relayConn)
}

func captureLoop(h *divert.Handle, relayConn *net.UDPConn) {
	buf := make([]byte, 65535)
	var addr divert.Address
	for {
		n, err := h.Recv(buf, &addr)
		if err != nil {
			continue
		}
		raw := buf[:n]
		ihl := int(raw[0]&0x0f) * 4
		if len(raw) < ihl+8 {
			_, _ = h.Send(raw, &addr)
			continue
		}
		
		srcIP := net.IPv4(raw[12], raw[13], raw[14], raw[15])
		dstIP := net.IPv4(raw[16], raw[17], raw[18], raw[19]) // Dynamically extract game server IP!
		srcPort := binary.BigEndian.Uint16(raw[ihl : ihl+2])
		dstPort := binary.BigEndian.Uint16(raw[ihl+2 : ihl+4])
		payload := raw[ihl+8:]

		// If running in Process Mode, check if the packet belongs to our process
		if *exeName != "" {
			pm := gamePorts.Load()
			if pm != nil && !(*pm)[srcPort] {
				// Not our game process. Re-inject intact to standard internet.
				_, _ = h.Send(raw, &addr)
				continue
			}
		}

		net4 := addr.Network()
		tmplMu.Lock()
		templates[srcPort] = &flowTemplate{
			localIP:   srcIP,
			localPort: srcPort,
			ifIdx:     net4.InterfaceIndex,
			subIfIdx:  net4.SubInterfaceIndex,
		}
		tmplMu.Unlock()

		seq := atomic.AddUint32(&seqCounter, 1)
		enc := proto.Encode(&proto.Packet{
			Flags:     proto.FlagData,
			Seq:       seq,
			Addr:      dstIP,   // Encapsulate dynamic destination
			Port:      dstPort,
			LocalPort: srcPort,
			Payload:   payload,
		})
		
		for i := 0; i < *redundancy; i++ {
			if _, err := relayConn.Write(enc); err != nil {
				break
			}
		}
	}
}

// ---------------------------------------------------------
// Process-Aware Logic (Windows API)
// ---------------------------------------------------------

func syncGamePorts(processName string) {
	for {
		pids := getPIDsByProcessName(processName)
		newPorts := make(map[uint16]bool)

		if len(pids) > 0 {
			rows, err := getUDPTable()
			if err == nil {
				for _, row := range rows {
					if pids[row.OwningPid] {
						port := parsePort(row.LocalPort)
						newPorts[port] = true
					}
				}
			}
		}

		gamePorts.Store(&newPorts)
		time.Sleep(2 * time.Second)
	}
}

func getPIDsByProcessName(name string) map[uint32]bool {
	pids := make(map[uint32]bool)
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return pids
	}
	defer windows.CloseHandle(snapshot)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = windows.Process32First(snapshot, &pe32)
	for err == nil {
		szExeFile := windows.UTF16ToString(pe32.ExeFile[:])
		if strings.EqualFold(szExeFile, name) {
			pids[pe32.ProcessID] = true
		}
		err = windows.Process32Next(snapshot, &pe32)
	}
	return pids
}

func getUDPTable() ([]MIB_UDPROW_OWNER_PID, error) {
	var size uint32
	procGetExtendedUdpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		UDP_TABLE_OWNER_PID,
		0,
	)

	if size == 0 {
		return nil, nil
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		UDP_TABLE_OWNER_PID,
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("error: %d", ret)
	}
	if len(buf) < 4 {
		return nil, nil
	}

	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	var rows []MIB_UDPROW_OWNER_PID
	offset := uint32(4)
	rowSize := uint32(12)

	for i := uint32(0); i < numEntries; i++ {
		if offset+rowSize > uint32(len(buf)) {
			break
		}
		row := MIB_UDPROW_OWNER_PID{
			LocalAddr: binary.LittleEndian.Uint32(buf[offset : offset+4]),
			LocalPort: binary.LittleEndian.Uint32(buf[offset+4 : offset+8]),
			OwningPid: binary.LittleEndian.Uint32(buf[offset+8 : offset+12]),
		}
		rows = append(rows, row)
		offset += rowSize
	}
	return rows, nil
}

func parsePort(dwPort uint32) uint16 {
	p := uint16(dwPort)
	return (p >> 8) | (p << 8)
}

// ---------------------------------------------------------
// Original Inbound Injection Logic
// ---------------------------------------------------------

func replyLoop(h *divert.Handle, relayConn *net.UDPConn, dedup *proto.Dedup) {
	buf := make([]byte, 65535)
	for {
		n, err := relayConn.Read(buf)
		if err != nil {
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

		// Inject dynamic pkt.Addr and pkt.Port from the relay response!
		raw := buildInbound(tmpl, pkt.Addr, pkt.Port, pkt.Payload)

		var a divert.Address
		a.SetLayer(divert.LayerNetwork)
		a.SetEvent(divert.EventNetworkPacket)
		a.Flags = flagIPChecksum | flagUDPChecksum
		ne := a.Network()
		ne.InterfaceIndex = tmpl.ifIdx
		ne.SubInterfaceIndex = tmpl.subIfIdx

		_, _ = h.Send(raw, &a)
	}
}

func buildInbound(t *flowTemplate, remoteIP net.IP, remotePort uint16, payload []byte) []byte {
	const ihl = 20
	udpLen := 8 + len(payload)
	total := ihl + udpLen
	b := make([]byte, total)

	b[0] = 0x45
	b[1] = 0x00
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[4:6], 0)
	binary.BigEndian.PutUint16(b[6:8], 0)
	b[8] = 64
	b[9] = 17
	copy(b[12:16], remoteIP.To4())
	copy(b[16:20], t.localIP.To4())
	binary.BigEndian.PutUint16(b[10:12], ipChecksum(b[:ihl]))

	binary.BigEndian.PutUint16(b[20:22], remotePort)
	binary.BigEndian.PutUint16(b[22:24], t.localPort)
	binary.BigEndian.PutUint16(b[24:26], uint16(udpLen))
	binary.BigEndian.PutUint16(b[26:28], 0)
	copy(b[28:], payload)

	csum := udpChecksum(remoteIP, t.localIP, b[20:])
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
