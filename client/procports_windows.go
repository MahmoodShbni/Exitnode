//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// iphlpapi.GetExtendedUdpTable lets us map UDP local ports -> owning PID,
// which is how we achieve process-awareness at the network layer (where
// WinDivert itself has no process condition).
var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afInet                  = 2 // AF_INET
	udpTableOwnerPID        = 1 // UDP_TABLE_OWNER_PID
	errInsufficientBuffer   = 122
	procTrackerRefreshEvery = time.Second
)

// procTracker keeps a live set of UDP local ports owned by every process
// matching a given executable name (e.g. "cs2.exe"). Reads are lock-free.
type procTracker struct {
	name  string
	ports atomic.Pointer[map[uint16]struct{}]
}

func newProcTracker(name string) *procTracker {
	t := &procTracker{name: name}
	empty := map[uint16]struct{}{}
	t.ports.Store(&empty)
	return t
}

// Has reports whether srcPort currently belongs to the target process.
func (t *procTracker) Has(srcPort uint16) bool {
	m := t.ports.Load()
	_, ok := (*m)[srcPort]
	return ok
}

// run refreshes the port set forever. Call in a goroutine.
func (t *procTracker) run() {
	for {
		set := map[uint16]struct{}{}
		if pids, err := findPIDs(t.name); err == nil && len(pids) > 0 {
			if ports, err := udpPortsForPIDs(pids); err == nil {
				set = ports
			}
		}
		t.ports.Store(&set)
		time.Sleep(procTrackerRefreshEvery)
	}
}

// findPIDs returns the set of PIDs whose executable name matches `name`
// (case-insensitive), e.g. "cs2.exe".
func findPIDs(name string) (map[uint32]struct{}, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	want := strings.ToLower(name)
	pids := map[uint32]struct{}{}

	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		exe := strings.ToLower(windows.UTF16ToString(e.ExeFile[:]))
		if exe == want {
			pids[e.ProcessID] = struct{}{}
		}
	}
	return pids, nil
}

// udpPortsForPIDs queries the system UDP table and returns the local ports
// owned by any of the given PIDs.
func udpPortsForPIDs(pids map[uint32]struct{}) (map[uint16]struct{}, error) {
	var size uint32
	// First call sizes the buffer (returns ERROR_INSUFFICIENT_BUFFER).
	getExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, udpTableOwnerPID, 0)

	var buf []byte
	for {
		if size == 0 {
			return map[uint16]struct{}{}, nil
		}
		buf = make([]byte, size)
		r1, _, _ := getExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0, afInet, udpTableOwnerPID, 0)
		switch r1 {
		case 0:
			// success
			goto parse
		case errInsufficientBuffer:
			continue // table grew between calls; retry with new size
		default:
			return nil, fmt.Errorf("GetExtendedUdpTable failed: %d", r1)
		}
	}

parse:
	// MIB_UDPTABLE_OWNER_PID:
	//   dwNumEntries uint32
	//   table[]      { dwLocalAddr uint32; dwLocalPort uint32; dwOwningPid uint32 }
	// The row array starts immediately after dwNumEntries (offset 4), each
	// row is 12 bytes. dwLocalPort holds the port in network byte order in
	// its first two bytes.
	if len(buf) < 4 {
		return map[uint16]struct{}{}, nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	out := map[uint16]struct{}{}
	for i := 0; i < int(n); i++ {
		off := 4 + i*12
		if off+12 > len(buf) {
			break
		}
		port := binary.BigEndian.Uint16(buf[off+4 : off+6])
		pid := binary.LittleEndian.Uint32(buf[off+8 : off+12])
		if _, ok := pids[pid]; ok {
			out[port] = struct{}{}
		}
	}
	return out, nil
}
