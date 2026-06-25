// Command relay-server is the Linux side: a lightweight UDP forwarder.
//
// Flow:
//
//	client --(encapsulated)--> relay --(raw UDP)--> game server
//	client <--(encapsulated)-- relay <--(raw UDP)-- game server
//
// The client<->relay leg can be plain UDP (default), fake-TCP, or both. The
// relay<->game leg is always real UDP.
package main

import (
	"flag"
	"log"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"relay/proto"
)

var (
	listenAddr  = flag.String("listen", ":51820", "address to listen on for client traffic")
	protocol    = flag.String("protocol", "udp", "client<->relay transport: udp | faketcp | both")
	idleTimeout = flag.Duration("idle", 60*time.Second, "drop a flow after this much silence")
	redundancy  = flag.Int("redundancy", 1, "send each reply this many times back to the client")
	redunDelay  = flag.Duration("redundancy-delay", 0, "spacing between redundant reply copies (e.g. 300us) to survive burst loss")
	dedupSize   = flag.Int("dedup", 4096, "duplicate-detection window per flow")
	sockBuf     = flag.Int("sockbuf", 4<<20, "per-socket read/write buffer in bytes")
	gogc        = flag.Int("gogc", 100, "GC target percent (higher = fewer GC pauses, more memory)")
	batch       = flag.Bool("batch", false, "Linux: read datagrams in batches via recvmmsg (helps many concurrent users)")
)

// session represents one game flow: a unique (client, dst, localPort) triple.
type session struct {
	conn      *net.UDPConn // connected socket to the real game server
	clientMu  sync.Mutex   // guards client (updated on rebind, read on reply)
	client    string       // transport token for replies
	dst       *net.UDPAddr // the game server (owns its IP bytes)
	localPort uint16       // client's original source port (flow id)
	dedupIn   *proto.Dedup // drops duplicate copies coming from the client
	lastSeen  atomic.Int64 // unixnano of last client packet
}

func (s *session) setClient(c string) {
	s.clientMu.Lock()
	s.client = c
	s.clientMu.Unlock()
}

func (s *session) getClient() string {
	s.clientMu.Lock()
	c := s.client
	s.clientMu.Unlock()
	return c
}

type server struct {
	transport serverTransport
	sessions  sync.Map // key string -> *session (lock-free hot-path lookups)
}

// globalSeqOut numbers every reply across ALL flows so the client's dedup
// (shared across flows) never sees a collision between two flows.
var globalSeqOut uint32

func main() {
	flag.Parse()
	debug.SetGCPercent(*gogc)

	var transport serverTransport
	var err error
	switch *protocol {
	case "udp":
		if *batch {
			transport, err = newBatchUDPTransport(*listenAddr, *sockBuf)
		} else {
			transport, err = newUDPTransport(*listenAddr)
		}
	case "faketcp":
		port, perr := portOf(*listenAddr)
		if perr != nil {
			log.Fatalf("faketcp needs a numeric port in -listen: %v", perr)
		}
		transport, err = newFaketcpServer(port)
	case "both":
		transport, err = newMultiTransport(*listenAddr, true)
	default:
		log.Fatalf("invalid -protocol %q (use udp, faketcp, or both)", *protocol)
	}
	if err != nil {
		log.Fatalf("open %s transport: %v", *protocol, err)
	}
	defer transport.Close()

	s := &server{transport: transport}
	go s.janitor()

	log.Printf("relay listening on %s (%s)", *listenAddr, *protocol)
	s.loop()
}

func (s *server) loop() {
	var pkt proto.Packet // reused; DecodeInto writes into it without allocating
	for {
		frame, client, err := s.transport.Recv()
		if err != nil {
			log.Printf("recv: %v", err)
			continue
		}
		if err := proto.DecodeInto(frame, &pkt); err != nil {
			continue // not ours / garbage
		}

		key := flowKey(client, pkt.Addr, pkt.Port, pkt.LocalPort)
		sess := s.getOrCreate(key, client, pkt.Addr, pkt.Port, pkt.LocalPort)
		if sess == nil {
			continue
		}
		sess.lastSeen.Store(time.Now().UnixNano())

		// Redundancy: identical copies share a seq, so dupes are dropped.
		if sess.dedupIn.Seen(pkt.Seq) {
			continue
		}
		if _, err := sess.conn.Write(pkt.Payload); err != nil {
			log.Printf("forward: %v", err)
		}
	}
}

func (s *server) getOrCreate(key, client string, ip net.IP, port, localPort uint16) *session {
	if v, ok := s.sessions.Load(key); ok {
		sess := v.(*session)
		sess.setClient(client) // keep reply route fresh on NAT rebind
		return sess
	}

	// Clone the destination IP: pkt.Addr aliases a reused decode buffer.
	ipc := make(net.IP, 4)
	copy(ipc, ip.To4())
	dst := &net.UDPAddr{IP: ipc, Port: int(port)}

	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		log.Printf("dial %s: %v", dst, err)
		return nil
	}
	// Generous socket buffers so bursts are not dropped by the kernel.
	_ = conn.SetReadBuffer(*sockBuf)
	_ = conn.SetWriteBuffer(*sockBuf)

	sess := &session{
		conn:      conn,
		client:    client,
		dst:       dst,
		localPort: localPort,
		dedupIn:   proto.NewDedup(*dedupSize),
	}
	sess.lastSeen.Store(time.Now().UnixNano())

	// LoadOrStore guards against a rare duplicate create (loop is single
	// goroutine, but be safe).
	if actual, loaded := s.sessions.LoadOrStore(key, sess); loaded {
		conn.Close()
		return actual.(*session)
	}

	go s.readReplies(key, sess)
	log.Printf("new flow %s -> %s (localPort %d)", client, dst, localPort)
	return sess
}

// readReplies pumps packets coming back from the game server to the client.
func (s *server) readReplies(key string, sess *session) {
	defer func() {
		sess.conn.Close()
		s.sessions.Delete(key)
		log.Printf("closed flow %s", key)
	}()

	buf := make([]byte, 65535)
	var reply proto.Packet
	reply.Flags = proto.FlagData
	reply.Addr = sess.dst.IP
	reply.Port = uint16(sess.dst.Port)
	reply.LocalPort = sess.localPort

	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(*idleTimeout))
		n, err := sess.conn.Read(buf)
		if err != nil {
			return // timeout or socket error -> close flow
		}

		reply.Seq = atomic.AddUint32(&globalSeqOut, 1)
		reply.Payload = buf[:n]

		pb := proto.GetBuf()
		*pb = proto.EncodeInto(*pb, &reply)
		client := sess.getClient()
		for i := 0; i < *redundancy; i++ {
			if err := s.transport.Send(*pb, client); err != nil {
				log.Printf("reply: %v", err)
				break
			}
			if i < *redundancy-1 && *redunDelay > 0 {
				time.Sleep(*redunDelay)
			}
		}
		proto.PutBuf(pb)
	}
}

func (s *server) janitor() {
	t := time.NewTicker(*idleTimeout)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-*idleTimeout).UnixNano()
		s.sessions.Range(func(_, v any) bool {
			sess := v.(*session)
			if sess.lastSeen.Load() < cutoff {
				sess.conn.SetReadDeadline(time.Now()) // unblock reader -> it cleans up
			}
			return true
		})
	}
}

// flowKey builds the session key with a single allocation.
func flowKey(client string, ip net.IP, port, localPort uint16) string {
	var b strings.Builder
	b.Grow(len(client) + 32)
	b.WriteString(client)
	b.WriteByte('|')
	b.WriteString(ip.String())
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(port)))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(int(localPort)))
	return b.String()
}

// portOf extracts the numeric port from a "host:port" or ":port" string.
func portOf(addr string) (uint16, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	p, err := net.LookupPort("udp", portStr)
	if err != nil {
		return 0, err
	}
	return uint16(p), nil
}
