// Command relay-server is the Linux side: a lightweight UDP forwarder.
//
// Flow:
//
//	client --(encapsulated)--> relay --(raw UDP)--> game server
//	client <--(encapsulated)-- relay <--(raw UDP)-- game server
//
// The client<->relay leg can be plain UDP (default) or fake-TCP
// (-protocol faketcp) for networks that block UDP. The relay<->game leg is
// always real UDP.
package main

import (
	"flag"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"relay/proto"
)

var (
	listenAddr  = flag.String("listen", ":51820", "address to listen on for client traffic")
	protocol    = flag.String("protocol", "udp", "client<->relay transport: udp | faketcp")
	idleTimeout = flag.Duration("idle", 60*time.Second, "drop a flow after this much silence")
	redundancy  = flag.Int("redundancy", 1, "send each reply this many times back to the client")
	dedupSize   = flag.Int("dedup", 4096, "duplicate-detection window per flow")
)

// session represents one game flow: a unique (client, dst, localPort) triple.
type session struct {
	conn      *net.UDPConn // connected socket to the real game server
	client    string       // transport token for replies
	dst       *net.UDPAddr // the game server
	localPort uint16       // client's original source port (flow id)
	seqOut    uint32       // sequence counter for replies (for client dedup)
	dedupIn   *proto.Dedup // drops duplicate copies coming from the client
	lastSeen  atomic.Int64 // unixnano of last client packet
}

type server struct {
	transport serverTransport
	mu        sync.Mutex
	sessions  map[string]*session
}

func main() {
	flag.Parse()

	var transport serverTransport
	var err error
	switch *protocol {
	case "udp":
		transport, err = newUDPTransport(*listenAddr)
	case "faketcp":
		port, perr := portOf(*listenAddr)
		if perr != nil {
			log.Fatalf("faketcp needs a numeric port in -listen: %v", perr)
		}
		transport, err = newFaketcpServer(port)
	default:
		log.Fatalf("invalid -protocol %q (use udp or faketcp)", *protocol)
	}
	if err != nil {
		log.Fatalf("open %s transport: %v", *protocol, err)
	}
	defer transport.Close()

	s := &server{transport: transport, sessions: make(map[string]*session)}
	go s.janitor()

	log.Printf("relay listening on %s (%s)", *listenAddr, *protocol)
	s.loop()
}

func (s *server) loop() {
	for {
		frame, client, err := s.transport.Recv()
		if err != nil {
			log.Printf("recv: %v", err)
			continue
		}
		pkt, err := proto.Decode(frame)
		if err != nil {
			continue // not ours / garbage
		}

		dst := &net.UDPAddr{IP: pkt.Addr, Port: int(pkt.Port)}
		key := client + "|" + dst.String() + "|" + itoa(pkt.LocalPort)

		sess := s.getOrCreate(key, client, dst, pkt.LocalPort)
		if sess == nil {
			continue
		}
		sess.lastSeen.Store(time.Now().UnixNano())

		// Redundancy: identical copies share a seq, so dupes are dropped.
		if sess.dedupIn.Seen(pkt.Seq) {
			continue
		}

		if _, err := sess.conn.Write(pkt.Payload); err != nil {
			log.Printf("forward to %s: %v", dst, err)
		}
	}
}

func (s *server) getOrCreate(key, client string, dst *net.UDPAddr, localPort uint16) *session {
	s.mu.Lock()
	if sess, ok := s.sessions[key]; ok {
		sess.client = client // keep reply route fresh
		s.mu.Unlock()
		return sess
	}
	s.mu.Unlock()

	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		log.Printf("dial %s: %v", dst, err)
		return nil
	}

	sess := &session{
		conn:      conn,
		client:    client,
		dst:       dst,
		localPort: localPort,
		dedupIn:   proto.NewDedup(*dedupSize),
	}
	sess.lastSeen.Store(time.Now().UnixNano())

	s.mu.Lock()
	s.sessions[key] = sess
	s.mu.Unlock()

	go s.readReplies(key, sess)
	log.Printf("new flow %s -> %s (localPort %d)", client, dst, localPort)
	return sess
}

// readReplies pumps packets coming back from the game server to the client.
func (s *server) readReplies(key string, sess *session) {
	defer func() {
		sess.conn.Close()
		s.mu.Lock()
		delete(s.sessions, key)
		s.mu.Unlock()
		log.Printf("closed flow %s", key)
	}()

	buf := make([]byte, 65535)
	for {
		_ = sess.conn.SetReadDeadline(time.Now().Add(*idleTimeout))
		n, err := sess.conn.Read(buf)
		if err != nil {
			return // timeout or socket error -> close flow
		}

		seq := atomic.AddUint32(&sess.seqOut, 1)
		out := proto.Encode(&proto.Packet{
			Flags:     proto.FlagData,
			Seq:       seq,
			Addr:      sess.dst.IP,
			Port:      uint16(sess.dst.Port),
			LocalPort: sess.localPort,
			Payload:   buf[:n],
		})

		// Send R copies back; the client dedups by seq.
		for i := 0; i < *redundancy; i++ {
			if err := s.transport.Send(out, sess.client); err != nil {
				log.Printf("reply to %s: %v", sess.client, err)
				break
			}
		}
	}
}

func (s *server) janitor() {
	t := time.NewTicker(*idleTimeout)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-*idleTimeout).UnixNano()
		s.mu.Lock()
		for k, sess := range s.sessions {
			if sess.lastSeen.Load() < cutoff {
				sess.conn.SetReadDeadline(time.Now()) // unblock reader
				delete(s.sessions, k)
			}
		}
		s.mu.Unlock()
	}
}

func itoa(v uint16) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	var b [5]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = digits[v%10]
		v /= 10
	}
	return string(b[i:])
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
