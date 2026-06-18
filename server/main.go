// Command relay-server is the Linux side: a lightweight UDP forwarder.
//
// Flow:
//
//	client --(encapsulated UDP)--> relay --(raw UDP)--> CS2 server
//	client <--(encapsulated UDP)-- relay <--(raw UDP)-- CS2 server
//
// It is intentionally stateless beyond a short-lived per-flow session
// so it can sit close to the game datacenter and just shuttle packets.
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
	listenAddr  = flag.String("listen", ":51820", "UDP address to listen on for client traffic")
	idleTimeout = flag.Duration("idle", 60*time.Second, "drop a flow after this much silence")
	redundancy  = flag.Int("redundancy", 1, "send each reply this many times back to the client")
	dedupSize   = flag.Int("dedup", 4096, "duplicate-detection window per flow")
)

// session represents one game flow: a unique (client, dst, localPort) triple.
type session struct {
	conn       *net.UDPConn // connected socket to the real game server
	clientAddr *net.UDPAddr // where to send replies (the client's relay socket)
	dst        *net.UDPAddr // the game server
	localPort  uint16       // client's original source port (flow id)
	seqOut     uint32       // sequence counter for replies (for client-side dedup)
	dedupIn    *proto.Dedup // drops duplicate copies coming from the client
	lastSeen   atomic.Int64 // unixnano of last client packet
}

type server struct {
	listen   *net.UDPConn
	mu       sync.Mutex
	sessions map[string]*session
}

func main() {
	flag.Parse()

	laddr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		log.Fatalf("resolve listen: %v", err)
	}
	lc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	// Generous buffers help under bursty load.
	_ = lc.SetReadBuffer(4 << 20)
	_ = lc.SetWriteBuffer(4 << 20)

	s := &server{listen: lc, sessions: make(map[string]*session)}
	go s.janitor()

	log.Printf("relay listening on %s", *listenAddr)
	s.loop()
}

func (s *server) loop() {
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := s.listen.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}
		pkt, err := proto.Decode(buf[:n])
		if err != nil {
			continue // not ours / garbage
		}

		dst := &net.UDPAddr{IP: pkt.Addr, Port: int(pkt.Port)}
		key := clientAddr.String() + "|" + dst.String() + "|" + itoa(pkt.LocalPort)

		sess := s.getOrCreate(key, clientAddr, dst, pkt.LocalPort)
		if sess == nil {
			continue
		}
		sess.lastSeen.Store(time.Now().UnixNano())

		// Redundancy: identical copies share a seq, so dupes are dropped.
		if sess.dedupIn.Seen(pkt.Seq) {
			continue
		}

		// Forward the original game payload to the real server.
		if _, err := sess.conn.Write(pkt.Payload); err != nil {
			log.Printf("forward to %s: %v", dst, err)
		}
	}
}

func (s *server) getOrCreate(key string, clientAddr, dst *net.UDPAddr, localPort uint16) *session {
	s.mu.Lock()
	if sess, ok := s.sessions[key]; ok {
		// Client source port may change on NAT rebind; keep it fresh.
		sess.clientAddr = clientAddr
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
		conn:       conn,
		clientAddr: clientAddr,
		dst:        dst,
		localPort:  localPort,
		dedupIn:    proto.NewDedup(*dedupSize),
	}
	sess.lastSeen.Store(time.Now().UnixNano())

	s.mu.Lock()
	s.sessions[key] = sess
	s.mu.Unlock()

	go s.readReplies(key, sess)
	log.Printf("new flow %s -> %s (localPort %d)", clientAddr, dst, localPort)
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
			if _, err := s.listen.WriteToUDP(out, sess.clientAddr); err != nil {
				log.Printf("reply to %s: %v", sess.clientAddr, err)
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
