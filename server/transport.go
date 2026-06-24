package main

import (
	"net"
	"sync"
)

// serverTransport abstracts the relay<->client leg so the forwarding logic
// is identical for plain UDP and fake-TCP. Clients are identified by an
// opaque string token (their address); Send routes a frame back to one.
type serverTransport interface {
	// Recv returns the next encapsulated frame and the client token it came
	// from. The returned slice is owned by the caller.
	Recv() (frame []byte, client string, err error)
	// Send delivers a frame to the given client token.
	Send(frame []byte, client string) error
	Close() error
}

// udpTransport is the original behavior: a single UDP listening socket.
type udpTransport struct {
	conn *net.UDPConn
	mu   sync.Mutex
	addr map[string]*net.UDPAddr // token -> last known UDP address
}

func newUDPTransport(listen string) (*udpTransport, error) {
	laddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(*sockBuf)
	_ = conn.SetWriteBuffer(*sockBuf)
	return &udpTransport{conn: conn, addr: make(map[string]*net.UDPAddr)}, nil
}

func (t *udpTransport) Recv() ([]byte, string, error) {
	buf := make([]byte, 65535)
	n, caddr, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, "", err
	}
	token := caddr.String()
	t.mu.Lock()
	t.addr[token] = caddr
	t.mu.Unlock()
	return buf[:n], token, nil
}

func (t *udpTransport) Send(frame []byte, client string) error {
	t.mu.Lock()
	caddr := t.addr[client]
	t.mu.Unlock()
	if caddr == nil {
		return nil // unknown client; drop
	}
	_, err := t.conn.WriteToUDP(frame, caddr)
	return err
}

func (t *udpTransport) Close() error {
	return t.conn.Close()
}
