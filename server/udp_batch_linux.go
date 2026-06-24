//go:build linux

package main

import (
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

// batchUDPTransport reads many datagrams per syscall using recvmmsg (via
// x/net/ipv4). This cuts syscall overhead under high aggregate packet rates
// (many concurrent users). For a single user it makes little difference, so
// it is opt-in via -batch.
type batchUDPTransport struct {
	conn  *net.UDPConn
	pc    *ipv4.PacketConn
	rmsgs []ipv4.Message
	qi    int // next message index to hand out
	qn    int // number of valid messages in the current batch
	mu    sync.Mutex
	addr  map[string]*net.UDPAddr
}

const batchSize = 32

func newBatchUDPTransport(listen string, sockbuf int) (serverTransport, error) {
	laddr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(sockbuf)
	_ = conn.SetWriteBuffer(sockbuf)

	t := &batchUDPTransport{
		conn:  conn,
		pc:    ipv4.NewPacketConn(conn),
		rmsgs: make([]ipv4.Message, batchSize),
		addr:  make(map[string]*net.UDPAddr),
	}
	for i := range t.rmsgs {
		t.rmsgs[i].Buffers = [][]byte{make([]byte, 65535)}
	}
	return t, nil
}

func (t *batchUDPTransport) Recv() ([]byte, string, error) {
	if t.qi >= t.qn {
		n, err := t.pc.ReadBatch(t.rmsgs, 0)
		if err != nil {
			return nil, "", err
		}
		t.qn = n
		t.qi = 0
	}
	m := &t.rmsgs[t.qi]
	t.qi++

	frame := m.Buffers[0][:m.N]
	token := m.Addr.String()
	if ua, ok := m.Addr.(*net.UDPAddr); ok {
		t.mu.Lock()
		t.addr[token] = ua
		t.mu.Unlock()
	}
	return frame, token, nil
}

func (t *batchUDPTransport) Send(frame []byte, client string) error {
	t.mu.Lock()
	ua := t.addr[client]
	t.mu.Unlock()
	if ua == nil {
		return nil
	}
	_, err := t.conn.WriteToUDP(frame, ua)
	return err
}

func (t *batchUDPTransport) Close() error {
	return t.conn.Close()
}
