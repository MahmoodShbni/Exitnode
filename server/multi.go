package main

import (
	"log"
	"time"
)

// multiTransport runs several serverTransports at once on the same listen
// port (UDP on IP proto 17, fake-TCP on IP proto 6 — they never collide) and
// presents them as a single serverTransport. Each client token is prefixed so
// replies are routed back over the exact transport the client used.
//
// This lets one server accept both protocols simultaneously; the client picks
// whichever it wants per run with -protocol.
type multiTransport struct {
	in       chan recvResult
	byPrefix map[string]serverTransport
	subs     []taggedSub
}

type taggedSub struct {
	prefix string
	t      serverTransport
}

type recvResult struct {
	frame  []byte
	client string
}

// newMultiTransport always brings up UDP; fake-TCP is added when wantFaketcp
// is set and it can be opened (Linux + root). If fake-TCP can't start, the
// server keeps serving UDP and logs a warning rather than failing.
func newMultiTransport(listen string, wantFaketcp bool) (*multiTransport, error) {
	m := &multiTransport{
		in:       make(chan recvResult, 1024),
		byPrefix: make(map[string]serverTransport),
	}

	udp, err := newUDPTransport(listen)
	if err != nil {
		return nil, err
	}
	m.add("u:", udp)

	if wantFaketcp {
		port, perr := portOf(listen)
		if perr != nil {
			return nil, perr
		}
		ft, ferr := newFaketcpServer(port)
		if ferr != nil {
			log.Printf("both mode: fake-TCP disabled: %v (serving UDP only)", ferr)
		} else {
			m.add("t:", ft)
			log.Printf("both mode: UDP + fake-TCP active on the same port")
		}
	}

	for _, s := range m.subs {
		go m.pump(s)
	}
	return m, nil
}

func (m *multiTransport) add(prefix string, t serverTransport) {
	m.subs = append(m.subs, taggedSub{prefix: prefix, t: t})
	m.byPrefix[prefix] = t
}

// pump drains one sub-transport into the shared channel, tagging the client.
func (m *multiTransport) pump(s taggedSub) {
	for {
		frame, client, err := s.t.Recv()
		if err != nil {
			time.Sleep(10 * time.Millisecond) // avoid busy-spin on errors
			continue
		}
		m.in <- recvResult{frame: frame, client: s.prefix + client}
	}
}

func (m *multiTransport) Recv() ([]byte, string, error) {
	r := <-m.in
	return r.frame, r.client, nil
}

func (m *multiTransport) Send(frame []byte, client string) error {
	if len(client) < 2 {
		return nil
	}
	sub := m.byPrefix[client[:2]]
	if sub == nil {
		return nil
	}
	return sub.Send(frame, client[2:])
}

func (m *multiTransport) Close() error {
	for _, s := range m.subs {
		_ = s.t.Close()
	}
	return nil
}
