//go:build linux

package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"

	"relay/tcpip"

	"golang.org/x/sys/unix"
)

// faketcpServer speaks the fake-TCP transport using raw sockets: it reads
// TCP-shaped packets addressed to our listen port and replies with raw TCP
// packets. No real TCP stack is involved, so there is no head-of-line
// blocking; each frame is one PSH|ACK segment.
//
// IMPORTANT: the kernel has no socket on this TCP port, so it will try to
// RST incoming connections. You MUST stop that with, e.g.:
//
//	iptables -A OUTPUT -p tcp --sport <port> --tcp-flags RST RST -j DROP
//
// Run as root (raw sockets require CAP_NET_RAW).
type faketcpServer struct {
	port    uint16
	recvFD  int // AF_INET SOCK_RAW IPPROTO_TCP
	sendFD  int // AF_INET SOCK_RAW IPPROTO_RAW (IP_HDRINCL)
	selfIP  net.IP
	mu      sync.Mutex
	clients map[string]*ftClient
}

type ftClient struct {
	ip       net.IP
	port     uint16
	ourSeq   uint32
	theirSeq uint32
}

func newFaketcpServer(port uint16) (*faketcpServer, error) {
	rfd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("raw recv socket (need root): %w", err)
	}
	sfd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		unix.Close(rfd)
		return nil, fmt.Errorf("raw send socket (need root): %w", err)
	}
	// IPPROTO_RAW implies IP_HDRINCL, but set it explicitly for clarity.
	if err := unix.SetsockoptInt(sfd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(rfd)
		unix.Close(sfd)
		return nil, err
	}
	return &faketcpServer{
		port:    port,
		recvFD:  rfd,
		sendFD:  sfd,
		selfIP:  localIPv4(),
		clients: make(map[string]*ftClient),
	}, nil
}

func (s *faketcpServer) Recv() ([]byte, string, error) {
	buf := make([]byte, 65535)
	for {
		n, _, err := unix.Recvfrom(s.recvFD, buf, 0)
		if err != nil {
			return nil, "", err
		}
		seg, ok := tcpip.Parse(buf[:n])
		if !ok || seg.DstPort != s.port {
			continue // not for us
		}
		token := fmt.Sprintf("%s:%d", seg.SrcIP, seg.SrcPort)

		s.mu.Lock()
		c := s.clients[token]
		if c == nil {
			c = &ftClient{ip: seg.SrcIP.To4(), port: seg.SrcPort, ourSeq: rand.Uint32()}
			s.clients[token] = c
		}
		s.mu.Unlock()

		switch {
		case seg.Flags&tcpip.FlagSYN != 0 && seg.Flags&tcpip.FlagACK == 0:
			// SYN: reply SYN-ACK.
			s.mu.Lock()
			c.theirSeq = seg.Seq + 1
			synAckSeq := c.ourSeq
			c.ourSeq++ // SYN consumes one
			ack := c.theirSeq
			s.mu.Unlock()
			s.sendRaw(c, synAckSeq, ack, tcpip.FlagSYN|tcpip.FlagACK, nil)
			continue
		case len(seg.Payload) > 0:
			// Data: update ack bookkeeping and deliver to the relay.
			s.mu.Lock()
			c.theirSeq = seg.Seq + uint32(len(seg.Payload))
			s.mu.Unlock()
			out := make([]byte, len(seg.Payload))
			copy(out, seg.Payload)
			return out, token, nil
		default:
			// bare ACK / handshake completion: nothing to deliver.
			continue
		}
	}
}

func (s *faketcpServer) Send(frame []byte, client string) error {
	s.mu.Lock()
	c := s.clients[client]
	if c == nil {
		s.mu.Unlock()
		return nil
	}
	seq := c.ourSeq
	ack := c.theirSeq
	c.ourSeq += uint32(len(frame))
	s.mu.Unlock()
	return s.sendRaw(c, seq, ack, tcpip.FlagPSH|tcpip.FlagACK, frame)
}

func (s *faketcpServer) sendRaw(c *ftClient, seq, ack uint32, flags uint8, payload []byte) error {
	raw := tcpip.Build(s.selfIP, c.ip, s.port, c.port, seq, ack, flags, 65535, payload)
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], c.ip.To4())
	sa.Port = int(c.port) // ignored for raw IP, but harmless
	return unix.Sendto(s.sendFD, raw, 0, &sa)
}

func (s *faketcpServer) Close() error {
	unix.Close(s.recvFD)
	return unix.Close(s.sendFD)
}

// localIPv4 finds the default outbound source IPv4 of this host.
func localIPv4() net.IP {
	c, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return net.IPv4zero.To4()
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.To4()
}
