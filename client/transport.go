//go:build windows

package main

import "net"

// relayTransport carries our encapsulated frames over the client<->relay leg.
// Two implementations: plain UDP (default) and fake-TCP.
type relayTransport interface {
	// Send transmits one encapsulated frame to the relay.
	Send(frame []byte) error
	// Recv blocks for the next frame from the relay, copying it into buf
	// and returning its length.
	Recv(buf []byte) (int, error)
	Close() error
}

// udpTransport is the original behavior: a connected UDP socket to the relay.
type udpTransport struct {
	conn *net.UDPConn
}

func newUDPTransport(raddr *net.UDPAddr) (*udpTransport, error) {
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(*sockBuf)
	_ = conn.SetWriteBuffer(*sockBuf)
	return &udpTransport{conn: conn}, nil
}

func (t *udpTransport) Send(frame []byte) error {
	_, err := t.conn.Write(frame)
	return err
}

func (t *udpTransport) Recv(buf []byte) (int, error) {
	return t.conn.Read(buf)
}

func (t *udpTransport) Close() error {
	return t.conn.Close()
}
