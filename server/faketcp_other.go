//go:build !linux

package main

import "errors"

// faketcpServer is only implemented on Linux (raw sockets). On other
// platforms the constructor returns an error so `go build` still works.
type faketcpServer struct{}

func newFaketcpServer(port uint16) (*faketcpServer, error) {
	return nil, errors.New("faketcp server transport is only supported on Linux")
}

func (s *faketcpServer) Recv() ([]byte, string, error)          { return nil, "", errors.New("unsupported") }
func (s *faketcpServer) Send(frame []byte, client string) error { return errors.New("unsupported") }
func (s *faketcpServer) Close() error                           { return nil }
