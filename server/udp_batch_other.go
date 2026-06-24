//go:build !linux

package main

// On non-Linux platforms recvmmsg batching isn't used; fall back to the
// standard UDP transport so -batch is harmless.
func newBatchUDPTransport(listen string, sockbuf int) (serverTransport, error) {
	return newUDPTransport(listen)
}
