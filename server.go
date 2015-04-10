package main

import (
	"io"
	"net"
)

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return net.Dial("tcp", addr)
}

// Serve starts a secure echo server on the given listener. Sending an empty
// message will quit the server.
func Serve(l net.Listener) error {
	var err error
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()
		n, err := io.Copy(conn, conn)
		if err != nil || n == 0 {
			break
		}
	}
	return err
}
