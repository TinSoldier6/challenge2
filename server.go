package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/nacl/box"
)

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	peer, err := clientExchangeKeys(conn, pub)
	if err != nil {
		return nil, err
	}
	secure := NewSecureConn(conn, priv, peer)
	return secure, nil
}

// Serve starts a secure echo server on the given listener. Sending an empty
// message will quit the server.
func Serve(l net.Listener) error {

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()

		pub, priv, err := box.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}

		peer, err := serveExchangeKeys(conn, pub)
		if err != nil {
			return err
		}
		secure := NewSecureConn(conn, priv, peer)
		if n, err := io.Copy(secure, secure); n == 0 {
			if err != nil {
				return err
			}
			return fmt.Errorf("Server ending.")
		}
	}
}

func clientExchangeKeys(conn net.Conn, pub *[keySize]byte) (*[keySize]byte, error) {

	peer := new([keySize]byte)

	_, err := conn.Write(pub[:])
	if err != nil {
		return nil, err
	}

	_, err = conn.Read(peer[:])
	if err != nil {
		return nil, err
	}

	return peer, nil
}

func serveExchangeKeys(conn net.Conn, pub *[keySize]byte) (*[keySize]byte, error) {
	peer := new([keySize]byte)

	_, err := conn.Read(peer[:])
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(pub[:])
	if err != nil {
		return nil, err
	}

	return peer, nil
}
