// secureconn.go contains types and routines for implementing NaCl-encrypted
// communication over a net.Conn.

package main

import "net"

// SecureConn implements NaCl-encryption and decryption over a net.Conn.
type SecureConn struct {
	net.Conn
	SecureReader
	SecureWriter
}

// NewSecureConn returns a new SecureConn using an existing net.Conn, and a new
// SecureReader and SecureWriter.
func NewSecureConn(c net.Conn, priv, pub, peer *[keySize]byte) {
	s := SecureConn{Conn: c}
	s.SecureReader = NewSecureReader(c, priv, peer)
	s.SecureWriter = NewSecureWriter(c, priv, pub)
}

func (s SecureConn) Read(p []byte) (int, error) {
	return s.SecureReader.Read(p)
}

func (s SecureConn) Write(p []byte) (int, error) {
	return s.SecureWriter.Write(p)
}
