package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize    = 32
	nonceSize  = 24
	msgLenSize = 2
	overhead   = nonceSize + box.Overhead
	bufSize    = 32768 + overhead
)

// SecureReader implements NaCl encryption over an io.Reader.
type SecureReader struct {
	key *[keySize]byte
	r   io.Reader
}

// NewSecureReader instantiates a new SecureReader.
func NewSecureReader(r io.Reader, priv, pub *[keySize]byte) SecureReader {
	s := SecureReader{r: r}
	box.Precompute(s.key, pub, priv)
	return s
}

func (s SecureReader) Read(p []byte) (int, error) {
	return 0, nil
}

// SecureWriter implements NaCl encryption over an io.Reader.
type SecureWriter struct {
	key *[keySize]byte
	w   io.Writer
}

// NewSecureWriter instantiates a new SecureWriter.
func NewSecureWriter(w io.Writer, priv, pub *[keySize]byte) SecureWriter {
	s := SecureWriter{w: w}
	box.Precompute(s.key, pub, priv)
	return s
}

func (s SecureWriter) Write(p []byte) (int, error) {
	m := packMessage(p)
	out := make([]byte, nonceSize, nonceSize+len(m))
	var nonce [nonceSize]byte

	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return 0, err
	}

	copy(out, nonce[:])

	return s.w.Write(secretbox.Seal(out, m, &nonce, s.key))
}

// packMessage prepends a slice's length to the message.
func packMessage(m []byte) []byte {
	l := len(m)
	out := bytes.NewBuffer(make([]byte, 0, msgLenSize))
	binary.Write(out, binary.LittleEndian, int16(l))
	binary.Write(out, binary.LittleEndian, m)
	return out.Bytes()
}

// unpackMessage extracts a length and a message from a previously packed message.
func unpackMessage(m []byte) (int, []byte) {
	out := bytes.NewBuffer(m)
	var l int16
	binary.Read(out, binary.LittleEndian, l)
	return int(l), out.Bytes()
}
