package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize    = 32
	nonceSize  = 24
	msgLenSize = 2
)

// SecureReader implements NaCl encryption over an io.Reader.
type SecureReader struct {
	key *[keySize]byte
	r   io.Reader
}

// NewSecureReader instantiates a new SecureReader.
func NewSecureReader(r io.Reader, priv, pub *[keySize]byte) SecureReader {
	s := SecureReader{r: r}
	s.key = new([keySize]byte)
	box.Precompute(s.key, pub, priv)
	return s
}

func (s SecureReader) Read(p []byte) (int, error) {
	var n int16
	err := binary.Read(s.r, binary.LittleEndian, &n)
	if err != nil {
		return 0, err
	}

	var nonce [nonceSize]byte
	err = binary.Read(s.r, binary.LittleEndian, &nonce)
	if err != nil {
		return 0, err
	}

	buf := make([]byte, n+secretbox.Overhead)
	_, err = io.ReadFull(s.r, buf)
	if err != nil {
		return 0, err
	}

	in, ok := secretbox.Open(nil, buf, &nonce, s.key)
	if !ok {
		return 0, fmt.Errorf("Failed to decrypt message.")
	}

	copy(p, in)
	return len(in), nil
}

// SecureWriter implements NaCl encryption over an io.Reader.
type SecureWriter struct {
	key *[keySize]byte
	w   io.Writer
}

// NewSecureWriter instantiates a new SecureWriter.
func NewSecureWriter(w io.Writer, priv, pub *[keySize]byte) SecureWriter {
	s := SecureWriter{w: w}
	s.key = new([keySize]byte)
	box.Precompute(s.key, pub, priv)
	return s
}

func (s SecureWriter) Write(p []byte) (int, error) {
	var nonce [nonceSize]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return 0, err
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, int16(len(p)))
	binary.Write(buf, binary.LittleEndian, nonce)

	out := make([]byte, buf.Len(), buf.Len()+len(p))
	buf.Read(out)
	return s.w.Write(secretbox.Seal(out, p, &nonce, s.key))
}
