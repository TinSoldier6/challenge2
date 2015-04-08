// securetext.go contains types and routines for implementing
// NaCl-encrypted streams.

package main

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	keySize    = 32
	nonceSize  = 24
)

// SecureReader implements NaCl decryption over an io.Reader stream.
type SecureReader struct {
	key *[keySize]byte
	r   io.Reader
}

func NewSecureReader(r io.Reader, priv, pub *[keySize]byte) SecureReader {
	s := SecureReader{r: r}
	s.key = new([keySize]byte)
	box.Precompute(s.key, pub, priv)
	return s
}

func (s SecureReader) Read(p []byte) (int, error) {
    n, err := s.r.Read(p)
    if err != nil {
        return 0, err
    }
    if n < nonceSize {
        return 0, fmt.Errorf("SecureReader.Read: invalid message length: %d", n)
    }
    return copy(p, decrypt(p[:n], s.key)), nil
}

// decrypt returns a byte slice decrypted with key. If the input cannot
// be decrypted, it returns its input unchanged.
func decrypt(in []byte, key *[keySize]byte) []byte {
    if len(in) < nonceSize {
        return in
    }
    var nonce [nonceSize]byte
    copy(nonce[:], in)
    out, ok := secretbox.Open(nil, in[nonceSize:], &nonce, key)
    if !ok {
        return in
    }
    return out
}

// SecureWriter implements NaCl encryption over an io.Writer stream.
type SecureWriter struct {
	key *[keySize]byte
	w   io.Writer
}

func NewSecureWriter(w io.Writer, priv, pub *[keySize]byte) SecureWriter {
	s := SecureWriter{w: w}
	s.key = new([keySize]byte)
	box.Precompute(s.key, pub, priv)
	return s
}

func (s SecureWriter) Write(p []byte) (int, error) {
    return s.w.Write(encrypt(p, s.key))
}

// encrypt returns a byte slice encrypted with key.
func encrypt(in []byte, key *[keySize]byte) []byte {
    nonce := newNonce()
    head := make([]byte, nonceSize)
    copy(head, nonce[:])
    return secretbox.Seal(head, in, &nonce, key)
}

func newNonce() *[nonceSize]byte {
    var nonce [nonceSize]byte
    _, err := io.ReadFull(rand.Reader, nonce[:])
    if err != nil {
        panic(err)
    }
    return &nonce
}

