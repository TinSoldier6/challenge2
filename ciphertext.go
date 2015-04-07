package main

import (
	"golang.org/x/crypto/nacl/box"
	"io"
)

const (
	keySize   = 32
	nonceSize = 24
)

type cipherText struct {
	txKey    *[keySize]byte
	rxKey    *[keySize]byte
	contents []byte
}

type SecureReader struct {
	r io.Reader
	c cipherText
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) SecureReader {
	return nil
}

func (s SecureReader) Read(p []byte) (int, error) {
	return 0, nil
}

type secureWriter struct {
	w io.Writer
	c cipherText
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) SecureWriter {
	return nil
}

func (s SecureWriter) Write(p []byte) (int, error) {
	return 0, nil
}
