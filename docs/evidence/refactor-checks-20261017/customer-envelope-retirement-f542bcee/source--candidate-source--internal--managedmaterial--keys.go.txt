package managedmaterial

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

const maxKeyFileBytes = 16 << 10

// ReadRecipientKey loads the owner-only X25519 PKCS#8 PEM key that opens the
// customer envelope.
func ReadRecipientKey(path string) (*ecdh.PrivateKey, error) {
	parsed, err := readOwnerPKCS8(path)
	if err != nil {
		return nil, fmt.Errorf("recipient key: %w", err)
	}
	private, ok := parsed.(*ecdh.PrivateKey)
	if !ok || private.Curve() != ecdh.X25519() {
		return nil, errors.New("recipient key must be X25519 PKCS#8 PEM")
	}
	return private, nil
}

// ReadRecipientSigner loads the owner-only Ed25519 PKCS#8 PEM key that signs
// recipient grants.
func ReadRecipientSigner(path string) (ed25519.PrivateKey, error) {
	parsed, err := readOwnerPKCS8(path)
	if err != nil {
		return nil, fmt.Errorf("recipient signer: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("recipient signer must be Ed25519 PKCS#8 PEM")
	}
	return private, nil
}

// ReadRecipientSignerPublic loads the independently pinned Ed25519
// SubjectPublicKeyInfo PEM of the recipient signer.
func ReadRecipientSignerPublic(path string) (ed25519.PublicKey, error) {
	wire, err := readBoundedFile(path, false)
	if err != nil {
		return nil, fmt.Errorf("recipient signer public key: %w", err)
	}
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("recipient signer public key must be one Ed25519 SubjectPublicKeyInfo PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	public, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("recipient signer public key must be Ed25519")
	}
	return public, nil
}

func readOwnerPKCS8(path string) (any, error) {
	wire, err := readBoundedFile(path, true)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("key must be one PKCS#8 PEM block")
	}
	defer clear(block.Bytes)
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

// readBoundedFile opens one regular file without following a final symlink.
// Private keys must also be owner-only and owned by this process user.
func readBoundedFile(path string, private bool) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxKeyFileBytes {
		return nil, errors.New("key must be a bounded regular file")
	}
	if private {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if info.Mode().Perm()&0o077 != 0 || !ok || stat.Uid != uint32(os.Getuid()) {
			return nil, errors.New("private key must be owner-only and owned by this process user")
		}
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxKeyFileBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > maxKeyFileBytes {
		return nil, errors.New("key cannot be read within its size limit")
	}
	return wire, nil
}
