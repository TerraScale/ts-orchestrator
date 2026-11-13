package nodelist

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
)

type PublicKeys struct {
	WGPublicKey   string `json:"wg_public_key"`
	TLSSPKISHA256 string `json:"tls_spki_sha256"`
}

func Keys(state string) (PublicKeys, error) {
	dir := filepath.Join(state, "node")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return PublicKeys{}, err
	}
	lock := flock.New(filepath.Join(dir, "identity.lock"))
	if err := lock.Lock(); err != nil {
		return PublicKeys{}, err
	}
	defer lock.Close()
	tlsBytes, err := identityFile(filepath.Join(dir, "tls.key"), func() ([]byte, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		data, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}), nil
	})
	if err != nil {
		return PublicKeys{}, err
	}
	block, rest := pem.Decode(tlsBytes)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return PublicKeys{}, errors.New("invalid node TLS key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return PublicKeys{}, errors.New("invalid node TLS key")
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return PublicKeys{}, errors.New("node TLS key must be P-256")
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return PublicKeys{}, err
	}
	wgBytes, err := identityFile(filepath.Join(dir, "wg.key"), func() ([]byte, error) {
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		data := key.Bytes()
		data[0] &= 248
		data[31] = data[31]&127 | 64
		return []byte(base64.StdEncoding.EncodeToString(data)), nil
	})
	if err != nil {
		return PublicKeys{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(string(wgBytes))
	if err != nil {
		return PublicKeys{}, errors.New("invalid node WireGuard key")
	}
	wg, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return PublicKeys{}, errors.New("invalid node WireGuard key")
	}
	sum := sha256.Sum256(spki)
	return PublicKeys{WGPublicKey: base64.StdEncoding.EncodeToString(wg.PublicKey().Bytes()), TLSSPKISHA256: hex.EncodeToString(sum[:])}, nil
}

func identityFile(path string, generate func() ([]byte, error)) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err == nil {
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return nil, errors.New("node private key must be a regular 0600 file")
		}
		return io.ReadAll(io.LimitReader(file, 16<<10))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	data, err := generate()
	if err != nil {
		return nil, err
	}
	if err := persist(path, data); err != nil {
		return nil, err
	}
	return data, nil
}

func persist(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".node-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = file.Chmod(0o600)
	if err == nil {
		_, err = file.Write(data)
	}
	err = errors.Join(err, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
