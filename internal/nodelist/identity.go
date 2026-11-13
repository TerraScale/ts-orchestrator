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
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/gofrs/flock"
)

type PublicKeys struct {
	WGPublicKey   string `json:"wg_public_key"`
	TLSSPKISHA256 string `json:"tls_spki_sha256"`
}

func Keys(state string) (PublicKeys, error) {
	dir := filepath.Join(state, "node")
	if err := secureDirectory(dir); err != nil {
		return PublicKeys{}, err
	}
	lock := flock.New(filepath.Join(dir, "identity.lock"))
	if err := lock.Lock(); err != nil {
		return PublicKeys{}, err
	}
	defer lock.Close()
	tlsPath, wgPath := filepath.Join(dir, "tls.key"), filepath.Join(dir, "wg.key")
	_, tlsErr := os.Lstat(tlsPath)
	_, wgErr := os.Lstat(wgPath)
	if errors.Is(tlsErr, os.ErrNotExist) && errors.Is(wgErr, os.ErrNotExist) {
		tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return PublicKeys{}, err
		}
		tlsDER, err := x509.MarshalPKCS8PrivateKey(tlsKey)
		if err != nil {
			return PublicKeys{}, err
		}
		wgKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return PublicKeys{}, err
		}
		wgRaw := wgKey.Bytes()
		wgRaw[0] &= 248
		wgRaw[31] = wgRaw[31]&127 | 64
		if err := persist(tlsPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tlsDER})); err != nil {
			return PublicKeys{}, err
		}
		if err := persist(wgPath, []byte(base64.StdEncoding.EncodeToString(wgRaw))); err != nil {
			return PublicKeys{}, err
		}
	} else if tlsErr != nil || wgErr != nil {
		return PublicKeys{}, errors.New("node identity is incomplete or inaccessible; restore both enrolled key files")
	}
	return ReadKeys(state)
}

func InitIdentity(state string) {
	_, err := Keys(state)
	observability.SetNodeFeatureAvailable("identity", err == nil)
	if err != nil {
		slog.Warn("node identity unavailable", "reason", err.Error())
	}
}

func ReadKeys(state string) (PublicKeys, error) {
	dir := filepath.Join(state, "node")
	if err := checkDirectory(dir); err != nil {
		return PublicKeys{}, err
	}
	tlsBytes, err := identityFile(filepath.Join(dir, "tls.key"))
	if err != nil {
		return PublicKeys{}, fmt.Errorf("read node TLS identity: %w", err)
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
	wgBytes, err := identityFile(filepath.Join(dir, "wg.key"))
	if err != nil {
		return PublicKeys{}, fmt.Errorf("read node WireGuard identity: %w", err)
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

func identityFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("node private key must be an owned regular 0600 file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, 16<<10))
}

func persist(path string, data []byte) error {
	if err := secureDirectory(filepath.Dir(path)); err != nil {
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

func secureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return checkDirectory(path)
}

func checkDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0o700 || !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("node directory must be an owned 0700 directory")
	}
	return nil
}
