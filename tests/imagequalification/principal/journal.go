package principal

import (
	"crypto/md5" // OCI API fingerprints require MD5 over the public SPKI DER.
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

type operation struct {
	Request            jsontext.Value `json:"request"`
	RequestSHA256      string         `json:"request_sha256"`
	RetryToken         string         `json:"retry_token"`
	FirstAttempt       time.Time      `json:"first_attempt"`
	ID                 string         `json:"id"`
	DeleteIntent       bool           `json:"delete_intent"`
	DeleteRequest      jsontext.Value `json:"delete_request,omitempty"`
	DeleteSHA256       string         `json:"delete_sha256"`
	DeleteRequestID    string         `json:"delete_request_id"`
	DeleteFirstAttempt time.Time      `json:"delete_first_attempt"`
	Deleted            bool           `json:"deleted"`
}

type journal struct {
	PreparationSHA256 string                `json:"preparation_sha256"`
	PreparationWire   jsontext.Value        `json:"preparation_wire"`
	Operations        map[string]*operation `json:"operations"`
	Cleaning          bool                  `json:"cleaning"`
	Cleaned           bool                  `json:"cleaned"`
}

type store struct {
	root *os.Root
	lock *os.File
}

func openStore(path string) (*store, error) {
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode().Perm() != 0700 || !owned(before) {
		return nil, errors.New("principal escrow directory must be owner-only 0700, without symlinks")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	directory, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	after, statErr := directory.Stat()
	directory.Close()
	if statErr != nil || !os.SameFile(before, after) {
		root.Close()
		return nil, errors.New("principal escrow directory changed while opening")
	}
	s := &store{root: root}
	lock, err := s.open("lock", os.O_CREATE|os.O_RDWR)
	if err != nil {
		root.Close()
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		root.Close()
		return nil, errors.New("principal escrow is already in use")
	}
	s.lock = lock
	return s, nil
}

func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func (s *store) open(name string, flags int) (*os.File, error) {
	f, err := s.root.OpenFile(name, flags|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !owned(info) || !ok || stat.Nlink != 1 {
		f.Close()
		return nil, errors.New("principal escrow file must be owner-only 0600 with one link")
	}
	return f, nil
}

func (s *store) close() {
	if s.lock != nil {
		syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		s.lock.Close()
	}
	s.root.Close()
}

func (s *store) read(name string, max int64) ([]byte, error) {
	f, err := s.open(name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	wire, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(wire)) > max {
		return nil, errors.New("principal escrow file exceeds limit")
	}
	return wire, nil
}

func (s *store) sync() error {
	f, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *store) write(name string, wire []byte) error {
	tmp := ".checkpoint-" + rand.Text()
	f, err := s.open(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	defer s.root.Remove(tmp)
	_, err = f.Write(wire)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := s.root.Rename(tmp, name); err != nil {
		return err
	}
	return s.sync()
}

func (s *store) save(j *journal) error {
	wire, err := json.Marshal(j, json.Deterministic(true))
	if err != nil {
		return err
	}
	return s.write("journal.json", wire)
}

func (s *store) load(v VerifiedPreparation, required bool) (*journal, error) {
	wire, err := s.read("journal.json", 256<<10)
	if errors.Is(err, os.ErrNotExist) && !required {
		return &journal{PreparationSHA256: v.digest, PreparationWire: jsontext.Value(v.wire), Operations: map[string]*operation{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var j journal
	if err := protocol.DecodeStrict(wire, &j, 256<<10); err != nil {
		return nil, err
	}
	if j.PreparationSHA256 != v.digest || string(j.PreparationWire) != string(v.wire) || j.Operations == nil || j.Cleaned && !j.Cleaning {
		return nil, errors.New("principal journal differs from exact signed preparation")
	}
	for name, op := range j.Operations {
		if !knownOperation(name) || op == nil || op.FirstAttempt.IsZero() || op.FirstAttempt.Before(v.preparation.ExpiresAt.Add(-maxLifetime)) || !op.FirstAttempt.Before(v.preparation.ExpiresAt) || op.RequestSHA256 != hash(op.Request) || op.RetryToken != hash([]byte(v.digest + "/" + name + "/" + op.RequestSHA256))[:32] || op.Deleted && !op.DeleteIntent {
			return nil, errors.New("principal journal operation is inconsistent")
		}
		if op.DeleteIntent && (op.DeleteFirstAttempt.IsZero() || op.DeleteSHA256 != hash(op.DeleteRequest) || op.DeleteRequestID != hash([]byte(v.digest + "/delete/" + name + "/" + op.DeleteSHA256))[:32]) {
			return nil, errors.New("principal delete journal is inconsistent")
		}
	}
	return &j, nil
}

func knownOperation(name string) bool {
	return name == "user" || name == "group" || name == "policy" || name == "key" || name == "membership"
}

func (s *store) intent(v VerifiedPreparation, j *journal, name string, request any, now time.Time) (*operation, error) {
	wire, err := json.Marshal(request, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	if op := j.Operations[name]; op != nil {
		if string(op.Request) != string(wire) || op.RequestSHA256 != hash(wire) {
			return nil, errors.New("principal replay request differs from durable intent")
		}
		if now.Before(op.FirstAttempt) || op.ID == "" && now.Sub(op.FirstAttempt) >= 23*time.Hour {
			return nil, errors.New("principal create retry window expired; retain exact recovery evidence")
		}
		if op.DeleteIntent || op.Deleted {
			return nil, errors.New("principal operation was already revoked")
		}
		return op, nil
	}
	op := &operation{Request: wire, RequestSHA256: hash(wire), FirstAttempt: now}
	op.RetryToken = hash([]byte(v.digest + "/" + name + "/" + op.RequestSHA256))[:32]
	j.Operations[name] = op
	if err := s.save(j); err != nil {
		return nil, err
	}
	return op, nil
}

// GenerateKey escrows a temporary RSA key before preparation signing. Reopening
// returns the same public identity; it never silently replaces recovery material.
func GenerateKey(workdir string) (publicPEM, fingerprint string, err error) {
	s, err := openStore(workdir)
	if err != nil {
		return "", "", err
	}
	defer s.close()
	wire, err := s.read("private.pem", 16<<10)
	if errors.Is(err, os.ErrNotExist) {
		if _, err := s.read("journal.json", 256<<10); !errors.Is(err, os.ErrNotExist) {
			return "", "", errors.New("cannot replace a missing private key for an existing journal")
		}
		key, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return "", "", err
		}
		wire = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		defer clear(wire)
		if err := s.write("private.pem", wire); err != nil {
			return "", "", err
		}
	} else if err != nil {
		return "", "", err
	}
	defer clear(wire)
	key, err := privateKey(wire)
	if err != nil {
		return "", "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	return publicIdentity(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func privateKey(wire []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "RSA PRIVATE KEY" || len(rest) > 0 {
		return nil, errors.New("invalid escrow private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil || key == nil || key.N.BitLen() != 3072 {
		return nil, errors.New("invalid escrow RSA key")
	}
	if err := key.Validate(); err != nil {
		return nil, errors.New("invalid escrow RSA parameters")
	}
	return key, nil
}

func publicIdentity(wire []byte) (string, string, error) {
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) > 0 {
		return "", "", errors.New("invalid public RSA PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", "", errors.New("invalid public RSA DER")
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N.BitLen() != 3072 || key.E != 65537 {
		return "", "", errors.New("3072-bit RSA public API key required")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), fingerprintDER(der), nil
}

func fingerprintDER(der []byte) string {
	digest := md5.Sum(der)
	parts := make([]string, len(digest))
	for i, b := range digest {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

func validFingerprint(value string) bool {
	compact := strings.ReplaceAll(value, ":", "")
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 16 && len(value) == 47 && strings.ToLower(value) == value && strings.Join(splitPairs(compact), ":") == value
}
func splitPairs(value string) []string {
	pairs := make([]string, len(value)/2)
	for i := range pairs {
		pairs[i] = value[i*2 : i*2+2]
	}
	return pairs
}
