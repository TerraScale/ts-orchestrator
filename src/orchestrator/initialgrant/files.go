package initialgrant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/nats-io/nkeys"
	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

const maximumProofBytes = 3 << 20

type publicProof struct {
	Version     int    `json:"version"`
	NodeID      string `json:"nodeId"`
	PublicKey   []byte `json:"publicKey"`
	SignedGrant []byte `json:"signedGrant"`
}

func proofDirectory(create bool) (*os.File, error) {
	if create && os.Geteuid() != 0 {
		return nil, errors.New("initialgrant: proof writer must be root")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(nodeauthority.InitialR1AdmissionDirectory, "/"), "/") {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(e, unix.ENOENT) && create {
			if e = unix.Mkdirat(fd, part, 0755); e != nil && !errors.Is(e, unix.EEXIST) {
				unix.Close(fd)
				return nil, e
			}
			if e = unix.Fsync(fd); e != nil {
				unix.Close(fd)
				return nil, e
			}
			next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&0005 != 0005 {
			unix.Close(fd)
			return nil, errors.New("initialgrant: proof ancestry must remain root-owned and readable")
		}
	}
	return os.NewFile(uintptr(fd), nodeauthority.InitialR1AdmissionDirectory), nil
}
func readProofFile(dir *os.File) ([]byte, error) {
	fd, err := unix.Openat(int(dir.Fd()), "proof.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "proof.json")
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm() != 0644 || info.Size() > maximumProofBytes {
		return nil, errors.New("initialgrant: unsafe root proof publication")
	}
	return io.ReadAll(io.LimitReader(f, maximumProofBytes+1))
}
func publishProof(p *Proof) error {
	dir, err := proofDirectory(true)
	if err != nil {
		return err
	}
	defer dir.Close()
	raw, err := json.Marshal(publicProof{Version: 1, NodeID: p.node, PublicKey: p.public, SignedGrant: p.signed})
	if err != nil || len(raw) > maximumProofBytes {
		return errors.New("initialgrant: proof exceeds publication bound")
	}
	prior, err := readProofFile(dir)
	if err == nil {
		if !bytes.Equal(prior, raw) {
			return errors.New("initialgrant: original proof publication conflicts")
		}
		return dir.Sync()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp("/proc/self/fd/"+strconv.FormatUint(uint64(dir.Fd()), 10), ".proof-")
	if err != nil {
		return err
	}
	name := filepath.Base(f.Name())
	defer unix.Unlinkat(int(dir.Fd()), name, 0)
	if err = f.Chmod(0644); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err == nil {
		err = closed
	}
	if err != nil {
		return err
	}
	if err = renamePublishedProof(int(dir.Fd()), name); err != nil {
		return err
	}
	return dir.Sync()
}

// ReadPublishedProof has no configurable trust root or caller-provided key path.
func ReadPublishedProof() (*Proof, error) {
	dir, err := proofDirectory(false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	raw, err := readProofFile(dir)
	if err != nil {
		return nil, err
	}
	var document publicProof
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&document) != nil || d.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("initialgrant: malformed original proof")
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(raw, canonical) || document.Version != 1 {
		return nil, errors.New("initialgrant: noncanonical original proof")
	}
	p, err := VerifyProof(document.NodeID, document.PublicKey, document.SignedGrant)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("initialgrant: published grant has no initial runtime")
	}
	return p, nil
}

func ReadConfiguration(path string) ([]byte, error) {
	return readMaterial(path, MaximumConfigBytes, false)
}

// ReadMaterialFile captures bounded credential bytes through verified directory
// descriptors. It grants no admission; consumers must check the returned bytes
// against the original signed public pins before using them.
func ReadMaterialFile(path string, maximum int64, private bool) ([]byte, error) {
	if maximum <= 0 || maximum > 1<<20 {
		return nil, errors.New("initialgrant: invalid material read bound")
	}
	return readMaterial(path, maximum, private)
}

func readMaterial(path string, maximum int64, private bool) ([]byte, error) {
	if !cleanPath(path) {
		return nil, errors.New("initialgrant: unsafe credential/config reference")
	}
	serviceUID := uint32(os.Geteuid())
	if os.Geteuid() == 0 {
		if u, err := user.Lookup("terrascale-orchestrator"); err == nil {
			if id, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
				serviceUID = uint32(id)
			}
		}
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 && st.Uid != serviceUID || st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) {
			unix.Close(fd)
			return nil, errors.New("initialgrant: unsafe credential/config ancestry")
		}
	}
	fileFD, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	unix.Close(fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fileFD), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || st.Uid != 0 && st.Uid != serviceUID || info.Mode().Perm()&0022 != 0 || private && info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("initialgrant: credential/config file ownership or bounds differ")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || int64(len(raw)) != info.Size() || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		clear(raw)
		return nil, errors.New("initialgrant: credential/config changed while reading")
	}
	return raw, nil
}
func verifyTLS(ref TLSFiles) error {
	ca, err := readMaterial(ref.CAFile, 1<<20, false)
	if err != nil {
		return err
	}
	if digest(ca) != ref.CASHA256 {
		return errors.New("initialgrant: CA pin differs")
	}
	cert, err := readMaterial(ref.CertificateFile, 1<<20, false)
	if err != nil {
		return err
	}
	if digest(cert) != ref.CertificateSHA256 {
		return errors.New("initialgrant: TLS certificate pin differs")
	}
	key, err := readMaterial(ref.KeyFile, 64<<10, true)
	if err != nil {
		return err
	}
	defer clear(key)
	if _, err = tls.X509KeyPair(cert, key); err != nil {
		return errors.New("initialgrant: TLS private key differs from signed certificate")
	}
	return nil
}
func verifyConnection(c Connection) error {
	if err := verifyTLS(c.TLS); err != nil {
		return err
	}
	raw, err := readMaterial(c.NKeySeedFile, 4096, true)
	if err != nil {
		return err
	}
	defer clear(raw)
	pair, err := nkeys.FromSeed(bytes.TrimSpace(raw))
	if err != nil {
		return err
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || public != c.PublicNKey {
		return errors.New("initialgrant: NKey private identity differs from signed public pin")
	}
	return nil
}
func verifyMaterial(c Config) error {
	if err := verifyConnection(c.Regional.Runtime); err != nil {
		return err
	}
	if c.Role == "seed" {
		if err := verifyTLS(c.Broker.TLS); err != nil {
			return err
		}
		for _, conn := range []Connection{*c.Regional.Provisioner, c.Global.Runtime, *c.Global.Provisioner} {
			if err := verifyConnection(conn); err != nil {
				return err
			}
		}
		if c.PreliminaryCapture != nil {
			for _, conn := range []Connection{c.PreliminaryCapture.Regional, c.PreliminaryCapture.Global} {
				if err := verifyConnection(conn); err != nil {
					return err
				}
			}
		}
	}
	raw, err := readMaterial(c.Membership.PinsFile, 64<<10, false)
	if err != nil {
		return err
	}
	if digest(raw) != c.Membership.PinsSHA256 {
		return errors.New("initialgrant: membership pins differ")
	}
	var pins map[string]string
	if json.Unmarshal(raw, &pins) != nil || len(pins) != len(c.Peers) {
		return errors.New("initialgrant: membership peer set differs")
	}
	canonical, _ := json.Marshal(pins)
	if !bytes.Equal(raw, canonical) {
		return errors.New("initialgrant: noncanonical membership pins")
	}
	for _, peer := range c.Peers {
		if pins[peer.Instance] != peer.MembershipPublicKey {
			return errors.New("initialgrant: membership peer identity differs")
		}
	}
	key, err := readMaterial(c.Membership.SigningKeyFile, 64<<10, true)
	if err != nil {
		return err
	}
	defer clear(key)
	block, rest := pem.Decode(key)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("initialgrant: membership signer must be one PKCS8 key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("initialgrant: membership signer must be P256")
	}
	public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	private.D.SetInt64(0)
	if err != nil || base64.StdEncoding.EncodeToString(public) != c.Membership.PublicKey {
		return errors.New("initialgrant: membership private key differs from signed public pin")
	}
	return nil
}
