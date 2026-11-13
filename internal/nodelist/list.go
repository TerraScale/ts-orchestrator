package nodelist

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const MaxBytes = 64 << 10

var local atomic.Pointer[Store]

type Node struct {
	Name          string `json:"name"`
	Region        string `json:"region"`
	PublicIP      string `json:"public_ip"`
	PrivateIP     string `json:"private_ip"`
	MeshIP        string `json:"mesh_ip"`
	WGPublicKey   string `json:"wg_public_key"`
	TLSSPKISHA256 string `json:"tls_spki_sha256"`
}

type List struct {
	Sequence uint64 `json:"sequence"`
	Nodes    []Node `json:"nodes"`
}

type Status struct {
	Sequence uint64 `json:"sequence"`
	Digest   string `json:"digest"`
	Refused  string `json:"refused,omitempty"`
}

func (s Status) String() string {
	text := fmt.Sprintf("node list: sequence %d, sha256 %s", s.Sequence, s.Digest)
	if s.Refused != "" {
		text = "node list: refused, " + s.Refused + "; " + text
	}
	return text
}

type Store struct {
	mu      sync.Mutex
	path    string
	list    List
	refused string
	loadErr error
}

func Current() []Node {
	store := local.Load()
	if store == nil {
		return nil
	}
	return store.Snapshot().Nodes
}

func Open(state string) *Store {
	local.Store(nil)
	store := &Store{path: filepath.Join(state, "node", "nodes.json"), list: List{Nodes: []Node{}}}
	err := secureDirectory(filepath.Dir(store.path))
	if err == nil {
		var data []byte
		data, err = readStored(store.path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		} else if err == nil {
			store.list, err = Decode(data)
		}
	}
	if err != nil {
		store.list = List{Nodes: []Node{}}
		store.loadErr = fmt.Errorf("stored node list: %w", err)
	}
	local.Store(store)
	return store
}

func StatusAt(state string) Status {
	if store := local.Load(); store != nil && store.path == filepath.Join(state, "node", "nodes.json") {
		return store.Status()
	}
	data, err := readStored(filepath.Join(state, "node", "list-status.json"))
	var status Status
	if err == nil {
		err = protocol.DecodeStrict(data, &status, MaxBytes)
	}
	if err != nil {
		status.Refused = "node list status unavailable"
	}
	return status
}

func readStored(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("stored node list must be a regular 0600 file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, MaxBytes+1))
}

func (s *Store) Snapshot() List {
	s.mu.Lock()
	defer s.mu.Unlock()
	return List{Sequence: s.list.Sequence, Nodes: slices.Clone(s.list.Nodes)}
}

func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status()
}

func (s *Store) status() Status {
	wire, _ := protocol.EncodeJSON(s.list)
	sum := sha256.Sum256(wire)
	return Status{Sequence: s.list.Sequence, Digest: hex.EncodeToString(sum[:]), Refused: s.refused}
}

func (s *Store) AdoptEmbedded() {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := Decode([]byte(m1.NodeList))
	if s.loadErr != nil {
		err = s.loadErr
	}
	if err == nil {
		if list.Sequence == s.list.Sequence && !same(list, s.list) {
			err = errors.New("conflicting node lists at the same sequence")
		} else if list.Sequence > s.list.Sequence {
			var wire []byte
			wire, err = protocol.EncodeJSON(list)
			if err == nil {
				err = persist(s.path, wire)
			}
			if err == nil {
				s.list = list
			}
		}
	}
	reason := ""
	if err != nil {
		reason = err.Error()
		if s.refused != reason {
			slog.Warn("node list: refused, " + reason)
		}
	}
	s.refused = reason
	wire, statusErr := protocol.EncodeJSON(s.status())
	if statusErr == nil {
		statusErr = persist(filepath.Join(filepath.Dir(s.path), "list-status.json"), wire)
	}
	if statusErr != nil && err == nil {
		slog.Warn("node list status unavailable", "reason", statusErr.Error())
	}
}

func same(a, b List) bool {
	x, _ := protocol.EncodeJSON(a)
	y, _ := protocol.EncodeJSON(b)
	return bytes.Equal(x, y)
}

func Decode(data []byte) (List, error) {
	var wire struct {
		Sequence *uint64 `json:"sequence"`
		Nodes    *[]Node `json:"nodes"`
	}
	if err := protocol.DecodeStrict(data, &wire, MaxBytes); err != nil {
		return List{}, err
	}
	if wire.Sequence == nil || wire.Nodes == nil {
		return List{}, errors.New("node list requires sequence and a nodes array")
	}
	list := List{Sequence: *wire.Sequence, Nodes: *wire.Nodes}
	return list, list.Validate()
}

func MeshIP(name, region string) (string, error) {
	entry, known := catalog.LookupName(region)
	suffix, ok := strings.CutPrefix(name, "ts-"+region+"-")
	nodeIndex, err := strconv.Atoi(suffix)
	if !known || entry.MeshIndex < 1 || entry.MeshIndex > 254 || !ok || err != nil || nodeIndex < 1 || nodeIndex > 254 || strconv.Itoa(nodeIndex) != suffix {
		return "", errors.New("node name must be ts-<catalog region>-<index 1..254>")
	}
	return fmt.Sprintf("10.201.%d.%d", entry.MeshIndex, nodeIndex), nil
}

func (l List) Validate() error {
	if len(l.Nodes) > 0 && l.Sequence == 0 {
		return errors.New("a populated node list needs a positive sequence")
	}
	seen := map[string]bool{}
	addresses := map[netip.Addr]bool{}
	for _, node := range l.Nodes {
		mesh, err := MeshIP(node.Name, node.Region)
		if err != nil || node.MeshIP != mesh {
			return fmt.Errorf("node %q has an invalid derived mesh address", node.Name)
		}
		wg, err := base64.StdEncoding.Strict().DecodeString(node.WGPublicKey)
		if err != nil || len(wg) != 32 || bytes.Equal(wg, make([]byte, 32)) || base64.StdEncoding.EncodeToString(wg) != node.WGPublicKey {
			return errors.New("invalid canonical WireGuard public key")
		}
		pin, err := hex.DecodeString(node.TLSSPKISHA256)
		if err != nil || len(pin) != 32 || hex.EncodeToString(pin) != node.TLSSPKISHA256 {
			return errors.New("invalid canonical TLS SPKI hash")
		}
		for _, field := range []struct{ kind, value string }{{"name", node.Name}, {"wg_public_key", string(wg)}, {"tls_spki_sha256", string(pin)}} {
			key := field.kind + ":" + field.value
			if seen[key] {
				return fmt.Errorf("duplicate node %s", field.kind)
			}
			seen[key] = true
		}
		for _, text := range []string{node.PublicIP, node.PrivateIP, node.MeshIP} {
			ip, err := netip.ParseAddr(text)
			if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() || ip.String() != text {
				return fmt.Errorf("node %q has an invalid canonical IPv4 address", node.Name)
			}
			if addresses[ip] {
				return errors.New("duplicate node address")
			}
			addresses[ip] = true
		}
	}
	wire, err := protocol.EncodeJSON(l)
	if err != nil {
		return err
	}
	if len(wire) > MaxBytes-1024 {
		return errors.New("node list is too large")
	}
	return nil
}
