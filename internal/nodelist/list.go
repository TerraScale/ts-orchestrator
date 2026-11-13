package nodelist

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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

var ErrStale = errors.New("a newer node list is held")

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

type held struct {
	List  List   `json:"list"`
	RunID uint64 `json:"run_id"`
}

type Store struct {
	mu   sync.Mutex
	path string
	held held
}

func Current() []Node {
	store := local.Load()
	if store == nil {
		return nil
	}
	return store.Snapshot().Nodes
}

func Open(state string) (*Store, error) {
	return OpenEmbedded(state, []byte(m1.NodeList))
}

func OpenEmbedded(state string, embedded []byte) (*Store, error) {
	list, err := Decode(embedded)
	if err != nil {
		return nil, fmt.Errorf("embedded node list: %w", err)
	}
	store := &Store{path: filepath.Join(state, "node", "nodes.json"), held: held{List: list}}
	data, err := os.ReadFile(store.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		var saved held
		if err := protocol.DecodeStrict(data, &saved, MaxBytes); err != nil {
			return nil, err
		}
		if err := saved.List.Validate(); err != nil {
			return nil, err
		}
		if saved.List.Sequence == list.Sequence && !same(saved.List, list) {
			return nil, errors.New("conflicting node lists at the same sequence")
		}
		if saved.List.Sequence >= list.Sequence {
			store.held = saved
		} else {
			store.held.RunID = saved.RunID
		}
	}
	if store.held.List.Sequence != 0 {
		wire, err := protocol.EncodeJSON(store.held)
		if err != nil {
			return nil, err
		}
		if err := persist(store.path, wire); err != nil {
			return nil, err
		}
	}
	local.Store(store)
	return store, nil
}

func (s *Store) Snapshot() List {
	s.mu.Lock()
	defer s.mu.Unlock()
	return List{Sequence: s.held.List.Sequence, Nodes: slices.Clone(s.held.List.Nodes)}
}

func (s *Store) Apply(list List, run uint64) (bool, error) {
	if err := list.Validate(); err != nil {
		return false, err
	}
	if run == 0 {
		return false, errors.New("node list requires a release run")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if run < s.held.RunID || list.Sequence < s.held.List.Sequence {
		return false, ErrStale
	}
	if list.Sequence == s.held.List.Sequence && !same(list, s.held.List) {
		return false, errors.New("conflicting node lists at the same sequence")
	}
	changed := list.Sequence != s.held.List.Sequence
	next := held{List: List{Sequence: list.Sequence, Nodes: slices.Clone(list.Nodes)}, RunID: run}
	wire, err := protocol.EncodeJSON(next)
	if err != nil {
		return false, err
	}
	if err := persist(s.path, wire); err != nil {
		return false, err
	}
	s.held = next
	return changed, nil
}

func same(a, b List) bool {
	x, _ := protocol.EncodeJSON(a)
	y, _ := protocol.EncodeJSON(b)
	return bytes.Equal(x, y)
}

func Decode(data []byte) (List, error) {
	var list List
	if len(data) == 0 {
		return list, nil
	}
	if err := protocol.DecodeStrict(data, &list, MaxBytes); err != nil {
		return List{}, err
	}
	return list, list.Validate()
}

func MeshIP(name, region string) (string, error) {
	regionIndex := slices.Index(catalog.Names(), region)
	suffix, ok := strings.CutPrefix(name, "ts-"+region+"-")
	nodeIndex, err := strconv.Atoi(suffix)
	if regionIndex < 0 || !ok || err != nil || nodeIndex < 1 || nodeIndex > 254 || strconv.Itoa(nodeIndex) != suffix {
		return "", errors.New("node name must be ts-<catalog region>-<index 1..254>")
	}
	return fmt.Sprintf("10.201.%d.%d", regionIndex+1, nodeIndex), nil
}

func (l List) Validate() error {
	if len(l.Nodes) == 0 {
		if l.Sequence != 0 {
			return errors.New("an empty node list must have sequence zero")
		}
		return nil
	}
	if l.Sequence == 0 {
		return errors.New("a populated node list needs a positive sequence")
	}
	seen := map[string]bool{}
	for _, node := range l.Nodes {
		mesh, err := MeshIP(node.Name, node.Region)
		if err != nil || node.MeshIP != mesh {
			return fmt.Errorf("node %q has an invalid derived mesh address", node.Name)
		}
		for _, field := range []struct{ kind, value string }{{"name", node.Name}, {"public_ip", node.PublicIP}, {"private_ip", node.PrivateIP}, {"mesh_ip", node.MeshIP}, {"wg_public_key", node.WGPublicKey}, {"tls_spki_sha256", node.TLSSPKISHA256}} {
			key := field.kind + ":" + field.value
			if seen[key] {
				return fmt.Errorf("duplicate node %s", field.kind)
			}
			seen[key] = true
		}
		for _, text := range []string{node.PublicIP, node.PrivateIP} {
			ip, err := netip.ParseAddr(text)
			if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("node %q has an invalid IPv4 address", node.Name)
			}
		}
		wg, err := base64.StdEncoding.Strict().DecodeString(node.WGPublicKey)
		if err != nil || len(wg) != 32 || bytes.Equal(wg, make([]byte, 32)) {
			return errors.New("invalid WireGuard public key")
		}
		pin, err := hex.DecodeString(node.TLSSPKISHA256)
		if err != nil || len(pin) != 32 || strings.ToLower(node.TLSSPKISHA256) != node.TLSSPKISHA256 {
			return errors.New("invalid TLS SPKI hash")
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
