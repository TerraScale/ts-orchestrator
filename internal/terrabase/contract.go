// Package terrabase is the orchestrator's contract with the C# TerraBase
// single-file binary (repository TerraScale/terrabase): its release assets,
// its TERRABASE_* settings, the cell's replication peer list, the member
// certificates and its health endpoint. The host agent launches a member
// as a native workload of role "terrabase"; see docs/terrabase-runtime-contract.md.
package terrabase

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Role is the native workload role of a TerraBase member.
const Role = "terrabase"

// DefaultAdminPort is the binary's default loopback administrative port.
const DefaultAdminPort = 9464

// Settings the workload profile supplies. The binary reads every
// TERRABASE_<NAME> variable of a setting it knows; it ignores the others.
const (
	EnvAdminPort  = "TERRABASE_ADMIN_PORT"
	EnvPeerPort   = "TERRABASE_PEER_PORT"
	EnvClientPort = "TERRABASE_CLIENT_PORT"
	// EnvPeers lists every member of the cell, this one included, as
	// comma-separated name=ip:port entries. A name is the member's host node.
	EnvPeers = "TERRABASE_PEERS"
)

// Settings the host agent owns. A workload profile must not set them.
const (
	EnvDataDirectory   = "TERRABASE_DATA_DIRECTORY"
	EnvPeerCertificate = "TERRABASE_PEER_CERTIFICATE"
	EnvPeerPrivateKey  = "TERRABASE_PEER_PRIVATE_KEY"
	EnvPeerClientCA    = "TERRABASE_PEER_CLIENT_CA"
	// The client listener serves the member certificate too.
	EnvClientCertificate = "TERRABASE_CLIENT_CERTIFICATE"
	EnvClientPrivateKey  = "TERRABASE_CLIENT_PRIVATE_KEY"
	// EnvBundleExtract is where the single-file bundle extracts its native
	// libraries; without it the binary needs a writable HOME.
	EnvBundleExtract = "DOTNET_BUNDLE_EXTRACT_BASE_DIR"
	// EnvNodeName is the member's name in EnvPeers: its host's node. Without
	// it the binary takes the OS hostname, so renaming a host's OS (TS-609)
	// would leave a restarted member outside its peer list.
	EnvNodeName = "TERRABASE_NODE_NAME"
)

var hostOwned = []string{EnvDataDirectory, EnvPeerCertificate, EnvPeerPrivateKey, EnvPeerClientCA,
	EnvClientCertificate, EnvClientPrivateKey, EnvBundleExtract, EnvNodeName}

var nameRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Peer is one member of the cell's replication mesh.
type Peer struct {
	Name    string
	Address netip.AddrPort
}

// Profile is the parsed TerraBase part of a role's workload environment.
type Profile struct {
	AdminPort  int
	PeerPort   int
	ClientPort int // Zero disables the client listener.
	Peers      []Peer
}

// ParseProfile validates the environment of the "terrabase" workload profile.
func ParseProfile(env map[string]string) (Profile, error) {
	for _, key := range hostOwned {
		if _, set := env[key]; set {
			return Profile{}, fmt.Errorf("terrabase profile must not set %s", key)
		}
	}
	profile := Profile{AdminPort: DefaultAdminPort}
	var err error
	if raw, set := env[EnvAdminPort]; set {
		if profile.AdminPort, err = parsePort(raw); err != nil {
			return Profile{}, fmt.Errorf("%s: %w", EnvAdminPort, err)
		}
	}
	if profile.PeerPort, err = parsePort(env[EnvPeerPort]); err != nil {
		return Profile{}, fmt.Errorf("%s: %w", EnvPeerPort, err)
	}
	if raw, set := env[EnvClientPort]; set {
		if profile.ClientPort, err = parsePort(raw); err != nil {
			return Profile{}, fmt.Errorf("%s: %w", EnvClientPort, err)
		}
	}
	if profile.Peers, err = ParsePeers(env[EnvPeers]); err != nil {
		return Profile{}, err
	}
	for _, peer := range profile.Peers {
		if int(peer.Address.Port()) != profile.PeerPort {
			return Profile{}, fmt.Errorf("%s: peer %s does not use %s", EnvPeers, peer.Name, EnvPeerPort)
		}
	}
	if profile.AdminPort == profile.PeerPort || profile.ClientPort == profile.AdminPort || profile.ClientPort == profile.PeerPort {
		return Profile{}, errors.New("terrabase admin, peer and client ports must differ")
	}
	return profile, nil
}

// Layout is a member's directory below the host's TerraBase root. The host
// agent creates it; the binary finds every path through its environment.
type Layout string

func (l Layout) Data() string        { return filepath.Join(string(l), "data") }
func (l Layout) Bundle() string      { return filepath.Join(string(l), "bundle") }
func (l Layout) TLS() string         { return filepath.Join(string(l), "tls") }
func (l Layout) Key() string         { return filepath.Join(l.TLS(), "member.key") }
func (l Layout) Certificate() string { return filepath.Join(l.TLS(), "member.pem") }
func (l Layout) CA() string          { return filepath.Join(l.TLS(), "ca.pem") }

// Env is the member's environment: the profile settings, the host-owned paths
// and node, the member's name.
func (l Layout) Env(env map[string]string, profile Profile, node string) map[string]string {
	result := maps.Clone(env)
	result[EnvNodeName] = node
	result[EnvDataDirectory] = l.Data()
	result[EnvBundleExtract] = l.Bundle()
	result[EnvPeerCertificate] = l.Certificate()
	result[EnvPeerPrivateKey] = l.Key()
	result[EnvPeerClientCA] = l.CA()
	if profile.ClientPort != 0 {
		result[EnvClientCertificate] = l.Certificate()
		result[EnvClientPrivateKey] = l.Key()
	}
	return result
}

// Peer returns the member named node.
func (p Profile) Peer(node string) (Peer, bool) {
	index := slices.IndexFunc(p.Peers, func(peer Peer) bool { return peer.Name == node })
	if index < 0 {
		return Peer{}, false
	}
	return p.Peers[index], true
}

// ParsePeers parses name=ip:port entries with unique names and addresses.
func ParsePeers(raw string) ([]Peer, error) {
	if raw == "" {
		return nil, fmt.Errorf("%s is required", EnvPeers)
	}
	entries := strings.Split(raw, ",")
	if len(entries) > 64 {
		return nil, fmt.Errorf("%s lists more than 64 members", EnvPeers)
	}
	peers := make([]Peer, 0, len(entries))
	for _, entry := range entries {
		name, address, found := strings.Cut(entry, "=")
		addrPort, err := netip.ParseAddrPort(address)
		if !found || !nameRE.MatchString(name) || err != nil || addrPort.String() != address ||
			addrPort.Port() == 0 || !addrPort.Addr().IsValid() || addrPort.Addr().IsUnspecified() {
			return nil, fmt.Errorf("%s entry %q is not name=ip:port", EnvPeers, entry)
		}
		if addrPort.Addr().Zone() != "" || addrPort.Addr().IsLinkLocalUnicast() || addrPort.Addr().IsLinkLocalMulticast() {
			return nil, fmt.Errorf("%s entry %q: zone identifiers and link-local addresses are not supported", EnvPeers, entry)
		}
		if slices.ContainsFunc(peers, func(p Peer) bool { return p.Name == name || p.Address == addrPort }) {
			return nil, fmt.Errorf("%s repeats member %q or its address", EnvPeers, name)
		}
		peers = append(peers, Peer{Name: name, Address: addrPort})
	}
	return peers, nil
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != raw {
		return 0, errors.New("must be a port between 1 and 65535")
	}
	return port, nil
}

// Ready asks the member's client listener on loopback whether it serves
// requests: GET /readyz over TLS verified against the member CA, the path the
// public load balancer checks. TerraBase answers 200 only once the member has
// caught up with its peers (TS-561).
func Ready(ctx context.Context, clientPort int, peer Peer, certificateFile, keyFile string, caPEM []byte) error {
	config, err := memberTLS(peer, certificateFile, keyFile, caPEM)
	if err != nil {
		return fmt.Errorf("terrabase readiness: %w", err)
	}
	// A plain transport speaks HTTP/1.1 only; offering h2 would let the
	// member pick a protocol it cannot read.
	config.NextProtos = []string{"http/1.1"}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(clientPort))+"/readyz", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("terrabase readiness: %w", err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("terrabase readiness: HTTP %d %q", response.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

// Healthy asks the member's loopback administrative listener whether it
// serves requests. It is the readiness gate: the host reports a member
// running only after it answers {"status":"ok"}.
func Healthy(ctx context.Context, adminPort int) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(adminPort)+"/healthz", nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("terrabase health: %w", err)
	}
	defer response.Body.Close()
	var body struct {
		Status string `json:"status"`
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err == nil && response.StatusCode == http.StatusOK {
		err = json.Unmarshal(data, &body)
	}
	if err != nil || response.StatusCode != http.StatusOK || body.Status != "ok" {
		return fmt.Errorf("terrabase health: HTTP %d %q", response.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}
