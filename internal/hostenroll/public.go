// Package hostenroll defines the private network bootstrap contract for
// orchestrator created hosts. The public bundle is pinned into the image; the
// instance descriptor read from IMDS is only a hint until OCI and placement
// have been reobserved by a controller.
package hostenroll

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/nats-io/nkeys"
)

const MaxPublicBundleBytes = 16 << 10

// PublicBundle contains only image-pinned public data and non-secret local
// paths. All three endpoint IPs must be covered by the regional CA's server
// certificates; TLS performs that check during each connection.
type PublicBundle struct {
	SchemaVersion               int      `json:"schema_version"`
	Cell                        string   `json:"cell"`
	Region                      string   `json:"region"`
	ControllerEndpoints         []string `json:"controller_endpoints"`
	NATSURLs                    []string `json:"nats_urls"`
	CAPEM                       string   `json:"ca_pem"`
	ControllerResponsePublicKey string   `json:"controller_response_public_key"`
	CellAccountNKey             string   `json:"cell_account_nkey"`
	Environment                 string   `json:"environment"`
	InstallRoot                 string   `json:"install_root"`
	StateRoot                   string   `json:"state_root"`
	ManagedRuntimeRoot          string   `json:"managed_runtime_root"`
	WorkloadUID                 uint32   `json:"workload_uid"`
	WorkloadGID                 uint32   `json:"workload_gid"`
}

// ParsePublicBundle rejects unknown fields, oversized input, ambiguous endpoint
// sets, and authority keys that cannot authenticate a regional controller.
func ParsePublicBundle(wire []byte) (PublicBundle, error) {
	if len(wire) == 0 || len(wire) > MaxPublicBundleBytes {
		return PublicBundle{}, errors.New("host enrollment public bundle is missing or too large")
	}
	var bundle PublicBundle
	if err := json.Unmarshal(wire, &bundle, json.RejectUnknownMembers(true)); err != nil {
		return PublicBundle{}, fmt.Errorf("parse host enrollment public bundle: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return PublicBundle{}, err
	}
	return bundle, nil
}

func ReadPublicBundle(path string) (PublicBundle, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return PublicBundle{}, errors.New("public bundle path must be clean and absolute")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return PublicBundle{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return PublicBundle{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxPublicBundleBytes {
		return PublicBundle{}, errors.New("host enrollment public bundle is not a bounded regular file")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return PublicBundle{}, errors.New("host enrollment public bundle must be root-owned and not writable by group or others")
	}
	wire := make([]byte, info.Size())
	if _, err := io.ReadFull(file, wire); err != nil {
		return PublicBundle{}, err
	}
	return ParsePublicBundle(wire)
}

func (bundle PublicBundle) Validate() error {
	if bundle.SchemaVersion != 1 || !validCellRegion(bundle.Cell, bundle.Region) ||
		bundle.Environment != "canary" && bundle.Environment != "production" ||
		bundle.WorkloadUID == 0 || bundle.WorkloadGID == 0 ||
		!cleanRoot(bundle.InstallRoot) || !cleanRoot(bundle.StateRoot) || !cleanRoot(bundle.ManagedRuntimeRoot) ||
		pathsOverlap(bundle.InstallRoot, bundle.StateRoot) || pathsOverlap(bundle.InstallRoot, bundle.ManagedRuntimeRoot) ||
		pathsOverlap(bundle.StateRoot, bundle.ManagedRuntimeRoot) {
		return errors.New("host enrollment public bundle has invalid identity or local paths")
	}
	if _, err := bundle.ResponsePublicKey(); err != nil {
		return err
	}
	if !nkeys.IsValidPublicAccountKey(bundle.CellAccountNKey) {
		return errors.New("host enrollment cell account key is invalid")
	}
	if _, err := bundle.RootCAs(); err != nil {
		return err
	}
	if len(bundle.ControllerEndpoints) != 3 || len(bundle.NATSURLs) != 3 {
		return errors.New("host enrollment needs exactly three regional controller and NATS endpoints")
	}
	controllers := make([]netip.Addr, 0, 3)
	natsPeers := make([]netip.Addr, 0, 3)
	for _, endpoint := range bundle.ControllerEndpoints {
		ip, err := parseEndpoint(endpoint, "8443")
		if err != nil || slices.Contains(controllers, ip) {
			return errors.New("host enrollment controller endpoints must be distinct private IPv4 port 8443 addresses")
		}
		controllers = append(controllers, ip)
	}
	for _, raw := range bundle.NATSURLs {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "tls" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
			return errors.New("host enrollment NATS URLs must be direct private TLS endpoints")
		}
		ip, err := parseEndpoint(parsed.Host, "4222")
		if err != nil || slices.Contains(natsPeers, ip) {
			return errors.New("host enrollment NATS endpoints must be distinct private IPv4 port 4222 addresses")
		}
		natsPeers = append(natsPeers, ip)
	}
	slices.SortFunc(controllers, netip.Addr.Compare)
	slices.SortFunc(natsPeers, netip.Addr.Compare)
	if !slices.Equal(controllers, natsPeers) {
		return errors.New("host enrollment controller and NATS endpoints differ")
	}
	return nil
}

func (bundle PublicBundle) ResponsePublicKey() (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.DecodeString(bundle.ControllerResponsePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("host enrollment response public key is invalid")
	}
	return ed25519.PublicKey(key), nil
}

func (bundle PublicBundle) RootCAs() (*x509.CertPool, error) {
	block, rest := pem.Decode([]byte(bundle.CAPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("host enrollment requires one regional CA certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !root.IsCA || root.KeyUsage&x509.KeyUsageCertSign == 0 || root.CheckSignatureFrom(root) != nil {
		return nil, errors.New("host enrollment regional CA certificate is invalid")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pool, nil
}

func parseEndpoint(endpoint, port string) (netip.Addr, error) {
	host, gotPort, err := net.SplitHostPort(endpoint)
	if err != nil || gotPort != port {
		return netip.Addr{}, errors.New("invalid endpoint port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() || !ip.IsPrivate() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return netip.Addr{}, errors.New("endpoint is not a private IPv4 address")
	}
	return ip, nil
}

func validCellRegion(cell, region string) bool {
	return cell == "gru" && region == "GRU" || cell == "sfo" && region == "SFO" || cell == "fra" && region == "FRA"
}

func cleanRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

func pathsOverlap(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+string(filepath.Separator)) || strings.HasPrefix(b, a+string(filepath.Separator))
}
