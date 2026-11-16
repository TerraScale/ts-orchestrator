// Package netbird enrolls an OCI server with TerraScale's NetBird manager.
package netbird

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
)

const (
	DefaultManagementURL = "https://netbird.terrascale.tech"
	DefaultRegion        = "sa-saopaulo-1"
	managerHostname      = "netbird.terrascale.tech"
	maxConfigBytes       = 16 << 10
	maxPeerNames         = 64
)

var regionPattern = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[1-9][0-9]*$`)
var secretSuffixPattern = regexp.MustCompile(`^[a-z0-9]+(?:\.[a-z0-9]+)*$`)

// Config is public image configuration. The setup key stays in OCI Vault.
type Config struct {
	ManagementURL    string `json:"management_url"`
	ManagementIP     string `json:"management_ip,omitempty"`
	Region           string `json:"region"`
	SetupKeySecretID string `json:"setup_key_secret_id"`
	// PeerNames maps a cell slot's fixed primary private IPv4 address to its
	// stable NetBird peer name. A server whose address is unmapped registers
	// under its OS hostname.
	PeerNames map[string]string `json:"peer_names,omitempty"`
	// AdminPATSecretID optionally names the OCI Vault secret holding the
	// NetBird admin PAT. Only the cell's leading controller reads it, to
	// reconcile the manager; absent, controllers leave the manager alone.
	AdminPATSecretID string `json:"admin_pat_secret_id,omitempty"`
}

// PublicConfigPath is where images install the public NetBird configuration.
const PublicConfigPath = "/etc/terrascale-orchestrator/netbird.json"

// ValidSecretID reports whether id names an OCI Vault secret in region.
func ValidSecretID(region, id string) bool {
	prefix := "ocid1.vaultsecret.oc1." + region + "."
	return regionPattern.MatchString(region) && len(id) <= 255 && strings.HasPrefix(id, prefix) &&
		secretSuffixPattern.MatchString(strings.TrimPrefix(id, prefix))
}

// ValidatePeerNames requires canonical private IPv4 keys and unique server
// names of the naming scheme (internal/naming), e.g. gru-1-ctl-1.
func ValidatePeerNames(names map[string]string) error {
	if len(names) > maxPeerNames {
		return errors.New("NetBird peer_names has too many entries")
	}
	seen := make(map[string]bool, len(names))
	for address, name := range names {
		ip, err := netip.ParseAddr(address)
		if err != nil || !ip.Is4() || !ip.IsPrivate() || ip.String() != address {
			return errors.New("NetBird peer_names keys must be canonical private IPv4 addresses")
		}
		if err := naming.Validate(name); err != nil || seen[name] {
			return fmt.Errorf("NetBird peer_names values must be unique cell server names: %q", name)
		}
		seen[name] = true
	}
	return nil
}

// Validate checks public enrollment settings without reading OCI Vault.
func (cfg Config) Validate() error {
	_, err := cfg.normalized()
	return err
}

func (cfg Config) normalized() (Config, error) {
	if cfg.ManagementURL == "" {
		cfg.ManagementURL = DefaultManagementURL
	}
	if cfg.Region == "" {
		cfg.Region = DefaultRegion
	}
	manager, err := normalizeManagerURL(cfg.ManagementURL)
	if err != nil {
		return Config{}, err
	}
	cfg.ManagementURL = manager
	if cfg.ManagementIP != "" {
		ip, err := netip.ParseAddr(cfg.ManagementIP)
		if err != nil || !ip.IsPrivate() || ip.Zone() != "" || ip.Is4In6() {
			return Config{}, errors.New("NetBird management_ip must be a private IPv4 or IPv6 address")
		}
		cfg.ManagementIP = ip.String()
	}
	if !ValidSecretID(cfg.Region, cfg.SetupKeySecretID) {
		return Config{}, errors.New("NetBird setup_key_secret_id must identify an OCI Vault secret in the configured region")
	}
	if cfg.AdminPATSecretID != "" && !ValidSecretID(cfg.Region, cfg.AdminPATSecretID) {
		return Config{}, errors.New("NetBird admin_pat_secret_id must identify an OCI Vault secret in the configured region")
	}
	if err := ValidatePeerNames(cfg.PeerNames); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func normalizeManagerURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Host != managerHostname && parsed.Host != managerHostname+":443" || strings.Contains(value, "#") ||
		parsed.Path != "" && parsed.Path != "/" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", errors.New("NetBird management_url must be https://netbird.terrascale.tech")
	}
	return DefaultManagementURL, nil
}
