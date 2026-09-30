// Package netbird enrolls an OCI server with TerraScale's NetBird manager.
package netbird

import (
	"encoding/json/v2"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
)

const (
	DefaultManagementURL = "https://netbird.terrascale.tech"
	DefaultRegion        = "sa-saopaulo-1"
	managerHostname      = "netbird.terrascale.tech"
	maxConfigBytes       = 16 << 10
)

var regionPattern = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[1-9][0-9]*$`)
var secretSuffixPattern = regexp.MustCompile(`^[a-z0-9]+(?:\.[a-z0-9]+)*$`)

// Config is public image configuration. The setup key stays in OCI Vault.
type Config struct {
	ManagementURL    string `json:"management_url"`
	ManagementIP     string `json:"management_ip,omitempty"`
	Region           string `json:"region"`
	SetupKeySecretID string `json:"setup_key_secret_id"`
}

// LoadConfig rejects unknown fields, symlinks and writable public config.
func LoadConfig(path string) (Config, error) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return Config{}, errors.New("netbird-enroll requires an absolute --config path")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return Config{}, errors.New("cannot open NetBird enrollment configuration")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !ownedRegular(info, 0o022) || info.Size() > maxConfigBytes {
		return Config{}, errors.New("NetBird configuration must be a root-owned regular file without group or other write access")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if err != nil || len(wire) > maxConfigBytes {
		return Config{}, errors.New("cannot read bounded NetBird enrollment configuration")
	}
	var cfg Config
	if err := json.Unmarshal(wire, &cfg, json.RejectUnknownMembers(true)); err != nil {
		return Config{}, errors.New("invalid NetBird enrollment configuration JSON")
	}
	return cfg.normalized()
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
	prefix := "ocid1.vaultsecret.oc1." + cfg.Region + "."
	if !regionPattern.MatchString(cfg.Region) || len(cfg.SetupKeySecretID) > 255 ||
		!strings.HasPrefix(cfg.SetupKeySecretID, prefix) || !secretSuffixPattern.MatchString(strings.TrimPrefix(cfg.SetupKeySecretID, prefix)) {
		return Config{}, errors.New("NetBird setup_key_secret_id must identify an OCI Vault secret in the configured region")
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

func ownedRegular(info os.FileInfo, forbidden os.FileMode) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&forbidden != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
