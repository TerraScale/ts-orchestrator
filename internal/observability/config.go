package observability

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

const (
	// DefaultListenAddress keeps the observability listener on loopback
	// unless an operator selects a private address explicitly. It is not
	// 9464, the TerraBase member's loopback admin port on the same host.
	DefaultListenAddress = "127.0.0.1:9463"
	// DisabledListenAddress turns the listener off.
	DisabledListenAddress = "off"

	minBearerTokenBytes = 32
	maxBearerTokenBytes = 4096
)

// Config is the observability section of a role configuration. Its zero
// value is the default: JSON logs, a loopback listener without a token and no
// cross-member aggregation.
type Config struct {
	// ListenAddress is an IP:port literal. Empty selects
	// DefaultListenAddress; "off" disables the listener. Only loopback and
	// RFC 1918/ULA private addresses are accepted; NetBird peers use
	// 10.200.0.0/16, so a NetBird address is private too.
	ListenAddress string `json:"listen_address,omitempty"`
	// BearerTokenFile is required for any non-loopback address. /metrics and
	// the JSON views then require "Authorization: Bearer <token>".
	BearerTokenFile string `json:"bearer_token_file,omitempty"`
	// TLSCertFile and TLSKeyFile optionally serve the listener over TLS 1.3.
	TLSCertFile string `json:"tls_cert_file,omitempty"`
	TLSKeyFile  string `json:"tls_key_file,omitempty"`
	// LogFormat is "json" (default) or "logfmt"; LogLevel defaults to info.
	LogFormat string `json:"log_format,omitempty"`
	LogLevel  string `json:"log_level,omitempty"`
	// ClusterAggregation answers and issues cell-wide snapshot requests on
	// ts.orch.v1.<cell>.obs.*. It requires a subscribe grant for that subject
	// on the controller credentials, which production issuers do not grant
	// by default, so it is opt-in.
	ClusterAggregation bool `json:"cluster_aggregation,omitzero"`
	// Dashboard serves the read-only operator dashboard on this listener,
	// with a browser login that exchanges the bearer token for a session
	// cookie. Off by default: enabling it adds browser-facing routes.
	Dashboard bool `json:"dashboard,omitzero"`
}

// Enabled reports whether the listener should start.
func (config Config) Enabled() bool {
	return config.ListenAddress != DisabledListenAddress
}

// Address returns the effective listen address.
func (config Config) Address() string {
	if config.ListenAddress == "" {
		return DefaultListenAddress
	}
	return config.ListenAddress
}

// Validate checks the listener address, token and TLS pairing and the log
// settings without reading any file.
func (config Config) Validate() error {
	if _, _, err := ParseLogConfig(config.LogFormat, config.LogLevel); err != nil {
		return err
	}
	if (config.TLSCertFile == "") != (config.TLSKeyFile == "") {
		return errors.New("observability TLS requires both a certificate and a key file")
	}
	if !config.Enabled() {
		return nil
	}
	address, err := ValidateListenAddress(config.Address())
	if err != nil {
		return err
	}
	if !address.Addr().IsLoopback() && config.BearerTokenFile == "" {
		return errors.New("a non-loopback observability listener requires bearer_token_file")
	}
	return nil
}

// ValidateListenAddress accepts only a literal private IP and a non-zero
// port. Wildcard, public, link-local and multicast addresses are rejected,
// so metrics never reach a public interface by configuration mistake.
func ValidateListenAddress(raw string) (netip.AddrPort, error) {
	address, err := netip.ParseAddrPort(raw)
	if err != nil || address.Port() == 0 || address.Addr().Zone() != "" ||
		address.String() != raw {
		return netip.AddrPort{}, fmt.Errorf("observability listen address %q must be a literal IP:port", raw)
	}
	ip := address.Addr().Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return netip.AddrPort{}, errors.New("observability listener must bind one private address, not a wildcard")
	}
	if !ip.IsLoopback() && !ip.IsPrivate() {
		return netip.AddrPort{}, errors.New("observability listener must bind loopback or a private VCN or NetBird address")
	}
	return address, nil
}

// readBearerToken reads a private token file. Group or world access is
// rejected the same way other key files of this binary are.
func readBearerToken(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open observability bearer token: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("observability bearer token must be a private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBearerTokenBytes+1))
	if err != nil {
		return nil, err
	}
	return checkBearerToken(data)
}

// checkBearerToken accepts one 32-4096 byte line, surrounding whitespace
// trimmed.
func checkBearerToken(data []byte) ([]byte, error) {
	token := []byte(strings.TrimSpace(string(data)))
	if len(data) > maxBearerTokenBytes || len(token) < minBearerTokenBytes ||
		strings.ContainsAny(string(token), " \t\r\n") {
		return nil, errors.New("observability bearer token must be one 32-4096 byte line")
	}
	return token, nil
}

func bearerMatches(header string, token []byte) bool {
	presented, found := strings.CutPrefix(header, "Bearer ")
	return found && subtle.ConstantTimeCompare([]byte(presented), token) == 1
}
