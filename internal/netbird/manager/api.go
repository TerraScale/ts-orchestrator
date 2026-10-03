package manager

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	maxResponseBytes = 8 << 20
	requestTimeout   = 30 * time.Second
)

// API is a hardened NetBird management REST client. It never follows
// redirects, bounds every response, and never reports response bodies or the
// token in errors.
type API struct {
	base  string
	token string
	http  *http.Client
}

// ValidateManagementURL accepts an https origin, or an http origin on a
// loopback address for tests.
func ValidateManagementURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	invalid := errors.New("NetBird management URL must be an https origin (http only on loopback)")
	if err != nil || parsed.User != nil || parsed.Opaque != "" || parsed.Host == "" ||
		parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(value, "#") {
		return "", invalid
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		host := parsed.Hostname()
		ip, err := netip.ParseAddr(host)
		if host != "localhost" && (err != nil || !ip.IsLoopback()) {
			return "", invalid
		}
	default:
		return "", invalid
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

// NewAPI returns a client for managementURL authenticating with a PAT.
func NewAPI(managementURL, token string) (*API, error) {
	base, err := ValidateManagementURL(managementURL)
	if err != nil {
		return nil, err
	}
	if !validToken(token) {
		return nil, errors.New("NetBird admin PAT has an invalid shape")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: requestTimeout,
		MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second,
	}
	return &API{base: base, token: token, http: &http.Client{
		Transport: transport, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func validToken(token string) bool {
	if len(token) < 20 || len(token) > 256 {
		return false
	}
	for _, c := range []byte(token) {
		if c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}

// Close releases idle connections.
func (api *API) Close() { api.http.CloseIdleConnections() }

// StatusError reports an unexpected HTTP status without the response body.
type StatusError struct {
	Method, Path string
	Status       int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("NetBird API %s %s: HTTP %d", e.Method, e.Path, e.Status)
}

// do sends one request. in may be nil; out may be nil to discard the body.
func (api *API) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		wire, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("NetBird API %s %s: encode request", method, path)
		}
		body = bytes.NewReader(wire)
	}
	request, err := http.NewRequestWithContext(ctx, method, api.base+"/api"+path, body)
	if err != nil {
		return fmt.Errorf("NetBird API %s %s: invalid request", method, path)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Token "+api.token)
	if in != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := api.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("NetBird API %s %s: request failed", method, path)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return &StatusError{Method: method, Path: path, Status: response.StatusCode}
	}
	if response.ContentLength > maxResponseBytes {
		return fmt.Errorf("NetBird API %s %s: response too large", method, path)
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(wire) > maxResponseBytes {
		return fmt.Errorf("NetBird API %s %s: response unreadable or too large", method, path)
	}
	if out == nil || len(bytes.TrimSpace(wire)) == 0 {
		return nil
	}
	if err := json.Unmarshal(wire, out); err != nil {
		return fmt.Errorf("NetBird API %s %s: unexpected response shape", method, path)
	}
	return nil
}

// Wire types hold only the fields this package reads or must send back.

type groupMinimum struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type resourceRef struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type apiGroup struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Issued    string         `json:"issued,omitempty"`
	Peers     []groupMinimum `json:"peers"`
	Resources []resourceRef  `json:"resources"`
}

type groupRequest struct {
	Name      string        `json:"name"`
	Peers     []string      `json:"peers"`
	Resources []resourceRef `json:"resources"`
}

type apiPeer struct {
	ID                          string         `json:"id"`
	Name                        string         `json:"name"`
	Hostname                    string         `json:"hostname"`
	IP                          string         `json:"ip"`
	ConnectionIP                string         `json:"connection_ip"`
	DNSLabel                    string         `json:"dns_label"`
	Connected                   bool           `json:"connected"`
	LastSeen                    time.Time      `json:"last_seen"`
	Groups                      []groupMinimum `json:"groups"`
	SSHEnabled                  bool           `json:"ssh_enabled"`
	LoginExpirationEnabled      bool           `json:"login_expiration_enabled"`
	InactivityExpirationEnabled bool           `json:"inactivity_expiration_enabled"`
	Version                     string         `json:"version"`
}

type peerRequest struct {
	Name                        string `json:"name"`
	SSHEnabled                  bool   `json:"ssh_enabled"`
	LoginExpirationEnabled      bool   `json:"login_expiration_enabled"`
	InactivityExpirationEnabled bool   `json:"inactivity_expiration_enabled"`
}

type apiRule struct {
	ID                  string              `json:"id,omitempty"`
	Name                string              `json:"name"`
	Description         string              `json:"description,omitempty"`
	Enabled             bool                `json:"enabled"`
	Action              string              `json:"action"`
	Bidirectional       bool                `json:"bidirectional"`
	Protocol            string              `json:"protocol"`
	Ports               []string            `json:"ports,omitempty"`
	PortRanges          []jsontext.Value    `json:"port_ranges,omitempty"`
	Sources             []groupMinimum      `json:"sources,omitempty"`
	Destinations        []groupMinimum      `json:"destinations,omitempty"`
	SourceResource      *resourceRef        `json:"sourceResource,omitempty"`
	DestinationResource *resourceRef        `json:"destinationResource,omitempty"`
	AuthorizedGroups    map[string][]string `json:"authorized_groups,omitempty"`
}

type apiPolicy struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	Enabled             bool      `json:"enabled"`
	Rules               []apiRule `json:"rules"`
	SourcePostureChecks []string  `json:"source_posture_checks"`
}

type ruleRequest struct {
	ID                  string              `json:"id,omitempty"`
	Name                string              `json:"name"`
	Description         string              `json:"description"`
	Enabled             bool                `json:"enabled"`
	Action              string              `json:"action"`
	Bidirectional       bool                `json:"bidirectional"`
	Protocol            string              `json:"protocol"`
	Ports               []string            `json:"ports,omitempty"`
	Sources             []string            `json:"sources,omitempty"`
	Destinations        []string            `json:"destinations,omitempty"`
	DestinationResource *resourceRef        `json:"destinationResource,omitempty"`
	AuthorizedGroups    map[string][]string `json:"authorized_groups,omitempty"`
}

type policyRequest struct {
	Name                string        `json:"name"`
	Description         string        `json:"description"`
	Enabled             bool          `json:"enabled"`
	Rules               []ruleRequest `json:"rules"`
	SourcePostureChecks []string      `json:"source_posture_checks"`
}

type apiNetwork struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type networkRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type apiResource struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Address     string         `json:"address"`
	Type        string         `json:"type"`
	Enabled     bool           `json:"enabled"`
	Groups      []groupMinimum `json:"groups"`
}

type resourceRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Address     string   `json:"address"`
	Enabled     bool     `json:"enabled"`
	Groups      []string `json:"groups"`
}

type apiRouter struct {
	ID         string   `json:"id"`
	Peer       string   `json:"peer,omitempty"`
	PeerGroups []string `json:"peer_groups,omitempty"`
	Metric     int      `json:"metric"`
	Masquerade bool     `json:"masquerade"`
	Enabled    bool     `json:"enabled"`
}

type routerRequest struct {
	Peer       string `json:"peer"`
	Metric     int    `json:"metric"`
	Masquerade bool   `json:"masquerade"`
	Enabled    bool   `json:"enabled"`
}

// apiAccount keeps settings and onboarding as raw members: the account PUT
// replaces every setting, so unmanaged values are sent back unchanged.
type apiAccount struct {
	ID         string                    `json:"id"`
	Settings   map[string]jsontext.Value `json:"settings"`
	Onboarding jsontext.Value            `json:"onboarding,omitzero"`
}

type accountRequest struct {
	Settings   map[string]jsontext.Value `json:"settings"`
	Onboarding jsontext.Value            `json:"onboarding,omitzero"`
}

type dnsSettings struct {
	DisabledManagementGroups []string `json:"disabled_management_groups"`
}

type apiZone struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Domain             string   `json:"domain"`
	Enabled            bool     `json:"enabled"`
	EnableSearchDomain bool     `json:"enable_search_domain"`
	DistributionGroups []string `json:"distribution_groups"`
}

type zoneRequest struct {
	Name               string   `json:"name"`
	Domain             string   `json:"domain"`
	Enabled            bool     `json:"enabled"`
	EnableSearchDomain bool     `json:"enable_search_domain"`
	DistributionGroups []string `json:"distribution_groups"`
}

type apiRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

type recordRequest struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
}

// apiSetupKey deliberately has no key member: key values are never decoded.
type apiSetupKey struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	State      string    `json:"state"`
	Valid      bool      `json:"valid"`
	Revoked    bool      `json:"revoked"`
	AutoGroups []string  `json:"auto_groups"`
	Ephemeral  bool      `json:"ephemeral"`
	UsedTimes  int       `json:"used_times"`
	Expires    time.Time `json:"expires"`
}

type created struct {
	ID string `json:"id"`
}
