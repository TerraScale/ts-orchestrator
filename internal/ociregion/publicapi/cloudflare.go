package publicapi

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	// Zone is the Cloudflare zone of every public name.
	Zone = "terrascale.tech"
	// TokenEnv names the Cloudflare API token, OCI Vault secret
	// gru-1-cloudflare-dns-edit-token (docs/secrets.md).
	TokenEnv      = "CF_API_TOKEN"
	cloudflareAPI = "https://api.cloudflare.com/client/v4"
	// originValidityDays is the longest Origin CA validity, 15 years.
	originValidityDays = 5475
)

// Cloudflare is the Cloudflare API client. Token may be empty for the
// published IP ranges, which need no authentication.
type Cloudflare struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// cloudflareError is an unsuccessful Cloudflare response.
type cloudflareError struct {
	Status int
	Detail string
	Codes  []int
}

func (e *cloudflareError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Detail) }

func (c Cloudflare) do(ctx context.Context, method, path string, body, result any) error {
	var payload io.Reader
	if body != nil {
		wire, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(wire)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, payload)
	if err != nil {
		return err
	}
	if c.Token != "" {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	request.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("Cloudflare %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	var envelope struct {
		Success bool           `json:"success"`
		Errors  []any          `json:"errors"`
		Result  jsontext.Value `json:"result"`
	}
	if err := json.UnmarshalRead(io.LimitReader(response.Body, 1<<20), &envelope); err != nil {
		return fmt.Errorf("Cloudflare %s %s: %w", method, path, &cloudflareError{Status: response.StatusCode, Detail: err.Error()})
	}
	if !envelope.Success || response.StatusCode/100 != 2 {
		var codes []int
		for _, e := range envelope.Errors {
			if code, ok := field(e, "code").(float64); ok {
				codes = append(codes, int(code))
			}
		}
		return fmt.Errorf("Cloudflare %s %s: %w", method, path, &cloudflareError{response.StatusCode, fmt.Sprint(envelope.Errors), codes})
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, result)
}

// OriginIPs returns Cloudflare's published IPv4 ranges, the only sources the
// load balancer admits.
func (c Cloudflare) OriginIPs(ctx context.Context) ([]string, error) {
	var ips struct {
		IPv4 []string `json:"ipv4_cidrs"`
	}
	if err := c.do(ctx, http.MethodGet, "/ips", nil, &ips); err != nil {
		return nil, err
	}
	if len(ips.IPv4) == 0 || len(ips.IPv4) > 50 {
		return nil, fmt.Errorf("Cloudflare publishes %d IPv4 ranges, want 1 to 50", len(ips.IPv4))
	}
	for i, cidr := range ips.IPv4 {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() < 8 || !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() {
			return nil, fmt.Errorf("Cloudflare publishes an unusable IPv4 range %q", cidr)
		}
		ips.IPv4[i] = prefix.String()
	}
	slices.Sort(ips.IPv4)
	return slices.Compact(ips.IPv4), nil
}

func (c Cloudflare) zoneID(ctx context.Context) (string, error) {
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(Zone), nil, &zones); err != nil {
		return "", err
	}
	if len(zones) != 1 || zones[0].Name != Zone || zones[0].ID == "" {
		return "", fmt.Errorf("Cloudflare token sees %d zones named %s, want 1", len(zones), Zone)
	}
	return zones[0].ID, nil
}

// record is a Cloudflare DNS record.
type record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}

// configRule pins SSL Full (strict) for the public names only, leaving the
// zone's other hostnames on their current mode.
type configRule struct {
	ID          string         `json:"id,omitempty"`
	Ref         string         `json:"ref"`
	Description string         `json:"description"`
	Expression  string         `json:"expression"`
	Action      string         `json:"action"`
	Parameters  map[string]any `json:"action_parameters"`
	Enabled     bool           `json:"enabled"`
}

func (r configRule) same(other configRule) bool {
	return r.Expression == other.Expression && r.Action == other.Action && r.Enabled == other.Enabled &&
		len(other.Parameters) == 1 && other.Parameters["ssl"] == "strict"
}

// strictTail reports whether only rules that set nothing but Full (strict),
// such as another cell's, follow rules[i]: a later rule wins, and these
// cannot downgrade it.
func strictTail(rules []configRule, i int) bool {
	for _, r := range rules[i+1:] {
		if r.Action != "set_config" || len(r.Parameters) != 1 || r.Parameters["ssl"] != "strict" {
			return false
		}
	}
	return true
}

// checkStrictTLS verifies the last matching configuration cannot downgrade TLS.
func (c Cloudflare) checkStrictTLS(ctx context.Context, entry string, want configRule) error {
	var ruleset struct {
		Rules []configRule `json:"rules"`
	}
	if err := c.do(ctx, http.MethodGet, entry, nil, &ruleset); err != nil {
		return err
	}
	count := 0
	for _, r := range ruleset.Rules {
		if r.Ref == want.Ref {
			count++
		}
	}
	i := slices.IndexFunc(ruleset.Rules, func(r configRule) bool { return r.Ref == want.Ref })
	if count != 1 || !want.same(ruleset.Rules[i]) || !strictTail(ruleset.Rules, i) {
		return fmt.Errorf("Cloudflare rule %s must be uniquely enabled with SSL Full (strict) at the end of the configuration ruleset", want.Ref)
	}
	return nil
}

// edgeSteps plans the Cloudflare side of the edge: Full (strict) to the
// origin, Authenticated Origin Pulls, then proxied A records to address.
//
// Settings come first so no proxied request reaches the origin without its
// client certificate. A name holding any other record is refused.
func (c Cloudflare) edgeSteps(ctx context.Context, names []string, address netip.Addr, cell string, originPull OriginPull) ([]step, error) {
	if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return nil, fmt.Errorf("%s is not a public IPv4 address", address)
	}
	if err := originPull.Validate(); err != nil {
		return nil, err
	}
	zone, err := c.zoneID(ctx)
	if err != nil {
		return nil, err
	}
	var steps []step
	quoted := make([]string, len(names))
	for i, name := range names {
		if !strings.HasSuffix(name, "."+Zone) {
			return nil, fmt.Errorf("%s is outside zone %s", name, Zone)
		}
		quoted[i] = `"` + name + `"`
	}
	aopEnabled, err := c.originPullState(ctx, zone, names, originPull, false)
	if err != nil {
		return nil, err
	}
	strict := configRule{Ref: "ts-orch-" + cell + "-api-ssl-strict", Description: cell + " public API: Full (strict) to the origin",
		Expression: "(http.host in {" + strings.Join(quoted, " ") + "})", Action: "set_config",
		Parameters: map[string]any{"ssl": "strict"}, Enabled: true}
	entry := "/zones/" + zone + "/rulesets/phases/http_config_settings/entrypoint"
	var ruleset struct {
		ID    string       `json:"id"`
		Rules []configRule `json:"rules"`
	}
	err = c.do(ctx, http.MethodGet, entry, nil, &ruleset)
	if cf, ok := errors.AsType[*cloudflareError](err); ok && cf.Status == http.StatusNotFound {
		err, ruleset.ID = nil, ""
	}
	if err != nil {
		return nil, err
	}
	what := fmt.Sprintf("set SSL Full (strict) for %s (configuration rule %s)", strings.Join(names, ", "), strict.Ref)
	current := slices.IndexFunc(ruleset.Rules, func(r configRule) bool { return r.Ref == strict.Ref })
	for i, r := range ruleset.Rules {
		if r.Ref == strict.Ref && i != current {
			return nil, fmt.Errorf("Cloudflare configuration rule %s is duplicated; resolve it by hand", strict.Ref)
		}
	}
	writeStrict := func(ctx context.Context, method, path string, body any) error {
		if err := c.do(ctx, method, path, body, nil); err != nil {
			return err
		}
		return c.checkStrictTLS(ctx, entry, strict)
	}
	switch {
	case ruleset.ID == "":
		steps = append(steps, step{what, func(ctx context.Context) error {
			return writeStrict(ctx, http.MethodPut, entry, map[string]any{"rules": []configRule{strict}})
		}})
	case current < 0:
		steps = append(steps, step{what, func(ctx context.Context) error {
			return writeStrict(ctx, http.MethodPost, "/zones/"+zone+"/rulesets/"+ruleset.ID+"/rules", strict)
		}})
	case !strict.same(ruleset.Rules[current]) || !strictTail(ruleset.Rules, current):
		id := ruleset.Rules[current].ID
		steps = append(steps, step{what, func(ctx context.Context) error {
			// Cloudflare's documented empty after position moves the rule last.
			body := struct {
				configRule
				Position map[string]string `json:"position"`
			}{strict, map[string]string{"after": ""}}
			return writeStrict(ctx, http.MethodPatch, "/zones/"+zone+"/rulesets/"+ruleset.ID+"/rules/"+id, body)
		}})
	}
	if !aopEnabled {
		steps = append(steps, step{"enable custom zone Authenticated Origin Pulls", func(ctx context.Context) error {
			if err := c.do(ctx, http.MethodPut, "/zones/"+zone+"/origin_tls_client_auth/settings", map[string]bool{"enabled": true}, nil); err != nil {
				return err
			}
			_, err := c.originPullState(ctx, zone, names, originPull, true)
			return err
		}})
	}
	for _, name := range names {
		var records []record
		if err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/dns_records?name="+url.QueryEscape(name), nil, &records); err != nil {
			return nil, err
		}
		want := record{Type: "A", Name: name, Content: address.String(), Proxied: true, TTL: 1}
		method, path, what := http.MethodPost, "/zones/"+zone+"/dns_records", fmt.Sprintf("create A %s %s (proxied)", name, want.Content)
		switch {
		case len(records) == 0:
		case len(records) == 1 && records[0].Type == "A" && records[0].Name == name:
			if records[0].Content == want.Content && records[0].Proxied {
				continue
			}
			method, path = http.MethodPut, path+"/"+records[0].ID
			what = fmt.Sprintf("update A %s %s (proxied %t) -> %s (proxied)", name, records[0].Content, records[0].Proxied, want.Content)
		default:
			return nil, fmt.Errorf("%s already holds %d records; resolve them by hand", name, len(records))
		}
		steps = append(steps, step{what, func(ctx context.Context) error {
			if _, err := c.originPullState(ctx, zone, names, originPull, true); err != nil {
				return err
			}
			if err := c.checkStrictTLS(ctx, entry, strict); err != nil {
				return err
			}
			return c.do(ctx, method, path, want, nil)
		}})
	}
	return steps, nil
}

// OriginCertificate asks Cloudflare's Origin CA to sign a certificate
// request for hostnames, valid for 15 years, and returns its PEM and ID.
func (c Cloudflare) OriginCertificate(ctx context.Context, csrPEM []byte, hostnames []string) (certificate []byte, id string, err error) {
	var issued struct {
		ID          string `json:"id"`
		Certificate string `json:"certificate"`
	}
	err = c.do(ctx, http.MethodPost, "/certificates", map[string]any{"hostnames": hostnames, "requested_validity": originValidityDays,
		"request_type": "origin-rsa", "csr": string(csrPEM)}, &issued)
	return []byte(issued.Certificate), issued.ID, err
}
