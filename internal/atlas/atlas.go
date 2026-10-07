// Package atlas publishes the cell's topology to ts-atlas, TerraScale's
// region discovery (ts-atlas docs/discovery-v1.md §Publishing): the
// authority leader probes every region's readyz and POSTs the signed
// document every Interval, so Atlas never serves an empty or stale topology
// after a re-found, a scale or a region change.
package atlas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/vaultsecret"
	sdkatlas "terrascale.tech/sdk/atlas"
)

const (
	// Interval is how often the leader publishes: the contract asks for
	// about 10 s, well inside Atlas' STALE_AFTER_S (60 s).
	Interval = 10 * time.Second
	// StaleAfter is Atlas' STALE_AFTER_S: past it every region reads
	// "unknown", so the loop alerts once no publish succeeded for this long.
	StaleAfter = 60 * time.Second
	// Role names the publish key's Vault secret, <cell>-<n>-atlas-publish-key.
	Role = "atlas"
	// KeyName is the publish key's Vault key: gru-1-atlas-publish-key.
	KeyName      = "ATLAS_PUBLISH_KEY"
	probeTimeout = 2500 * time.Millisecond
)

// Required lists the services every topology carries (ts-atlas
// REQUIRED_SERVICES); Atlas refuses a topology without one.
var Required = []string{"terrabase", "auth", "dashboard", "status", "docs"}

var regionID = regexp.MustCompile(`^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Config is the cell spec's atlas section: where Atlas is, the Vault secret
// holding the P-256 publish key, and the topology without its health.
type Config struct {
	URL        string          `json:"url"`
	PublishKey vaultsecret.Ref `json:"publish_key"`
	Regions    []Region        `json:"regions"`
	Services   []Service       `json:"services"`
}

// Region is one region of the topology; its health is probed at publish.
type Region struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Country string  `json:"country"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	API     string  `json:"api"`
	Auth    string  `json:"auth"`
}

// Service is one entry of the service catalog.
type Service = sdkatlas.Service

// Validate checks what the controller relies on; Atlas validates the rest
// at publish and refuses the whole document on any error.
func (c Config) Validate(cell string) error {
	if parsed, err := url.Parse(c.URL); err != nil || !httpsURL(c.URL) || strings.Trim(parsed.Path, "/") != "" {
		return errors.New("atlas url must be an https origin without a path")
	}
	if err := vaultsecret.ValidateRefs(cell, Role, map[string]vaultsecret.Ref{KeyName: c.PublishKey}, nil); err != nil {
		return err
	}
	if len(c.Regions) == 0 || len(c.Regions) > 64 || len(c.Services) > 32 {
		return errors.New("atlas needs 1 to 64 regions and at most 32 services")
	}
	seen := map[string]bool{}
	for _, region := range c.Regions {
		if !regionID.MatchString(region.ID) || seen[region.ID] || !httpsURL(region.API) || !httpsURL(region.Auth) {
			return fmt.Errorf("atlas region %q needs a unique region id and https api and auth origins", region.ID)
		}
		seen[region.ID] = true
	}
	ids := map[string]bool{}
	for _, service := range c.Services {
		if service.ID == "" || ids[service.ID] || !httpsURL(service.URL) {
			return fmt.Errorf("atlas service %q needs a unique id and an https url", service.ID)
		}
		ids[service.ID] = true
	}
	for _, id := range Required {
		if !ids[id] {
			return fmt.Errorf("atlas services must list %s", id)
		}
	}
	return nil
}

// AddRegion returns c with region cell (sfo-1) listed as the catalog
// describes it, with its regional API and auth origins, in catalog order.
// added is false when cell is already listed exactly so; a different entry
// for cell is refused.
func (c Config) AddRegion(cell string) (next Config, added bool, err error) {
	name, index, _ := strings.Cut(cell, "-")
	entry, known := catalog.LookupName(name)
	if n, err := strconv.Atoi(index); !known || err != nil || n < 1 || strconv.Itoa(n) != index {
		return c, false, fmt.Errorf("cell %q is not <catalog region>-<n>, such as %s-1", cell, catalog.Names()[0])
	}
	region := Region{ID: cell, Name: entry.City, Country: entry.Country, Lat: entry.Latitude, Lon: entry.Longitude,
		API: "https://" + name + ".api.terrascale.tech", Auth: "https://" + name + ".auth.terrascale.tech"}
	if i := slices.IndexFunc(c.Regions, func(r Region) bool { return r.ID == cell }); i >= 0 {
		if c.Regions[i] != region {
			return c, false, fmt.Errorf("atlas already lists region %s as %+v, not the catalog's %+v", cell, c.Regions[i], region)
		}
		return c, false, nil
	}
	// Regions outside the catalog sort last; cells of one region by number.
	order := func(r Region) (int, int) {
		name, index, _ := strings.Cut(r.ID, "-")
		n, _ := strconv.Atoi(index)
		if i := slices.Index(catalog.Names(), name); i >= 0 {
			return i, n
		}
		return catalog.Len, n
	}
	at := slices.IndexFunc(c.Regions, func(r Region) bool {
		ri, rn := order(r)
		ni, nn := order(region)
		return ri > ni || ri == ni && rn > nn
	})
	if at < 0 {
		at = len(c.Regions)
	}
	c.Regions = slices.Insert(slices.Clone(c.Regions), at, region)
	return c, true, nil
}

func httpsURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}

// Publisher signs and posts topologies with Key through the ts-go Atlas
// client, keeping updated monotonic.
type Publisher struct {
	HTTP *http.Client
	Key  *ecdsa.PrivateKey
	last int64
}

// ErrUnauthorized is Atlas refusing the signature: the key is not in
// PUBLISH_KEYS, or the clock is off by more than 300 s.
var ErrUnauthorized = errors.New("atlas refused the publish signature")

// Publish probes every region's readyz and publishes the topology. It
// succeeds only when Atlas wrote it ("updated"). A non-nil guard runs right
// before the POST, so a controller that lost authority meanwhile publishes
// nothing.
func (p *Publisher) Publish(ctx context.Context, config Config, now time.Time, guard func(context.Context) error) error {
	doc := sdkatlas.Topology{V: 1, Updated: max(now.Unix(), p.last+1), Services: config.Services}
	doc.Regions = make([]sdkatlas.Region, len(config.Regions))
	var probes sync.WaitGroup
	for i, entry := range config.Regions {
		doc.Regions[i] = sdkatlas.Region{ID: entry.ID, Name: entry.Name, Country: entry.Country, Lat: entry.Lat, Lon: entry.Lon, API: entry.API, Auth: entry.Auth}
		probes.Go(func() { doc.Regions[i].OK = ready(ctx, p.HTTP, entry.API) })
	}
	probes.Wait()
	if guard != nil {
		if err := guard(ctx); err != nil {
			return err
		}
	}
	client := sdkatlas.Publisher{BaseURL: config.URL, Key: p.Key, HTTPClient: p.HTTP}
	report, err := client.Publish(ctx, sdkatlas.Document{Topology: &doc})
	if refused, ok := errors.AsType[*sdkatlas.Error](err); ok && refused.Status == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	if report.Topology != "updated" {
		return fmt.Errorf("atlas answered topology %q", report.Topology)
	}
	p.last = doc.Updated
	return nil
}

// ready is the region's GET <api>/readyz verdict.
func ready(ctx context.Context, client *http.Client, api string) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(api, "/")+"/readyz", nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	return response.StatusCode == http.StatusOK
}

// NewKey returns a new P-256 publish key in PKCS #8 PEM, the Vault form.
func NewKey(context.Context) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ParseKey reads a PKCS #8 PEM P-256 publish key.
func ParseKey(value string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("the atlas publish key is not a PKCS #8 PEM key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("the atlas publish key is not a P-256 key")
	}
	return key, nil
}

// VaultKey reads the publish key with the instance principal, as the
// controllers do.
func VaultKey(ctx context.Context, ref vaultsecret.Ref) (*ecdsa.PrivateKey, error) {
	values, err := vaultsecret.ReadRefs(ctx, map[string]vaultsecret.Ref{KeyName: ref})
	if err != nil {
		return nil, err
	}
	return ParseKey(values[KeyName])
}

// JWKS is the PUBLISH_KEYS value for key's public half.
func JWKS(key *ecdsa.PrivateKey) (string, error) {
	point, err := key.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(point[1:33]), "y": base64.RawURLEncoding.EncodeToString(point[33:])}}})
	return string(encoded), err
}

// Loop is the leader's publisher: Run calls tick every Interval.
type Loop struct {
	Publisher
	// Config is the cell spec's atlas section, nil when the cell publishes
	// nothing; only Authority's leader publishes.
	Config    func() *Config
	Authority authority.Fencer
	// LoadKey reads the publish key from the Vault.
	LoadKey func(context.Context, vaultsecret.Ref) (*ecdsa.PrivateKey, error)

	ref     vaultsecret.Ref
	reading *keyRead  // the key read in flight, at most one
	since   time.Time // last success, or when this controller took the job
	alerted bool
}

type keyRead struct {
	ref  vaultsecret.Ref
	done chan keyResult
}

type keyResult struct {
	key *ecdsa.PrivateKey
	err error
}

// Run publishes until ctx ends.
func (l *Loop) Run(ctx context.Context) error {
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		l.tick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (l *Loop) tick(ctx context.Context, now time.Time) {
	config, snapshot := l.Config(), l.Authority.Current()
	if config == nil || !snapshot.CanMutate() {
		l.follow()
		return
	}
	if l.since.IsZero() {
		l.since = now
	}
	err := l.publish(ctx, *config, now, snapshot.Epoch)
	if errors.Is(err, authority.ErrNotLeader) || errors.Is(err, authority.ErrFenced) {
		l.follow()
		return
	}
	if err == nil {
		if l.alerted {
			slog.Info("Atlas topology is current again", observability.ComponentKey, "atlas", observability.EventKey, true)
		}
		l.since, l.alerted = now, false
		return
	}
	if errors.Is(err, ErrUnauthorized) {
		l.Key = nil // re-read a rotated key
	}
	slog.Warn("Atlas publish failed", observability.ComponentKey, "atlas", "error", err)
	if !l.alerted && now.Sub(l.since) >= StaleAfter {
		l.alerted = true
		slog.Error("ALERT Atlas topology is stale: no publish succeeded", observability.ComponentKey, "atlas",
			"since", l.since, "error", err, observability.EventKey, true)
	}
}

// follow drops the job: another controller, or nobody, owns it, and it
// starts afresh if it comes back here.
func (l *Loop) follow() { l.since, l.alerted = time.Time{}, false }

// publish bounds the whole attempt, the key read included, by Interval, so
// a hung Vault read cannot hold the loop past StaleAfter without an alert.
func (l *Loop) publish(parent context.Context, config Config, now time.Time, epoch uint64) error {
	ctx, cancel := context.WithTimeout(parent, Interval)
	defer cancel()
	if l.Key == nil || l.ref != config.PublishKey {
		key, err := l.loadKey(parent, ctx, config.PublishKey)
		if err != nil {
			return err
		}
		l.Key, l.ref = key, config.PublishKey
	}
	return l.Publish(ctx, config, now, func(ctx context.Context) error { return l.Authority.Guard(ctx, epoch) })
}

// loadKey keeps one key read in flight and stops waiting for it at ctx's
// deadline even when the read ignores it: the instance principal's setup
// takes no context. Later attempts wait on the same read instead of starting
// another, so a stalled Vault or metadata service never piles reads up. The
// read runs on parent, bounded by StaleAfter, so a slow one can still finish.
func (l *Loop) loadKey(parent, ctx context.Context, ref vaultsecret.Ref) (*ecdsa.PrivateKey, error) {
	if l.reading == nil {
		read := &keyRead{ref: ref, done: make(chan keyResult, 1)}
		go func() {
			readCtx, cancel := context.WithTimeout(parent, StaleAfter)
			defer cancel()
			key, err := l.LoadKey(readCtx, ref)
			read.done <- keyResult{key, err}
		}()
		l.reading = read
	}
	select {
	case result := <-l.reading.done:
		read := l.reading
		l.reading = nil
		if read.ref != ref {
			return nil, errors.New("the atlas publish key ref changed during its read")
		}
		return result.key, result.err
	case <-ctx.Done():
		return nil, fmt.Errorf("read the atlas publish key: %w", ctx.Err())
	}
}
