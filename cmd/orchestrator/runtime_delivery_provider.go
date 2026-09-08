package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/cloudflare"
	"terrascale.tech/orchestrator/src/orchestrator/control"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// productionDeliveryFile names operator-owned admission and credential files.
// It never accepts health booleans, unsigned manifests, or a replacement mirror.
type productionDeliveryFile struct {
	MembershipFile        string                            `json:"membership_file"`
	ReleaseCatalogFile    string                            `json:"release_catalog_file"`
	ReleaseTrustFiles     map[string]string                 `json:"release_trust_files"`
	CommandSigningKeyFile string                            `json:"command_signing_key_file"`
	MasterSigningKeyFile  string                            `json:"master_signing_key_file"`
	MasterVerifierFiles   []string                          `json:"master_verifier_files"`
	IntentVerifierFiles   []string                          `json:"intent_verifier_files"`
	RegionalLeaders       map[string]string                 `json:"regional_leaders"`
	ObjectStore           productionDeliveryObjectStoreFile `json:"object_store"`
	Cloudflare            productionDeliveryCloudflareFile  `json:"cloudflare"`
	Registry              productionDeliveryRegistryFile    `json:"registry"`
}
type productionDeliveryCloudflareFile struct {
	AccountID               string            `json:"account_id"`
	ZoneID                  string            `json:"zone_id"`
	TokenFile               string            `json:"token_file"`
	CanaryRouteURL          string            `json:"canary_route_url"`
	CanaryProjectID         string            `json:"canary_project_id"`
	CanaryDatabaseID        string            `json:"canary_database_id"`
	CanaryTokenFile         string            `json:"canary_token_file"`
	CanaryForeignTokenFile  string            `json:"canary_foreign_token_file"`
	CanaryExpectedMarker    string            `json:"canary_expected_marker"`
	CanaryMinimumRevision   int64             `json:"canary_minimum_revision"`
	CanaryDownstreamService string            `json:"canary_downstream_service"`
	TailscaleEgressCIDRs    []string          `json:"tailscale_egress_cidrs"`
	SnippetServices         map[string]string `json:"snippet_services"`
	WorkerStages            []int             `json:"worker_stages"`
}
type productionDeliveryRegistryFile struct {
	URL       string `json:"url"`
	TokenFile string `json:"token_file"`
}
type productionDeliveryPlan struct {
	file       productionDeliveryFile
	spec       estate.Spec
	cell       string
	membership *productionDeliveryMembership
}
type constructedProductionDelivery struct {
	Store       provider.DeliveryRegionStoreConfig
	Ownership   *provider.DurableOwnershipJournal
	plan        *productionDeliveryPlan
	lifetime    context.Context
	global      *nats.Conn
	leaders     jetstream.KeyValue
	connections map[string]*nats.Conn
	credentials []*bootstrapcredentials.Credentials
	signers     []*security.CommandSignatureSigner
	once        sync.Once
}

func (f productionDeliveryFile) Admit(spec estate.Spec, cell string) (*productionDeliveryPlan, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	member, err := newProductionDeliveryMembership(spec, f.MembershipFile)
	if err != nil {
		return nil, err
	}
	config, err := member.source.configuration()
	if err != nil {
		return nil, err
	}
	found := false
	for _, region := range config.Regions {
		found = found || region.Code == cell
		if strings.TrimSpace(f.RegionalLeaders[region.Code]) == "" {
			return nil, fmt.Errorf("delivery: regional leaders bucket for %s is required", region.Code)
		}
	}
	if !found || len(f.RegionalLeaders) != len(config.Regions) {
		return nil, errors.New("delivery: exact estate region and leader scopes are required")
	}
	if err := f.ObjectStore.Admit(); err != nil {
		return nil, err
	}
	if len(f.ObjectStore.Regions) != len(spec.Regions) {
		return nil, errors.New("delivery: artifact scopes must cover exact estate")
	}
	for _, region := range spec.Regions {
		bucket, err := delivery.ReleaseBucket(region)
		if err != nil {
			return nil, err
		}
		found := false
		for _, scope := range f.ObjectStore.Regions {
			if scope.Region == region.Code && scope.Bucket == bucket {
				found = true
			}
		}
		if !found {
			return nil, errors.New("delivery: artifact bucket differs from estate")
		}
	}
	keys, err := readProductionReleaseTrust(f.ReleaseTrustFiles)
	if err != nil {
		return nil, err
	}
	catalog, err := hostcontrol.NewSignedReleaseCatalog(f.ReleaseCatalogFile, keys)
	if err != nil {
		return nil, err
	}
	if err = catalog.Validate(context.Background()); err != nil {
		return nil, err
	}
	validationSigner, err := security.LoadCommandSignatureSignerPEM(f.CommandSigningKeyFile)
	if err != nil {
		return nil, err
	}
	_ = validationSigner.Close()
	if _, err = security.LoadCommandSignatureVerifierPEM(f.MasterVerifierFiles); err != nil {
		return nil, err
	}
	if _, err = security.LoadCommandSignatureVerifierPEM(f.IntentVerifierFiles); err != nil {
		return nil, err
	}
	admissionToken, err := readProductionDeliveryToken(f.Cloudflare.TokenFile)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(f.Cloudflare.AccountID) == "" || strings.TrimSpace(f.Cloudflare.ZoneID) == "" {
		return nil, errors.New("delivery: Cloudflare account and zone are required")
	}
	zone, err := cloudflare.Production(nil, f.Cloudflare.TailscaleEgressCIDRs)
	if err != nil {
		return nil, err
	}
	// Constructor validation is local and does not invoke this artifact source.
	client := cloudflare.NewClient(admissionToken, f.Cloudflare.ZoneID, f.Cloudflare.AccountID)
	canary, err := productionCanaryProbe(f.Cloudflare, client)
	if err != nil {
		return nil, err
	}
	if _, err = cloudflare.NewEdgeReleasePromoter(cloudflare.EdgeReleasePromoterConfig{Client: client, Zone: zone, Artifacts: productionDeliveryMirrorSource{}, Health: canary, SnippetServices: f.Cloudflare.SnippetServices, WorkerStages: f.Cloudflare.WorkerStages}); err != nil {
		return nil, err
	}
	if cell == "gru" {
		validationSigner, err := security.LoadCommandSignatureSignerPEM(f.MasterSigningKeyFile)
		if err != nil {
			return nil, err
		}
		_ = validationSigner.Close()
		u, e := url.Parse(f.Registry.URL)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
			return nil, errors.New("delivery: registry requires explicit HTTPS origin")
		}
		if _, err = readProductionDeliveryToken(f.Registry.TokenFile); err != nil {
			return nil, err
		}
	}
	return &productionDeliveryPlan{file: f, spec: spec, cell: cell, membership: member}, nil
}

func (p *productionDeliveryPlan) Construct(ctx context.Context, global *nats.Conn, leaders jetstream.KeyValue) (*constructedProductionDelivery, error) {
	r := &constructedProductionDelivery{plan: p, lifetime: ctx, global: global, leaders: leaders, connections: map[string]*nats.Conn{}}
	if p == nil || ctx == nil || global == nil || leaders == nil {
		return r, errors.New("delivery: admitted plan and authenticated global leaders are required")
	}
	config, err := p.membership.source.configuration()
	if err != nil {
		return r, err
	}
	for _, region := range config.Regions {
		credentials, e := bootstrapcredentials.Load(region.Connection)
		if e != nil {
			return r, e
		}
		r.credentials = append(r.credentials, credentials)
		connection, e := dialBootstrapStore(ctx, bootstrap.ControlNATSStore{URL: credentials.URL, Options: credentials.Options})
		if e != nil {
			return r, e
		}
		r.connections[region.Code] = connection
	}
	r.Store, r.Ownership, err = p.file.ObjectStore.ConstructWithOwnership(ctx, global)
	if err != nil {
		return r, err
	}
	if len(r.Store.Regions) != len(p.spec.Regions) {
		return r, errors.New("delivery: artifact scopes must cover exact estate")
	}
	for _, region := range p.spec.Regions {
		scope, ok := r.Store.Regions[region.Code]
		bucket, e := delivery.ReleaseBucket(region)
		if !ok || e != nil || scope.Bucket != bucket {
			return r, errors.New("delivery: artifact bucket differs from estate")
		}
	}
	return r, nil
}
func (r *constructedProductionDelivery) Close() error {
	if r == nil {
		return nil
	}
	r.once.Do(func() {
		for _, connection := range r.connections {
			connection.Close()
		}
		for _, signer := range r.signers {
			_ = signer.Close()
		}
		for _, credential := range r.credentials {
			_ = credential.Close()
		}
	})
	return nil
}

func (r *constructedProductionDelivery) BindMirror(mirror *delivery.ArtifactMirror) (productionDeliveryConfig, error) {
	var result productionDeliveryConfig
	if r == nil || r.plan == nil || mirror == nil {
		return result, errors.New("delivery: admitted construction and root mirror are required")
	}
	f := r.plan.file
	keys, err := readProductionReleaseTrust(f.ReleaseTrustFiles)
	if err != nil {
		return result, err
	}
	trust, err := delivery.NewTrustSet(keys)
	if err != nil {
		return result, err
	}
	catalog, err := hostcontrol.NewSignedReleaseCatalog(f.ReleaseCatalogFile, keys)
	if err != nil {
		return result, err
	}
	signer, err := security.LoadCommandSignatureSignerPEM(f.CommandSigningKeyFile)
	if err != nil {
		return result, err
	}
	r.signers = append(r.signers, signer)
	masterVerifier, err := security.LoadCommandSignatureVerifierPEM(f.MasterVerifierFiles)
	if err != nil {
		return result, err
	}
	intentVerifier, err := security.LoadCommandSignatureVerifierPEM(f.IntentVerifierFiles)
	if err != nil {
		return result, err
	}
	client, err := hostcontrol.New(hostcontrol.Config{Region: strings.ToUpper(r.plan.cell), Connection: r.connections[r.plan.cell], SigningKey: signer, ResolveHost: r.plan.membership.ResolveHost, Timeout: 30 * time.Second, Authorize: func(ctx context.Context, _ hostcontrol.Host) error { return delivery.CheckExecutionFence(ctx) }, CommandAuthority: func(ctx context.Context, _ hostcontrol.Host) (delivery.RegionalCommandAuthority, error) {
		return delivery.RegionalCommandAuthorityFromContext(ctx)
	}})
	if err != nil {
		return result, err
	}
	host, err := hostcontrol.NewDeliveryControl(hostcontrol.DeliveryConfig{Client: client, ResolveRelease: catalog.ResolveRelease, Timeout: 10 * time.Minute, PollInterval: time.Second})
	if err != nil {
		return result, err
	}
	gates := newProductionDeliveryGates(r.plan.membership, client, catalog)
	result = productionDeliveryConfig{Delegation: &control.MasterDeliveryAdmissionConfig{Connection: r.global, Leaders: r.leaders, MasterVerifier: masterVerifier, IntentVerifier: intentVerifier}, Trust: func() *delivery.TrustSet { return trust }, Rollout: delivery.RolloutConfig{Spec: r.plan.spec, Hosts: r.plan.membership, Control: host, Gates: gates, Edge: regionalDeliveryEdge{}, GateTimeout: 10 * time.Minute}}
	if r.plan.cell == "gru" {
		masterSigner, e := security.LoadCommandSignatureSignerPEM(f.MasterSigningKeyFile)
		if e != nil {
			return result, e
		}
		r.signers = append(r.signers, masterSigner)
		routes := map[string]control.RegionalDeliveryRoute{}
		for cell, connection := range r.connections {
			js, e := jetstream.New(connection)
			if e != nil {
				return result, e
			}
			bounded, cancel := context.WithTimeout(r.lifetime, 10*time.Second)
			bucket, e := js.KeyValue(bounded, f.RegionalLeaders[cell])
			cancel()
			if e != nil {
				return result, e
			}
			routes[cell] = control.RegionalDeliveryRoute{Connection: connection, Leaders: bucket, MasterSignerKeyID: masterSigner.PublicKeyID()}
		}
		registryToken, e := readProductionDeliveryToken(f.Registry.TokenFile)
		if e != nil {
			return result, e
		}
		result.Master = &productionMasterDeliveryConfig{Fetcher: &delivery.ForgejoArtifactFetcher{BaseURL: f.Registry.URL, Token: func() string { return registryToken }}, Signer: masterSigner, Regions: routes, RequestTimeout: 30 * time.Second}
	}
	return result, nil
}

func readProductionReleaseTrust(files map[string]string) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	for id, path := range files {
		raw, err := bootstrapcredentials.ReadFile(path, false, 64<<10)
		if err != nil {
			return nil, err
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
			return nil, errors.New("delivery: exact Ed25519 PUBLIC KEY PEM required")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("delivery: release trust must use Ed25519")
		}
		keys[id] = key
	}
	if _, err := delivery.NewTrustSet(keys); err != nil {
		return nil, err
	}
	return keys, nil
}
func readProductionDeliveryToken(path string) (string, error) {
	raw, err := bootstrapcredentials.ReadFile(path, true, 16<<10)
	if err != nil {
		return "", err
	}
	defer clear(raw)
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, "\r\n\t ") {
		return "", errors.New("delivery: nonempty private token file required")
	}
	return token, nil
}

type productionDeliveryMirrorSource struct {
	mirror *delivery.ArtifactMirror
	region string
}

func (s productionDeliveryMirrorSource) EdgeArtifact(ctx context.Context, service, digest string) ([]byte, error) {
	if s.mirror == nil {
		return nil, errors.New("delivery: root artifact mirror is required")
	}
	reader, ok := s.mirror.Store.(delivery.RegionObjectStoreContentReader)
	if !ok {
		return nil, errors.New("delivery: root mirror content reader is required")
	}
	for _, region := range s.mirror.Spec.Regions {
		if region.Code != s.region {
			continue
		}
		bucket, err := delivery.ReleaseBucket(region)
		if err != nil {
			return nil, err
		}
		stream, identity, err := reader.Get(ctx, region.Code, bucket, delivery.MirrorObject(service, digest))
		if err != nil {
			return nil, err
		}
		if stream == nil {
			return nil, errors.New("delivery: mirrored artifact is absent")
		}
		body, readErr := io.ReadAll(io.LimitReader(stream, delivery.MaxArtifactBytes+1))
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil {
			return nil, errors.Join(readErr, closeErr)
		}
		if len(body) == 0 || int64(len(body)) > delivery.MaxArtifactBytes || !delivery.SameDigest(delivery.SHA256Digest(body), digest) || !delivery.SameDigest(identity.Digest, digest) || identity.Size != int64(len(body)) {
			return nil, errors.New("delivery: mirrored edge artifact identity differs")
		}
		return body, nil
	}
	return nil, errors.New("delivery: mirror does not contain local region")
}
