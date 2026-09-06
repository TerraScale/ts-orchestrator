package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// Credentials are file references; no private signing material belongs in the runtime JSON.
type productionDeliveryObjectRegionFile struct {
	Region            string `json:"region"`
	OCIRegion         string `json:"oci_region"`
	CompartmentID     string `json:"compartment_id"`
	Namespace         string `json:"namespace"`
	Bucket            string `json:"bucket"`
	Endpoint          string `json:"endpoint"`
	SigningKeyIDFile  string `json:"signing_key_id_file"`
	SigningKeyPEMFile string `json:"signing_key_pem_file"`
}

type productionDeliveryObjectStoreFile struct {
	Regions         []productionDeliveryObjectRegionFile `json:"regions"`
	JournalBucket   string                               `json:"journal_bucket"`
	JournalReplicas int                                  `json:"journal_replicas"`
}

func deliveryScopePart(s string) bool {
	return s != "" && len(s) <= 256 && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "/\\\x00\r\n\t ") && s != "." && s != ".."
}

func (f productionDeliveryObjectStoreFile) Admit() error {
	if len(f.Regions) == 0 || !deliveryScopePart(f.JournalBucket) || strings.ContainsAny(f.JournalBucket, ".*>-") || f.JournalReplicas != 3 {
		return errors.New("delivery object store requires regional scopes and a three-replica journal")
	}
	seen := map[string]bool{}
	for _, r := range f.Regions {
		if !deliveryScopePart(r.Region) || !deliveryScopePart(r.CompartmentID) || !deliveryScopePart(r.Namespace) || !deliveryScopePart(r.Bucket) || seen[r.Region] || !filepath.IsAbs(r.SigningKeyIDFile) || !filepath.IsAbs(r.SigningKeyPEMFile) {
			return errors.New("delivery object store has an incomplete or duplicate regional scope")
		}
		if _, err := r.transport(); err != nil {
			return fmt.Errorf("delivery object region %s: %w", r.Region, err)
		}
		seen[r.Region] = true
	}
	return nil
}

func (f productionDeliveryObjectStoreFile) Construct(ctx context.Context, authenticated *nats.Conn) (provider.DeliveryRegionStoreConfig, error) {
	var result provider.DeliveryRegionStoreConfig
	if err := f.Admit(); err != nil {
		return result, err
	}
	if ctx == nil || authenticated == nil || !authenticated.IsConnected() {
		return result, errors.New("delivery object journal requires the authenticated runtime NATS connection")
	}
	if err := checkDeliveryObjectConnection(authenticated); err != nil {
		return result, err
	}
	// Load and admit all transport credentials before provisioning durable state.
	transports := make(map[string]*provider.OCIHTTPTransport, len(f.Regions))
	for _, r := range f.Regions {
		transport, err := r.transport()
		if err != nil {
			return result, err
		}
		transports[r.Region] = transport
	}
	js, err := jetstream.New(authenticated)
	if err != nil {
		return result, err
	}
	kv, err := js.KeyValue(ctx, f.JournalBucket)
	if errors.Is(err, jetstream.ErrBucketNotFound) {
		kv, err = js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: f.JournalBucket, Storage: jetstream.FileStorage, Replicas: 3, History: 1})
	}
	if err != nil {
		return result, err
	}
	stream, err := js.Stream(ctx, "KV_"+f.JournalBucket)
	if err != nil {
		return result, err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return result, err
	}
	c := info.Config
	if c.Storage != jetstream.FileStorage || c.Replicas != 3 || c.MaxAge != 0 || c.MaxMsgsPerSubject != 1 || c.Mirror != nil || len(c.Sources) != 0 || !c.AllowRollup || !c.DenyDelete || c.DenyPurge || c.Discard != jetstream.DiscardNew {
		return result, errors.New("delivery provider journal is not an authoritative non-expiring file-backed R3 KV stream")
	}
	cas, err := provider.NewNatsOwnershipCASStore(kv)
	if err != nil {
		return result, err
	}
	result.Journal, err = provider.NewCASProviderMutationJournal(cas)
	if err != nil {
		return result, err
	}
	result.Regions = make(map[string]provider.DeliveryRegionStoreRegion, len(f.Regions))
	for _, r := range f.Regions {
		adapter, err := provider.NewOCIObjectStorageAdapter(transports[r.Region], result.Journal)
		if err != nil {
			return provider.DeliveryRegionStoreConfig{}, err
		}
		result.Regions[r.Region] = provider.DeliveryRegionStoreRegion{Provider: adapter, Region: r.Region, OCIRegion: r.OCIRegion, CompartmentID: r.CompartmentID, Namespace: r.Namespace, Bucket: r.Bucket, Owner: provider.TerraScaleObjectOwner}
	}
	result.OwnershipCheck = func(ctx context.Context, scope provider.DeliveryRegionStoreRegion) error {
		transport := transports[scope.Region]
		if transport == nil || transport.Config.Region != scope.OCIRegion {
			return errors.New("delivery ownership scope has no regional transport")
		}
		observed, found, err := provider.ObserveOCIBucket(ctx, transport, scope.Namespace, scope.Bucket)
		if err != nil {
			return err
		}
		if !found || observed.CompartmentID != scope.CompartmentID || observed.Namespace != scope.Namespace || observed.Name != scope.Bucket || !provider.HasOCIOwnershipTags(observed.FreeformTags, "bucket", scope.Region) {
			return errors.New("delivery bucket ownership was not established by OCI")
		}
		return nil
	}
	return result, nil
}

func (r productionDeliveryObjectRegionFile) transport() (*provider.OCIHTTPTransport, error) {
	cfg, err := provider.NewOCIServiceTransportConfig(provider.OCIServiceObjectStorage, r.OCIRegion, r.Endpoint)
	if err != nil {
		return nil, err
	}
	identity, err := bootstrapcredentials.ReadFile(r.SigningKeyIDFile, true, 16<<10)
	if err != nil {
		return nil, err
	}
	defer clear(identity)
	keyID := strings.TrimSpace(string(identity))
	if keyID == "" || strings.ContainsAny(keyID, "\x00\r\n\t\"") {
		return nil, errors.New("invalid delivery OCI signing identity")
	}
	raw, err := bootstrapcredentials.ReadFile(r.SigningKeyPEMFile, true, 64<<10)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	block, rest := pem.Decode(raw)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid delivery OCI RSA PEM")
	}
	defer clear(block.Bytes)
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	default:
		return nil, errors.New("invalid delivery OCI RSA PEM type")
	}
	if err != nil || key == nil {
		return nil, errors.New("invalid delivery OCI RSA key")
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	cfg.MaxObjectBytes = 1 << 30
	return provider.NewOCIInstancePrincipalTransport(cfg, nil, keyID, key)
}

func checkDeliveryObjectConnection(connection *nats.Conn) error {
	if connection == nil || !connection.IsConnected() || !connection.AuthRequired() || connection.Opts.SignatureCB == nil || (connection.Opts.Nkey == "" && connection.Opts.UserJWT == nil) {
		return errors.New("delivery journal requires connected NKey-authenticated NATS")
	}
	if connection.Opts.AllowReconnect && connection.Opts.ReconnectBufSize >= 0 {
		return errors.New("delivery journal requires disabled reconnect publication buffering")
	}
	state, err := connection.TLSConnectionState()
	if err != nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		return errors.New("delivery journal requires verified TLS 1.3")
	}
	cfg := connection.Opts.TLSConfig
	if cfg == nil || cfg.InsecureSkipVerify || (len(cfg.Certificates) == 0 && cfg.GetClientCertificate == nil && connection.Opts.TLSCertCB == nil) {
		return errors.New("delivery journal requires a client TLS identity")
	}
	return nil
}
