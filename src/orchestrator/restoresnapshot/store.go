// Package restoresnapshot persists and verifies control snapshots in OCI.
package restoresnapshot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
)

// Region binds a transport and durable ownership identity to one bucket.
// BucketResourceID is the exact resource identity recorded by reconciliation.
type Region struct {
	Transport                                                     *provider.OCIHTTPTransport
	OCIRegion, Namespace, Bucket, BucketResourceID, CompartmentID string
	OwnershipGeneration                                           uint64
}

type Config struct {
	Regions      map[string]Region
	SourceRegion string
	Prefix       string
	MaxBytes     int64
	Journal      provider.ProviderMutationJournal
	Ownership    *provider.DurableOwnershipJournal
	// Authorize verifies live global mutation authority at snapshotControlEpoch
	// and permission to write the specified destination Region. The term is
	// snapshot.ControlEpoch, never the destination's regional election term.
	// Missing, expired, or mismatched global authority and out-of-scope
	// destinations must return an error before each new PUT.
	Authorize func(ctx context.Context, destinationRegion string, snapshotControlEpoch uint64) error
}

type binding struct {
	region  Region
	objects *provider.OCIObjectStorageAdapter
}
type Store struct {
	regions        map[string]binding
	source, prefix string
	max            int64
	ownership      *provider.DurableOwnershipJournal
	authorize      func(context.Context, string, uint64) error
}

var _ restoredrill.SnapshotObjectStore = (*Store)(nil)
var _ restoredrill.VerifiedSnapshotMirror = (*Store)(nil)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var suffix = regexp.MustCompile(`\.epoch-([1-9][0-9]*)\.snapshot$`)

func New(config Config) (*Store, error) {
	if config.Journal == nil || !config.Journal.AuthoritativeDurable() || config.Ownership == nil || !config.Ownership.AuthoritativeDurable() || config.Authorize == nil || len(config.Regions) == 0 {
		return nil, errors.New("snapshot: durable journal, ownership and live authority are required")
	}
	if config.MaxBytes == 0 {
		config.MaxBytes = 64 << 20
	}
	if config.MaxBytes < 1 || config.MaxBytes > 1<<30 {
		return nil, errors.New("snapshot: invalid byte limit")
	}
	if config.Prefix == "" {
		config.Prefix = "jetstream/control/"
	}
	if !strings.HasSuffix(config.Prefix, "/") || path.Clean(config.Prefix)+"/" != config.Prefix || strings.HasPrefix(config.Prefix, "/") || strings.Contains(config.Prefix, "..") {
		return nil, errors.New("snapshot: invalid prefix")
	}
	for _, part := range strings.Split(strings.TrimSuffix(config.Prefix, "/"), "/") {
		if !token(part) {
			return nil, errors.New("snapshot: invalid prefix component")
		}
	}
	s := &Store{regions: make(map[string]binding), source: config.SourceRegion, prefix: config.Prefix, max: config.MaxBytes, ownership: config.Ownership, authorize: config.Authorize}
	for code, r := range config.Regions {
		if !token(code) || !token(r.Namespace) || !token(r.Bucket) || r.BucketResourceID == "" || r.CompartmentID == "" || r.OwnershipGeneration == 0 || r.Transport == nil || r.Transport.Client == nil || r.Transport.Signer == nil || r.OCIRegion == "" || r.Transport.Config.Region != r.OCIRegion {
			return nil, fmt.Errorf("snapshot: invalid Region %q", code)
		}
		if httpTransport, ok := r.Transport.Client.Transport.(*http.Transport); ok && httpTransport.TLSClientConfig != nil && httpTransport.TLSClientConfig.InsecureSkipVerify {
			return nil, errors.New("snapshot: OCI TLS verification is required")
		}
		transport := *r.Transport
		client := *transport.Client
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		transport.Client = &client
		adapter, err := provider.NewOCIObjectStorageAdapter(&transport, config.Journal)
		if err != nil {
			return nil, err
		}
		r.Transport = nil
		s.regions[code] = binding{r, adapter}
	}
	if _, ok := s.regions[s.source]; !ok {
		return nil, errors.New("snapshot: source Region is not configured")
	}
	return s, nil
}
func token(v string) bool {
	return v != "" && len(v) <= 256 && strings.TrimSpace(v) == v && !strings.ContainsAny(v, "/\\\x00\r\n\t") && v != "." && v != ".."
}
func (s *Store) resolve(ctx context.Context, region, bucket, key string) (binding, provider.ObjectRef, uint64, error) {
	if ctx == nil {
		return binding{}, provider.ObjectRef{}, 0, errors.New("snapshot: context is required")
	}
	if err := ctx.Err(); err != nil {
		return binding{}, provider.ObjectRef{}, 0, err
	}
	if s == nil {
		return binding{}, provider.ObjectRef{}, 0, errors.New("snapshot: unavailable")
	}
	b, ok := s.regions[region]
	if !ok || bucket != b.region.Bucket || !strings.HasPrefix(key, s.prefix) || !token(strings.TrimPrefix(key, s.prefix)) {
		return binding{}, provider.ObjectRef{}, 0, errors.New("snapshot: object outside configured scope")
	}
	match := suffix.FindStringSubmatch(key)
	if len(match) != 2 {
		return binding{}, provider.ObjectRef{}, 0, errors.New("snapshot: epoch missing")
	}
	epoch, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		return binding{}, provider.ObjectRef{}, 0, err
	}
	if err := s.owned(ctx, region, b); err != nil {
		return binding{}, provider.ObjectRef{}, 0, err
	}
	return b, provider.ObjectRef{Namespace: b.region.Namespace, Bucket: bucket, Name: key}, epoch, nil
}
func (s *Store) owned(ctx context.Context, region string, b binding) error {
	record, found, err := s.ownership.Lookup(ctx, provider.ProviderResourceId{Value: b.region.BucketResourceID})
	if err != nil {
		return err
	}
	if !found || record.CellId.Value != region || record.CompartmentId.Value != b.region.CompartmentID || record.Generation.Value != b.region.OwnershipGeneration {
		return errors.New("snapshot: bucket ownership is missing or changed")
	}
	return nil
}
func (s *Store) validMetadata(m provider.ObjectMetadata) bool {
	digest := m.SHA256
	return len(digest) == 64 && digestPattern.MatchString(digest) && m.Size > 0 && m.Size <= s.max && m.ETag != ""
}
func identity(m provider.ObjectMetadata) delivery.ObjectIdentity {
	return delivery.ObjectIdentity{Digest: "sha256:" + m.SHA256, Size: m.Size, ETag: m.ETag}
}
func (s *Store) Head(ctx context.Context, region, bucket, key string) (delivery.ObjectIdentity, bool, error) {
	b, ref, _, err := s.resolve(ctx, region, bucket, key)
	if err != nil {
		return delivery.ObjectIdentity{}, false, err
	}
	m, found, err := b.objects.HeadObject(ctx, ref)
	if err != nil || !found {
		return delivery.ObjectIdentity{}, found, err
	}
	if !s.validMetadata(m) {
		return delivery.ObjectIdentity{}, false, errors.New("snapshot: invalid provider metadata")
	}
	return identity(m), true, nil
}
func (s *Store) GetSnapshot(ctx context.Context, region, bucket, key string) ([]byte, bool, error) {
	b, ref, _, err := s.resolve(ctx, region, bucket, key)
	if err != nil {
		return nil, false, err
	}
	head, found, err := b.objects.HeadObject(ctx, ref)
	if err != nil || !found {
		return nil, found, err
	}
	if !s.validMetadata(head) {
		return nil, false, errors.New("snapshot: invalid provider metadata")
	}
	if err = s.owned(ctx, region, b); err != nil {
		return nil, false, err
	}
	reader, m, err := b.objects.GetObject(ctx, ref)
	if err != nil {
		return nil, false, err
	}
	if reader == nil {
		return nil, false, errors.New("snapshot: missing response body")
	}
	body, readErr := io.ReadAll(io.LimitReader(reader, s.max+1))
	closeErr := reader.Close()
	if err = errors.Join(readErr, closeErr); err != nil {
		return nil, false, err
	}
	if !s.validMetadata(m) || m != head || int64(len(body)) != m.Size || delivery.SHA256Digest(body) != "sha256:"+m.SHA256 {
		return nil, false, errors.New("snapshot: content verification failed")
	}
	return body, true, nil
}
func (s *Store) Put(ctx context.Context, region, bucket, key string, body []byte) error {
	b, ref, epoch, err := s.resolve(ctx, region, bucket, key)
	if err != nil {
		return err
	}
	if len(body) == 0 || int64(len(body)) > s.max {
		return errors.New("snapshot: invalid body size")
	}
	body = append([]byte(nil), body...)
	existing, found, err := s.GetSnapshot(ctx, region, bucket, key)
	if err != nil {
		return err
	}
	digest := delivery.SHA256Digest(body)
	if found {
		if delivery.SHA256Digest(existing) != digest {
			return errors.New("snapshot: immutable object conflict")
		}
		return nil
	}
	if err = s.owned(ctx, region, b); err != nil {
		return err
	}
	if err := s.authorize(ctx, region, epoch); err != nil {
		return err
	}
	req := provider.ObjectPutRequest{Object: ref, Content: body, SHA256: strings.TrimPrefix(digest, "sha256:")}
	op := "control-snapshot-" + provider.ProviderMutationFingerprint(region, ref.Namespace, ref.Bucket, key)
	req.Mutation = provider.ProviderMutationIntent{OperationID: provider.ProviderOperationId{Value: op}, Epoch: provider.ProviderEpoch{Value: epoch}, Action: "object.put", Scope: provider.ObjectPutMutationScope(req), Fingerprint: provider.ObjectPutMutationFingerprint(req), IdempotencyKey: provider.ProviderIdempotencyKey{Value: provider.ProviderMutationFingerprint(op, digest)}}
	if _, err = b.objects.PutObject(ctx, req); err != nil {
		return err
	}
	verified, found, err := s.GetSnapshot(ctx, region, bucket, key)
	if err != nil {
		return err
	}
	if !found || delivery.SHA256Digest(verified) != digest {
		return errors.New("snapshot: uploaded bytes are not readable")
	}
	return nil
}
func (s *Store) Mirror(ctx context.Context, snapshot restoredrill.ControlStateSnapshot, region string) error {
	if s == nil {
		return errors.New("snapshot: unavailable")
	}
	target, ok := s.regions[region]
	if !ok {
		return errors.New("snapshot: mirror Region is not configured")
	}
	source := s.regions[s.source]
	body, found, err := s.GetSnapshot(ctx, s.source, source.region.Bucket, snapshot.ObjectKey)
	if err != nil {
		return err
	}
	if !found || !matches(snapshot, body) {
		return errors.New("snapshot: source identity mismatch")
	}
	if err = s.Put(ctx, region, target.region.Bucket, snapshot.ObjectKey, body); err != nil {
		return err
	}
	return s.VerifyMirror(ctx, snapshot, region)
}
func (s *Store) VerifyMirror(ctx context.Context, snapshot restoredrill.ControlStateSnapshot, region string) error {
	if s == nil {
		return errors.New("snapshot: unavailable")
	}
	target, ok := s.regions[region]
	if !ok {
		return errors.New("snapshot: mirror Region is not configured")
	}
	body, found, err := s.GetSnapshot(ctx, region, target.region.Bucket, snapshot.ObjectKey)
	if err != nil {
		return err
	}
	if !found || !matches(snapshot, body) {
		return errors.New("snapshot: mirror identity mismatch")
	}
	return nil
}
func matches(s restoredrill.ControlStateSnapshot, body []byte) bool {
	return s.ControlEpoch > 0 && strings.HasSuffix(s.ObjectKey, ".epoch-"+strconv.FormatUint(s.ControlEpoch, 10)+".snapshot") && s.Size == int64(len(body)) && s.Checksum == delivery.SHA256Digest(body)
}
