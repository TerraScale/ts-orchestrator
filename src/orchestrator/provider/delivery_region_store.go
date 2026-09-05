package provider

// This file is the narrow wiring boundary between provider Object Storage and
// delivery.  The delivery package deliberately knows nothing about OCI
// compartments, Regions, or ownership.  Keep those checks here, immediately
// before every provider operation.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

// TerraScaleObjectOwner is the only ownership marker accepted by this
// bridge. It is intentionally not configurable: accepting arbitrary owner
// labels would turn a caller assertion into ownership evidence.
const TerraScaleObjectOwner = "terrascale"

const deliveryObjectOwner = TerraScaleObjectOwner

// DeliveryRegionStoreRegion is the immutable provider scope for one delivery
// Region. Provider is intentionally per-Region: an OCI transport is itself
// bound to one OCI Region and must not be selected by a caller-supplied
// Region string.
type DeliveryRegionStoreRegion struct {
	Provider ObjectStorageProvider
	Region   string
	// OCIRegion is the provider transport's OCI identifier (for example
	// sa-saopaulo-1). Region remains the delivery estate code (for example
	// gru), so callers can bind both identities when the OCI adapter is used.
	OCIRegion     string
	CompartmentID string
	Namespace     string
	Bucket        string
	Owner         string
}

// DeliveryRegionStoreConfig composes the per-Region stores used by delivery.
// Journal is used to bind the provider mutation request generated for the
// delivery seam. OwnershipCheck is optional for tests and local composition;
// production may use it to re-read durable object/bucket ownership immediately
// before a call.
type DeliveryRegionStoreConfig struct {
	Regions        map[string]DeliveryRegionStoreRegion
	Journal        ProviderMutationJournal
	OwnershipCheck func(context.Context, DeliveryRegionStoreRegion) error
}

// DeliveryRegionStore implements delivery.RegionObjectStore and its optional
// identity/fenced seams. Its maps are copied at construction and never mutate,
// making concurrent MirrorAll calls deterministic and race-safe.
type DeliveryRegionStore struct {
	regions        map[string]DeliveryRegionStoreRegion
	journal        ProviderMutationJournal
	ownershipCheck func(context.Context, DeliveryRegionStoreRegion) error
	mu             sync.RWMutex
	putLocks       sync.Map // immutable object key -> *sync.Mutex
}

var (
	_ delivery.RegionObjectStore                     = (*DeliveryRegionStore)(nil)
	_ delivery.RegionObjectStoreInspector            = (*DeliveryRegionStore)(nil)
	_ delivery.RegionObjectStoreIdentityWriter       = (*DeliveryRegionStore)(nil)
	_ delivery.FencedRegionObjectStore               = (*DeliveryRegionStore)(nil)
	_ delivery.FencedRegionObjectStoreIdentityWriter = (*DeliveryRegionStore)(nil)
)

// NewDeliveryRegionStore validates and snapshots a multi-Region composition.
// A durable mutation journal is mandatory because OCI ObjectStorageProvider
// mutation requests require a durable fence.
func NewDeliveryRegionStore(config DeliveryRegionStoreConfig) (*DeliveryRegionStore, error) {
	if config.Journal == nil || !config.Journal.AuthoritativeDurable() {
		return nil, errors.New("provider: delivery object store requires an authoritative durable mutation journal")
	}
	if len(config.Regions) == 0 {
		return nil, errors.New("provider: delivery object store requires at least one Region")
	}
	regions := make(map[string]DeliveryRegionStoreRegion, len(config.Regions))
	for name, input := range config.Regions {
		if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name || strings.ContainsAny(name, "\r\n\t") {
			return nil, errors.New("provider: delivery Region identity is invalid")
		}
		if input.Region == "" {
			input.Region = name
		}
		if input.Region != name || !safeScopePart(input.Region, 63) {
			return nil, fmt.Errorf("provider: delivery Region %q is invalid", name)
		}
		if input.Provider == nil || strings.TrimSpace(input.CompartmentID) == "" ||
			!safeScopePart(input.CompartmentID, 256) || (input.OCIRegion != "" && !safeScopePart(input.OCIRegion, 63)) || !safeScopePart(input.Namespace, 128) ||
			!safeScopePart(input.Bucket, 256) || input.Owner != deliveryObjectOwner {
			return nil, fmt.Errorf("provider: delivery scope for Region %s is invalid", name)
		}
		// OCI transports are bound to one Region. Snapshot the HTTP client so a
		// caller cannot later replace it with a redirect-following client.
		input.Provider = snapshotNoRedirectProvider(input.Provider)
		if oci, ok := input.Provider.(*OCIObjectStorageAdapter); ok && (oci.ObjectStorage == nil || oci.ObjectStorage.Client == nil || oci.ObjectStorage.Config.Endpoint == nil) {
			return nil, fmt.Errorf("provider: object store transport for Region %s is unavailable", input.Region)
		}
		if oci, ok := input.Provider.(*OCIObjectStorageAdapter); ok && input.OCIRegion != "" && oci.ObjectStorage.Config.Region != input.OCIRegion {
			return nil, fmt.Errorf("provider: object store transport is outside Region %s", input.Region)
		}
		regions[name] = input
	}
	return &DeliveryRegionStore{regions: regions, journal: config.Journal, ownershipCheck: config.OwnershipCheck}, nil
}

// NewScopedDeliveryRegionStore composes the common single-Region case.
func NewScopedDeliveryRegionStore(provider ObjectStorageProvider, scope DeliveryRegionStoreRegion, journal ProviderMutationJournal) (*DeliveryRegionStore, error) {
	if scope.Region == "" {
		return nil, errors.New("provider: delivery Region is required")
	}
	return NewDeliveryRegionStore(DeliveryRegionStoreConfig{
		Regions: map[string]DeliveryRegionStoreRegion{scope.Region: func() DeliveryRegionStoreRegion {
			scope.Provider = provider
			return scope
		}()}, Journal: journal,
	})
}

func safeScopePart(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t/\\")
}

// snapshotNoRedirectProvider makes the OCI adapter's transport fail closed on
// redirects. Other ObjectStorageProvider implementations own their own
// transport policy; this bridge never follows provider-returned locations.
func snapshotNoRedirectProvider(value ObjectStorageProvider) ObjectStorageProvider {
	oci, ok := value.(*OCIObjectStorageAdapter)
	if !ok || oci == nil || oci.ObjectStorage == nil || oci.ObjectStorage.Client == nil {
		return value
	}
	transport := *oci.ObjectStorage
	client := *transport.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	transport.Client = &client
	copy := *oci
	copy.ObjectStorage = &transport
	return &copy
}

func (s *DeliveryRegionStore) scope(ctx context.Context, region, bucket, object string) (DeliveryRegionStoreRegion, ObjectRef, error) {
	configured, ref, err := s.regionBucket(ctx, region, bucket)
	if err != nil {
		return DeliveryRegionStoreRegion{}, ObjectRef{}, err
	}
	if !safeObjectKey(object) {
		return DeliveryRegionStoreRegion{}, ObjectRef{}, errors.New("provider: delivery object key is not immutable")
	}
	ref.Name = object
	return configured, ref, nil
}

func (s *DeliveryRegionStore) regionBucket(ctx context.Context, region, bucket string) (DeliveryRegionStoreRegion, ObjectRef, error) {
	if ctx == nil {
		return DeliveryRegionStoreRegion{}, ObjectRef{}, errors.New("provider: delivery object-store context is required")
	}
	if err := ctx.Err(); err != nil {
		return DeliveryRegionStoreRegion{}, ObjectRef{}, err
	}
	if s == nil || s.journal == nil || !s.journal.AuthoritativeDurable() {
		return DeliveryRegionStoreRegion{}, ObjectRef{}, errors.New("provider: delivery object store is unavailable")
	}
	s.mu.RLock()
	configured, ok := s.regions[region]
	s.mu.RUnlock()
	if !ok || configured.Region != region || configured.Bucket != bucket {
		return DeliveryRegionStoreRegion{}, ObjectRef{}, errors.New("provider: delivery object is outside its Region or bucket scope")
	}
	return configured, ObjectRef{Namespace: configured.Namespace, Bucket: configured.Bucket}, nil
}

// authorizeProvider is intentionally called immediately before every
// provider operation. Resolving a Region scope earlier is not ownership
// evidence at the mutation boundary: a bucket may have been replaced or its
// ownership marker may have changed between the scope lookup and the call.
func (s *DeliveryRegionStore) authorizeProvider(ctx context.Context, configured DeliveryRegionStoreRegion) error {
	if ctx == nil {
		return errors.New("provider: delivery object-store context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.ownershipCheck == nil {
		return nil
	}
	return s.ownershipCheck(ctx, configured)
}

func safeObjectKey(object string) bool {
	parts := strings.Split(object, "/")
	if len(parts) != 3 || parts[0] != "releases" || !safeScopePart(parts[1], 256) || parts[1] == "." || parts[1] == ".." || len(parts[2]) != sha256.Size*2 || strings.ToLower(parts[2]) != parts[2] {
		return false
	}
	_, err := hex.DecodeString(parts[2])
	return err == nil
}

func keyDigest(object string) string {
	return strings.Split(object, "/")[2]
}

func digestHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func metadataMatches(metadata ObjectMetadata, digest string, size int64) bool {
	observed := strings.TrimPrefix(strings.TrimSpace(metadata.SHA256), "sha256:")
	return metadata.Size >= 0 && size >= 0 && len(observed) == sha256.Size*2 && strings.EqualFold(observed, digest) && metadata.Size == size
}

func (s *DeliveryRegionStore) mutation(action string, ref ObjectRef, digest string, fence *delivery.OperationFence, ifMatch string, size int) ProviderMutationIntent {
	operation := "delivery-mirror-" + ProviderMutationFingerprint(ref.Namespace, ref.Bucket, ref.Name, digest, action)
	epoch := uint64(1)
	if fence != nil {
		operation, epoch = fence.OperationID, fence.Generation
	}
	ifMatch = strings.TrimSpace(ifMatch)
	intent := ProviderMutationIntent{OperationID: ProviderOperationId{Value: operation}, Scope: ProviderMutationScope("object", ref.Namespace, ref.Bucket, ref.Name), Action: action, Epoch: ProviderEpoch{Value: epoch}, IdempotencyKey: ProviderIdempotencyKey{Value: ProviderMutationFingerprint(operation, ref.Namespace, ref.Bucket, ref.Name, ifMatch)}}
	if action == "object.put" {
		intent.Fingerprint = ObjectPutMutationFingerprint(ObjectPutRequest{Object: ref, Content: make([]byte, size), SHA256: digest})
	} else {
		intent.Fingerprint = ObjectDeleteMutationFingerprint(ObjectDeleteRequest{Object: ref, IfMatch: ifMatch})
	}
	return intent
}

func (s *DeliveryRegionStore) putWithFence(ctx context.Context, region, bucket, object string, body []byte, fence *delivery.OperationFence) (delivery.ObjectIdentity, error) {
	configured, ref, err := s.scope(ctx, region, bucket, object)
	if err != nil {
		return delivery.ObjectIdentity{}, err
	}
	if len(body) == 0 || keyDigest(object) != digestHex(body) {
		return delivery.ObjectIdentity{}, errors.New("provider: delivery artifact bytes do not match immutable key digest")
	}
	if fence != nil && (fence.OperationID == "" || fence.RequestDigest == "" || fence.OwnerID == "" || fence.Generation == 0) {
		return delivery.ObjectIdentity{}, errors.New("provider: delivery operation fence is incomplete")
	}
	lockValue, _ := s.putLocks.LoadOrStore(region+"\x00"+bucket+"\x00"+object, &sync.Mutex{})
	lock := lockValue.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()
	// A read-before-write both makes retries idempotent and prevents an
	// overwrite when an untrusted provider implementation ignores its own
	// If-None-Match contract. The provider PUT still receives the immutable
	// conditional request through ObjectPutRequest's OCI implementation.
	if err := s.authorizeProvider(ctx, configured); err != nil {
		return delivery.ObjectIdentity{}, err
	}
	existing, found, err := configured.Provider.HeadObject(ctx, ref)
	if err != nil {
		return delivery.ObjectIdentity{}, err
	}
	if found {
		if !metadataMatches(existing, keyDigest(object), int64(len(body))) {
			return delivery.ObjectIdentity{}, errors.New("provider: immutable delivery object already contains a different digest")
		}
		return toDeliveryIdentity(existing), nil
	}
	if err := s.authorizeProvider(ctx, configured); err != nil {
		return delivery.ObjectIdentity{}, err
	}
	request := ObjectPutRequest{Object: ref, Content: append([]byte(nil), body...), SHA256: keyDigest(object), Mutation: s.mutation("object.put", ref, keyDigest(object), fence, "", len(body))}
	metadata, err := configured.Provider.PutObject(ctx, request)
	if err != nil {
		return delivery.ObjectIdentity{}, err
	}
	if !metadataMatches(metadata, keyDigest(object), int64(len(body))) {
		return delivery.ObjectIdentity{}, errors.New("provider: delivery object PUT returned an invalid identity")
	}
	return toDeliveryIdentity(metadata), nil
}

func toDeliveryIdentity(metadata ObjectMetadata) delivery.ObjectIdentity {
	digest := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(metadata.SHA256)), "sha256:")
	return delivery.ObjectIdentity{Digest: "sha256:" + digest, Size: metadata.Size, ETag: metadata.ETag}
}

func (s *DeliveryRegionStore) Put(ctx context.Context, region, bucket, object string, body []byte) error {
	_, err := s.putWithFence(ctx, region, bucket, object, body, nil)
	return err
}

func (s *DeliveryRegionStore) PutWithIdentity(ctx context.Context, region, bucket, object string, body []byte) (delivery.ObjectIdentity, error) {
	return s.putWithFence(ctx, region, bucket, object, body, nil)
}

func (s *DeliveryRegionStore) PutFenced(ctx context.Context, region, bucket, object string, body []byte, fence delivery.OperationFence) error {
	_, err := s.putWithFence(ctx, region, bucket, object, body, &fence)
	return err
}

func (s *DeliveryRegionStore) PutWithIdentityFenced(ctx context.Context, region, bucket, object string, body []byte, fence delivery.OperationFence) (delivery.ObjectIdentity, error) {
	return s.putWithFence(ctx, region, bucket, object, body, &fence)
}

func (s *DeliveryRegionStore) Head(ctx context.Context, region, bucket, object string) (delivery.ObjectIdentity, bool, error) {
	configured, ref, err := s.scope(ctx, region, bucket, object)
	if err != nil {
		return delivery.ObjectIdentity{}, false, err
	}
	if err := s.authorizeProvider(ctx, configured); err != nil {
		return delivery.ObjectIdentity{}, false, err
	}
	metadata, found, err := configured.Provider.HeadObject(ctx, ref)
	if err != nil || !found {
		return delivery.ObjectIdentity{}, found, err
	}
	if !metadataMatches(metadata, keyDigest(object), metadata.Size) {
		return delivery.ObjectIdentity{}, false, errors.New("provider: delivery object metadata digest is invalid")
	}
	return toDeliveryIdentity(metadata), true, nil
}

// Get reads an immutable release object and verifies its provider identity and
// complete streamed content before exposing EOF to the caller.
func (s *DeliveryRegionStore) Get(ctx context.Context, region, bucket, object string) (io.ReadCloser, delivery.ObjectIdentity, error) {
	configured, ref, err := s.scope(ctx, region, bucket, object)
	if err != nil {
		return nil, delivery.ObjectIdentity{}, err
	}
	if err := s.authorizeProvider(ctx, configured); err != nil {
		return nil, delivery.ObjectIdentity{}, err
	}
	reader, metadata, err := configured.Provider.GetObject(ctx, ref)
	if err != nil {
		return nil, delivery.ObjectIdentity{}, err
	}
	if reader == nil || !metadataMatches(metadata, keyDigest(object), metadata.Size) {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, delivery.ObjectIdentity{}, errors.New("provider: delivery object GET returned an invalid identity")
	}
	return &deliveryDigestReader{ReadCloser: reader, hash: sha256.New(), expected: keyDigest(object), expectedSize: metadata.Size}, toDeliveryIdentity(metadata), nil
}

func (s *DeliveryRegionStore) HeadObject(ctx context.Context, region, bucket, object string) (delivery.ObjectIdentity, bool, error) {
	return s.Head(ctx, region, bucket, object)
}
func (s *DeliveryRegionStore) GetObject(ctx context.Context, region, bucket, object string) (io.ReadCloser, delivery.ObjectIdentity, error) {
	return s.Get(ctx, region, bucket, object)
}

// Delete removes only an exact immutable key under an explicit ETag fence.
func (s *DeliveryRegionStore) Delete(ctx context.Context, region, bucket, object, ifMatch string) error {
	configured, ref, err := s.scope(ctx, region, bucket, object)
	if err != nil {
		return err
	}
	if !isSafeETag(ifMatch) {
		return errors.New("provider: delivery delete requires an ETag fence")
	}
	if err := s.authorizeProvider(ctx, configured); err != nil {
		return err
	}
	metadata, found, err := configured.Provider.HeadObject(ctx, ref)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if metadata.ETag != ifMatch || !metadataMatches(metadata, keyDigest(object), metadata.Size) {
		return errors.New("provider: delivery delete identity does not match")
	}
	if err := s.authorizeProvider(ctx, configured); err != nil {
		return err
	}
	request := ObjectDeleteRequest{Object: ref, IfMatch: ifMatch, Mutation: s.mutation("object.delete", ref, keyDigest(object), nil, ifMatch, 0)}
	return configured.Provider.DeleteObject(ctx, request)
}

func (s *DeliveryRegionStore) DeleteObject(ctx context.Context, region, bucket, object, ifMatch string) error {
	return s.Delete(ctx, region, bucket, object, ifMatch)
}

// ObjectStorageListProvider is an optional extension to the existing OCI
// ObjectStorageProvider contract. The old contract has no LIST method, so a
// provider that cannot list returns an explicit unsupported error.
type ObjectStorageListProvider interface {
	ListObjects(context.Context, ObjectRef, string) ([]ObjectRef, error)
}

func (s *DeliveryRegionStore) List(ctx context.Context, region, bucket, prefix string) ([]ObjectRef, error) {
	configured, ref, err := s.regionBucket(ctx, region, bucket)
	if err != nil {
		return nil, err
	}
	lister, ok := configured.Provider.(ObjectStorageListProvider)
	if !ok {
		return nil, errors.New("provider: object storage provider does not expose a bounded list operation")
	}
	if strings.ContainsAny(prefix, "\x00\r\n") || strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") {
		return nil, errors.New("provider: delivery list prefix is invalid")
	}
	if err := s.authorizeProvider(ctx, configured); err != nil {
		return nil, err
	}
	ref.Name = prefix
	objects, err := lister.ListObjects(ctx, ref, prefix)
	if err != nil {
		return nil, err
	}
	result := make([]ObjectRef, 0, len(objects))
	for _, object := range objects {
		if object.Namespace != ref.Namespace || object.Bucket != ref.Bucket || !safeObjectKey(object.Name) || !strings.HasPrefix(object.Name, prefix) {
			return nil, errors.New("provider: object list returned an out-of-scope object")
		}
		result = append(result, object)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func (s *DeliveryRegionStore) ListObjects(ctx context.Context, region, bucket, prefix string) ([]ObjectRef, error) {
	return s.List(ctx, region, bucket, prefix)
}

type deliveryDigestReader struct {
	io.ReadCloser
	hash         hash.Hash
	expected     string
	expectedSize int64
	read         int64
	closed       bool
}

func (r *deliveryDigestReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, errors.New("provider: delivery object reader is closed")
	}
	n, err := r.ReadCloser.Read(p)
	r.read += int64(n)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
	}
	if err == io.EOF {
		if r.read != r.expectedSize || hex.EncodeToString(r.hash.Sum(nil)) != r.expected {
			return n, errors.New("provider: delivery object content digest or length is invalid")
		}
	}
	return n, err
}

func (r *deliveryDigestReader) Close() error { r.closed = true; return r.ReadCloser.Close() }
