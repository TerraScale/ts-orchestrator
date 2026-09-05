package preliminarycapture

import (
	"bytes"
	"context"
	"errors"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
)

// CompletedStoreConfig reads historical evidence under a separately admitted,
// current authorization. The old request never authorizes new capture work.
type CompletedStoreConfig struct {
	Context                         context.Context
	CheckAuthorization              func(context.Context) error
	OutputDir                       string
	Request                         VerifiedRequest
	SignedRequest                   []byte
	ExpectedReceiptSHA256           string
	SourcePublicKeyPEM              []byte
	MaxSnapshotBytes, MaxTotalBytes int64
}

// CompletedStore has no publication or cleanup capability. Its exclusive lock
// prevents cooperative capture writers from changing the inventory while read.
type CompletedStore struct {
	store     *Store
	context   context.Context
	authorize func(context.Context) error
	receipt   []byte
	objects   map[string]Object
}

func OpenCompletedStore(c CompletedStoreConfig) (_ *CompletedStore, resultErr error) {
	// Check at the signed issuance time verifies provenance and all structural
	// fields without treating historical capture authorization as current.
	if c.Context == nil || c.Request.Check(c.Request.Request.IssuedAt) != nil || !bytes.Equal(c.SignedRequest, c.Request.Signed) || !digest(c.ExpectedReceiptSHA256) || c.MaxSnapshotBytes < 1024 || c.MaxSnapshotBytes > 1<<30 || c.MaxTotalBytes < c.MaxSnapshotBytes || c.MaxTotalBytes > 256<<30 {
		return nil, errors.New("preliminarycapture: invalid completed capture configuration")
	}
	r := &CompletedStore{context: c.Context, authorize: c.CheckAuthorization, objects: map[string]Object{}}
	if err := r.check(c.Context); err != nil {
		return nil, err
	}
	dir, err := openOutputMode(c.OutputDir, func() error { return r.check(c.Context) }, false)
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, request: c.Request, maximum: c.MaxSnapshotBytes, totalMaximum: c.MaxTotalBytes, allowed: map[string]string{}}
	r.store = s
	defer func() {
		if resultErr != nil {
			s.Close()
		}
	}()
	s.lock, err = s.openFile(".lock", unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(s.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, err
	}
	pinned, found, err := s.read("request.json", MaximumBytes)
	if err != nil || !found || !bytes.Equal(pinned, c.SignedRequest) {
		return nil, errors.Join(errors.New("preliminarycapture: completed request pin differs"), err)
	}
	allowedFiles := map[string]bool{".lock": true, "request.json": true, "receipt.json": true}
	for _, account := range c.Request.Request.Accounts {
		for _, stream := range account.Streams {
			key, _ := ObjectKey(account.Account, stream, c.Request.Request.ControlEpoch)
			s.allowed[key] = account.Account
			allowedFiles[objectFile(key)] = true
		}
	}
	entries, err := s.entries()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !allowedFiles[entry.Name()] {
			return nil, errors.New("preliminarycapture: completed capture contains unadmitted entry")
		}
	}
	raw, found, err := s.read("receipt.json", MaximumBytes)
	if err != nil || !found || delivery.SHA256Digest(raw) != "sha256:"+c.ExpectedReceiptSHA256 {
		return nil, errors.Join(errors.New("preliminarycapture: completed receipt digest differs"), err)
	}
	receipt, err := VerifyReceipt(c.SourcePublicKeyPEM, raw)
	if err != nil {
		return nil, err
	}
	var total int64
	for _, object := range receipt.Objects {
		if object.Size > s.maximum || total > s.totalMaximum-object.Size {
			return nil, errors.New("preliminarycapture: completed inventory exceeds budget")
		}
		total += object.Size
		r.objects[object.Key] = object
	}
	// Reuse the capture receipt's exact inventory and artifact integrity rules;
	// unlike Store.ReadReceipt, this path does not fsync or mutate old evidence.
	if err := s.validateReceipt(raw); err != nil {
		return nil, err
	}
	r.receipt = append([]byte(nil), raw...)
	if err := r.check(c.Context); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *CompletedStore) check(ctx context.Context) error {
	if r == nil || r.context == nil || ctx == nil {
		return errors.New("preliminarycapture: completed reader context required")
	}
	if err := r.context.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.authorize != nil {
		return r.authorize(ctx)
	}
	return nil
}

func (r *CompletedStore) ReadReceipt() ([]byte, bool, error) {
	if err := r.check(r.context); err != nil {
		return nil, false, err
	}
	s := r.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, errors.New("preliminarycapture: completed reader closed")
	}
	raw, found, err := s.read("receipt.json", MaximumBytes)
	if err != nil || !found || !bytes.Equal(raw, r.receipt) {
		return nil, false, errors.Join(errors.New("preliminarycapture: completed receipt changed"), err)
	}
	if err := s.validateReceipt(raw); err != nil {
		return nil, false, err
	}
	if err := r.check(r.context); err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func (r *CompletedStore) GetSnapshot(ctx context.Context, region, bucket, key string) ([]byte, bool, error) {
	if err := r.check(ctx); err != nil {
		return nil, false, err
	}
	s := r.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.scope(ctx, region, bucket, key); err != nil {
		return nil, false, err
	}
	body, found, err := s.read(objectFile(key), s.maximum)
	object := r.objects[key]
	if err != nil || !found || int64(len(body)) != object.Size || delivery.SHA256Digest(body) != object.SHA256 {
		return nil, false, errors.Join(errors.New("preliminarycapture: completed artifact changed"), err)
	}
	if err := r.check(ctx); err != nil {
		return nil, false, err
	}
	return body, true, nil
}

func (r *CompletedStore) Head(ctx context.Context, region, bucket, key string) (delivery.ObjectIdentity, bool, error) {
	body, found, err := r.GetSnapshot(ctx, region, bucket, key)
	if err != nil || !found {
		return delivery.ObjectIdentity{}, found, err
	}
	digest := delivery.SHA256Digest(body)
	return delivery.ObjectIdentity{Digest: digest, Size: int64(len(body)), ETag: digest}, true, nil
}
func (r *CompletedStore) Close() error {
	if r == nil {
		return nil
	}
	return r.store.Close()
}
