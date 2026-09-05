package sourcepublication

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"reflect"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/restoresnapshot"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// Config binds one finite source upload to its historical local artifacts.
type Config struct {
	Upload              preliminarytransfer.VerifiedUpload
	OutputDir, StateDir string
	Journal             provider.OwnershipCASStore
	Regions             map[string]restoresnapshot.Region
	Signer              *security.CommandSignatureSigner
	Guard               func(context.Context) error
}

type guardedTransport struct {
	base  http.RoundTripper
	guard func(context.Context) error
}

func (t guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.guard(req.Context()); err != nil {
		return nil, err
	}
	response, err := t.base.RoundTrip(req)
	if check := t.guard(req.Context()); check != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		return nil, check
	}
	return response, err
}

// Publish never opens a source capture connection or creates snapshot bytes.
// A durable local receipt is reused verbatim under later same-scope authority.
func Publish(ctx context.Context, c Config) ([]byte, error) {
	if ctx == nil || c.Guard == nil || c.Signer == nil || c.Journal == nil {
		return nil, errors.New("sourcepublication: incomplete configuration")
	}
	check := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.Upload.Check(time.Now().UTC()); err != nil {
			return err
		}
		return c.Guard(ctx)
	}
	if err := check(ctx); err != nil {
		return nil, err
	}
	scope := c.Upload.Scope.Scope
	sourceID, err := preliminarytransfer.PublicKeyID([]byte(scope.SourcePublicKeyPEM))
	if err != nil || c.Signer.PublicKeyID() != sourceID {
		return nil, errors.New("sourcepublication: receipt signer differs")
	}
	state, err := OpenState(ctx, c.StateDir, c.Upload, check)
	if err != nil {
		return nil, err
	}
	defer state.Close()
	historical, err := c.Upload.Scope.HistoricalCapture()
	if err != nil {
		return nil, err
	}
	local, err := preliminarycapture.OpenCompletedStore(preliminarycapture.CompletedStoreConfig{Context: ctx, CheckAuthorization: check, OutputDir: c.OutputDir, Request: historical, SignedRequest: scope.CaptureRequest, ExpectedReceiptSHA256: scope.ReceiptSHA256, SourcePublicKeyPEM: []byte(scope.SourcePublicKeyPEM), MaxSnapshotBytes: scope.MaxSnapshotBytes, MaxTotalBytes: scope.MaxTotalBytes})
	if err != nil {
		return nil, err
	}
	defer local.Close()
	receiptRaw, err := state.ReadReceipt(ctx)
	if err != nil {
		return nil, err
	}
	var old preliminarytransfer.PublicationReceipt
	if len(receiptRaw) > 0 {
		old, err = preliminarytransfer.CheckPublicationForScope(c.Upload.Scope, receiptRaw)
		if err != nil {
			return nil, err
		}
	}
	regions := make(map[string]restoresnapshot.Region)
	keys := []string{}
	destinations := make(map[string]preliminarytransfer.Destination)
	for _, d := range scope.Destinations {
		r, ok := c.Regions[d.Region]
		if !ok || r.Transport == nil || r.Transport.Client == nil || r.OCIRegion != d.OCIRegion || r.Namespace != d.Namespace || r.Bucket != d.Bucket || r.BucketResourceID != d.BucketResourceID || r.CompartmentID != d.CompartmentID || r.OwnershipGeneration != d.OwnershipGeneration {
			return nil, errors.New("sourcepublication: transport destination differs")
		}
		if t, ok := r.Transport.Client.Transport.(*http.Transport); ok && t.TLSClientConfig != nil && (t.TLSClientConfig.InsecureSkipVerify || (t.TLSClientConfig.MinVersion != 0 && t.TLSClientConfig.MinVersion < tls.VersionTLS12)) {
			return nil, errors.New("sourcepublication: verified TLS required")
		}
		transport := *r.Transport
		client := *transport.Client
		base := client.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		client.Transport = guardedTransport{base, check}
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		transport.Client = &client
		r.Transport = &transport
		regions[d.Region] = r
		destinations[d.Region] = d
		keys = append(keys, OwnershipKey(d.BucketResourceID), MutationKey(provider.ProviderMutationScope("object", d.Namespace, d.Bucket, preliminarytransfer.PublicationKey(scope))))
	}
	if len(c.Regions) != len(regions) {
		return nil, errors.New("sourcepublication: extra transport destination")
	}
	for _, o := range scope.Objects {
		d := destinations[o.Region]
		keys = append(keys, MutationKey(provider.ProviderMutationScope("object", d.Namespace, d.Bucket, o.ObjectKey)))
	}
	cas, err := NewJournalCAS(c.Journal, keys, check)
	if err != nil {
		return nil, err
	}
	ownership, err := provider.NewDurableOwnershipJournal(cas, 3)
	if err != nil {
		return nil, err
	}
	journal, err := provider.NewCASProviderMutationJournal(cas)
	if err != nil {
		return nil, err
	}
	// Observe every destination before granting any bucket a durable ownership record.
	for _, d := range scope.Destinations {
		if err := check(ctx); err != nil {
			return nil, err
		}
		observed, found, err := provider.ObserveOCIBucket(ctx, regions[d.Region].Transport, d.Namespace, d.Bucket)
		if err != nil {
			return nil, err
		}
		if !found || observed.ID != d.BucketResourceID || observed.CompartmentID != d.CompartmentID || observed.Namespace != d.Namespace || observed.Name != d.Bucket || !reflect.DeepEqual(observed.FreeformTags, d.OwnershipTags) {
			return nil, errors.New("sourcepublication: observed bucket ownership differs")
		}
	}
	for _, d := range scope.Destinations {
		if err := ownership.Record(ctx, provider.ProviderOwnershipRecord{ResourceId: provider.ProviderResourceId{Value: d.BucketResourceID}, CellId: provider.ProviderCellId{Value: d.Region}, CompartmentId: provider.ProviderCompartmentId{Value: d.CompartmentID}, Generation: provider.ProviderGeneration{Value: d.OwnershipGeneration}}); err != nil {
			return nil, err
		}
	}
	newStore := func(prefix string, maximum int64) (*restoresnapshot.Store, error) {
		return restoresnapshot.New(restoresnapshot.Config{Regions: regions, SourceRegion: "gru", Prefix: prefix, MaxBytes: maximum, Journal: journal, Ownership: ownership, Authorize: func(ctx context.Context, region string, epoch uint64) error {
			if _, ok := destinations[region]; !ok || epoch != c.Upload.Authorization.ControlEpoch {
				return errors.New("sourcepublication: upload authority differs")
			}
			return check(ctx)
		}})
	}
	stores := map[string]*restoresnapshot.Store{}
	published := make([]preliminarytransfer.PublishedObject, 0, len(scope.Objects))
	for i, o := range scope.Objects {
		if err := check(ctx); err != nil {
			return nil, err
		}
		body, found, err := local.GetSnapshot(ctx, "gru", o.Account, o.LocalKey)
		if err != nil {
			return nil, err
		}
		if !found || int64(len(body)) != o.Size || delivery.SHA256Digest(body) != o.SHA256 {
			return nil, errors.New("sourcepublication: local artifact differs")
		}
		prefix := path.Dir(o.ObjectKey) + "/"
		remote := stores[prefix]
		if remote == nil {
			remote, err = newStore(prefix, scope.MaxSnapshotBytes)
			if err != nil {
				return nil, err
			}
			stores[prefix] = remote
		}
		bucket := destinations[o.Region].Bucket
		if err := remote.PutAtEpoch(ctx, o.Region, bucket, o.ObjectKey, body, c.Upload.Authorization.ControlEpoch); err != nil {
			return nil, fmt.Errorf("sourcepublication: upload %s/%s: %w", o.Region, o.Stream, err)
		}
		got, found, err := remote.GetSnapshot(ctx, o.Region, bucket, o.ObjectKey)
		if err != nil {
			return nil, err
		}
		if !found || !bytes.Equal(body, got) {
			return nil, errors.New("sourcepublication: remote artifact differs")
		}
		head, found, err := remote.Head(ctx, o.Region, bucket, o.ObjectKey)
		if err != nil {
			return nil, err
		}
		if !found || head.Digest != o.SHA256 || head.Size != o.Size || head.ETag == "" {
			return nil, errors.New("sourcepublication: remote identity differs")
		}
		if len(receiptRaw) > 0 && old.Objects[i].ETag != head.ETag {
			return nil, errors.New("sourcepublication: historical publication identity changed")
		}
		published = append(published, preliminarytransfer.PublishedObject{ObjectMapping: o, ETag: head.ETag})
	}
	if len(receiptRaw) == 0 {
		if err := check(ctx); err != nil {
			return nil, err
		}
		var request preliminarytransfer.Request
		if err := json.Unmarshal(c.Upload.Signed, &request); err != nil {
			return nil, err
		}
		receiptRaw, err = preliminarytransfer.SignPublicationReceipt(c.Signer, preliminarytransfer.PublicationReceipt{Version: 1, ScopeSHA256: c.Upload.Scope.Digest, UploadRequestSHA256: c.Upload.Digest, UploadAuthorization: request.Authorization, ControlEpoch: c.Upload.Authorization.ControlEpoch, CreatedAt: time.Now().UTC(), Objects: published})
		if err != nil {
			return nil, err
		}
		if _, err = preliminarytransfer.CheckPublication(c.Upload, receiptRaw); err != nil {
			return nil, err
		}
		if err = state.SaveReceipt(ctx, receiptRaw); err != nil {
			return nil, err
		}
	}
	remote, err := newStore(scope.Prefix+"/"+scope.RequestSHA256+"/", preliminarytransfer.MaximumBytes)
	if err != nil {
		return nil, err
	}
	key := preliminarytransfer.PublicationKey(scope)
	for _, d := range scope.Destinations {
		if err := check(ctx); err != nil {
			return nil, err
		}
		if err := remote.PutPublicationReceipt(ctx, d.Region, d.Bucket, key, receiptRaw, c.Upload.Authorization.ControlEpoch); err != nil {
			return nil, err
		}
		got, found, err := remote.GetPublicationReceipt(ctx, d.Region, d.Bucket, key)
		if err != nil {
			return nil, err
		}
		if !found || !bytes.Equal(got, receiptRaw) {
			return nil, errors.New("sourcepublication: remote publication receipt differs")
		}
	}
	if err := check(ctx); err != nil {
		return nil, err
	}
	return receiptRaw, nil
}
