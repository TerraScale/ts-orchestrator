package controlrestore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/transitionreceipts"
)

// OCIObjects reads only admitted final envelopes from one destination bucket.
type OCIObjects struct {
	plan     controltransition.VerifiedPlan
	location controltransition.ObjectLocation
	reader   *provider.OCIObjectStorageReader
	objects  map[string]controltransition.CaptureObject
}

func NewOCIObjects(v controltransition.VerifiedPlan, cut, source, capture []byte, region string, transport *provider.OCIHTTPTransport) (*OCIObjects, error) {
	receipt, err := controltransition.VerifyCaptureReceipt(v, cut, source, capture)
	if err != nil {
		return nil, err
	}
	p, err := v.Plan()
	if err != nil {
		return nil, err
	}
	var location controltransition.ObjectLocation
	for _, d := range p.Destinations {
		if d.Region == region {
			location = d.Objects
		}
	}
	if location.Bucket == "" || transport == nil || transport.Config.Region != location.OCIRegion {
		return nil, errors.New("controlrestore: object region differs")
	}
	reader, err := provider.NewOCIObjectStorageReader(transport, provider.ObjectReadScope{Namespace: location.Namespace, Bucket: location.Bucket, Prefix: location.Prefix + "/final/" + v.Digest() + "/", MaxObjectBytes: p.Limits.MaxSnapshotBytes})
	if err != nil {
		return nil, err
	}
	objects := map[string]controltransition.CaptureObject{}
	for _, object := range receipt.Objects {
		objects[object.Key] = object
	}
	return &OCIObjects{plan: v, location: location, reader: reader, objects: objects}, nil
}
func (r *OCIObjects) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.plan.Check(time.Now().UTC()); err != nil {
		return err
	}
	actual, found, err := r.reader.ObserveBucket(ctx)
	if err != nil {
		return err
	}
	digest, err := transitionreceipts.BucketObservationDigest(actual)
	expected := r.location
	if err != nil || !found || actual.ID != expected.BucketResourceID || actual.CompartmentID != expected.CompartmentID || actual.Namespace != expected.Namespace || actual.Name != expected.Bucket || digest != expected.OwnershipObservationSHA256 {
		return errors.New("controlrestore: observed bucket ownership differs")
	}
	return nil
}
func (r *OCIObjects) OpenSnapshot(ctx context.Context, object controltransition.CaptureObject) (io.ReadCloser, error) {
	if r == nil || r.objects[object.Key] != object {
		return nil, errors.New("controlrestore: undeclared final object")
	}
	if err := r.check(ctx); err != nil {
		return nil, err
	}
	reference := provider.ObjectRef{Namespace: r.location.Namespace, Bucket: r.location.Bucket, Name: r.location.Prefix + "/" + object.Key}
	head, found, err := r.reader.HeadObject(ctx, reference)
	if err != nil {
		return nil, err
	}
	if !found || head.Size != object.Size || head.SHA256 != object.SHA256 || head.ETag == "" {
		return nil, errors.New("controlrestore: final object metadata differs")
	}
	body, metadata, err := r.reader.GetObject(ctx, reference)
	if err != nil {
		return nil, err
	}
	if metadata.Size != head.Size || metadata.SHA256 != head.SHA256 || metadata.ETag != head.ETag {
		body.Close()
		return nil, errors.New("controlrestore: object changed between observations")
	}
	return body, nil
}

// PublishCapture copies each final envelope to every admitted destination with
// create-only writes and independent exact body readback. Success is transport
// evidence only; it never substitutes for destination restore/quorum receipts.
func PublishCapture(ctx context.Context, v controltransition.VerifiedPlan, cut, source, capture []byte, objects ObjectReader, transports map[string]*provider.OCIHTTPTransport) error {
	if ctx == nil || objects == nil {
		return errors.New("controlrestore: publication dependencies absent")
	}
	receipt, err := controltransition.VerifyCaptureReceipt(v, cut, source, capture)
	if err != nil {
		return err
	}
	p, err := v.Plan()
	if err != nil {
		return err
	}
	for _, destination := range p.Destinations {
		transport := transports[destination.Region]
		remote, err := NewOCIObjects(v, cut, source, capture, destination.Region, transport)
		if err != nil {
			return err
		}
		if err := remote.check(ctx); err != nil {
			return err
		}
		client := *transport.Client
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		safe, err := provider.NewOCIHTTPTransport(transport.Config, &client, transport.Signer)
		if err != nil {
			return err
		}
		for _, object := range receipt.Objects {
			if err := remote.check(ctx); err != nil {
				return err
			}
			body, err := objects.OpenSnapshot(ctx, object)
			if err != nil {
				return err
			}
			raw, readErr := io.ReadAll(io.LimitReader(body, object.Size+1))
			closeErr := body.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return err
			}
			if int64(len(raw)) != object.Size || controltransition.Digest(raw) != object.SHA256 {
				return errors.New("controlrestore: local captured envelope differs")
			}
			ref := provider.ObjectRef{Namespace: destination.Objects.Namespace, Bucket: destination.Objects.Bucket, Name: destination.Objects.Prefix + "/" + object.Key}
			response, uploadErr := safe.PutObjectBody(ctx, ref, bytes.NewReader(raw), map[string]string{"If-None-Match": "*", "opc-meta-terrascale-sha256": object.SHA256})
			if response != nil && response.Body != nil {
				response.Body.Close()
			}
			got, err := remote.OpenSnapshot(ctx, object)
			if err != nil {
				return errors.Join(uploadErr, err)
			}
			downloaded, readErr := io.ReadAll(io.LimitReader(got, object.Size+1))
			closeErr = got.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return errors.Join(uploadErr, err)
			}
			if !bytes.Equal(raw, downloaded) {
				return errors.New("controlrestore: remote final archive readback differs")
			}
		}
		if err := remote.check(ctx); err != nil {
			return err
		}
	}
	return nil
}
