package transitionreceipts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// PublishPlanPin publishes an already durable host acknowledgement verbatim.
// The caller must recover signed from the private host journal and supply the
// host's instance-principal transport. No signer, NATS connection, or mutable
// upload journal is needed: the exact signed plan and receipt fix the entire
// operation, and every attempt uses create-only semantics. Success proves only
// remote publication, never storage preparation or permission to retire.
func PublishPlanPin(ctx context.Context, plan controltransition.VerifiedPlan, node string, signed []byte, transport *provider.OCIHTTPTransport) error {
	bad := errors.New("transitionreceipts: conflicting pin publication")
	if ctx == nil {
		return bad
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return plan.Check(time.Now())
	}
	if err := check(); err != nil {
		return err
	}
	raw := bytes.Clone(signed)
	receipt, err := controltransition.VerifyPinReceipt(plan, raw)
	if err != nil {
		return err
	}
	if receipt.NodeID != node || receipt.PublishedAt.After(time.Now()) {
		return bad
	}
	region, key, err := PinObjectKey(plan, node)
	if err != nil {
		return err
	}
	p, err := plan.Plan()
	if err != nil {
		return err
	}
	var location controltransition.ObjectLocation
	for _, d := range p.Destinations {
		if d.Region == region {
			location = d.Objects
		}
	}
	if transport == nil || transport.Client == nil || transport.Config.Region != location.OCIRegion {
		return bad
	}
	// Reader construction validates the signed service endpoint and TLS settings
	// before any write. The write client also refuses redirects.
	reader, err := provider.NewOCIObjectStorageReader(transport, provider.ObjectReadScope{Namespace: location.Namespace, Bucket: location.Bucket, Prefix: location.Prefix + "/" + plan.Digest() + "/plan-pinned/", MaxObjectBytes: controltransition.PinReceiptMaximumBytes})
	if err != nil {
		return err
	}
	client := *transport.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	safe, err := provider.NewOCIHTTPTransport(transport.Config, &client, transport.Signer)
	if err != nil {
		return err
	}
	observe := func() error {
		if err := check(); err != nil {
			return err
		}
		o, found, err := reader.ObserveBucket(ctx)
		if err != nil {
			return err
		}
		digest, err := BucketObservationDigest(o)
		if err != nil || !found || o.ID != location.BucketResourceID || o.CompartmentID != location.CompartmentID || o.Namespace != location.Namespace || o.Name != location.Bucket || digest != location.OwnershipObservationSHA256 {
			return bad
		}
		return check()
	}
	if err := observe(); err != nil {
		return err
	}
	object := provider.ObjectRef{Namespace: location.Namespace, Bucket: location.Bucket, Name: key}
	digest := controltransition.Digest(raw)
	response, uploadErr := safe.PutObjectBody(ctx, object, bytes.NewReader(raw), map[string]string{"If-None-Match": "*", "opc-meta-terrascale-sha256": digest})
	if response != nil {
		// A failed response is not proof of absence. Reconcile through an exact GET
		// even for a precondition failure or an uncertain server-side outcome.
		if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
			uploadErr = errors.Join(uploadErr, fmt.Errorf("transitionreceipts: upload status %d", response.StatusCode))
		}
		if response.Body != nil {
			response.Body.Close()
		}
	}
	if err := check(); err != nil {
		return errors.Join(uploadErr, err)
	}
	body, metadata, err := reader.GetObject(ctx, object)
	if err != nil {
		return errors.Join(uploadErr, err)
	}
	got, readErr := io.ReadAll(io.LimitReader(body, controltransition.PinReceiptMaximumBytes+1))
	closeErr := body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return errors.Join(uploadErr, err)
	}
	if !bytes.Equal(got, raw) || metadata.Size != int64(len(raw)) || metadata.SHA256 != digest || metadata.ETag == "" {
		return errors.Join(uploadErr, bad)
	}
	if err := observe(); err != nil {
		return err
	}
	return check()
}
