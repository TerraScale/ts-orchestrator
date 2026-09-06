package hostagent

import (
	"context"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/transitionreceipts"
)

// Fetching supplies untrusted bytes. The original host admission validates
// their owner signature, lifetime, and host bindings before local retention.
func fetchStorageTransitionPlan(ctx context.Context, d controltransition.Delivery) ([]byte, bool, error) {
	if ctx == nil || d.PlanObject == nil || d.Validate() != nil {
		return nil, false, errors.New("hostagent: remote plan delivery is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	o := d.PlanObject.Objects
	identity, err := ociinstance.NewFromConfig(ctx, ociinstance.Config{Region: o.OCIRegion, Qualification: d.OCIQualification}, func(path string) ([]byte, error) { return bootstrapcredentials.ReadFile(path, true, 64<<10) })
	if err != nil {
		return nil, false, err
	}
	defer identity.Close()
	transport, err := identity.NewTransport(provider.OCIServiceObjectStorage, controltransition.MaximumBytes)
	if err != nil {
		return nil, false, err
	}
	reader, err := provider.NewOCIObjectStorageReader(transport, provider.ObjectReadScope{Namespace: o.Namespace, Bucket: o.Bucket, Prefix: o.Prefix + "/", MaxObjectBytes: controltransition.MaximumBytes})
	if err != nil {
		return nil, false, err
	}
	observe := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		got, found, err := reader.ObserveBucket(ctx)
		if err != nil {
			return err
		}
		digest, err := transitionreceipts.BucketObservationDigest(got)
		if err != nil || !found || got.ID != o.BucketResourceID || got.CompartmentID != o.CompartmentID || got.Namespace != o.Namespace || got.Name != o.Bucket || digest != o.OwnershipObservationSHA256 {
			return errors.New("hostagent: remote plan bucket ownership differs")
		}
		return ctx.Err()
	}
	if err := observe(); err != nil {
		return nil, false, err
	}
	ref := provider.ObjectRef{Namespace: o.Namespace, Bucket: o.Bucket, Name: o.Prefix + "/plan.json"}
	head, found, err := reader.HeadObject(ctx, ref)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, observe()
	}
	body, metadata, err := reader.GetObject(ctx, ref)
	if err != nil {
		return nil, false, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(body, controltransition.MaximumBytes+1))
	closeErr := body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, false, err
	}
	if len(raw) > controltransition.MaximumBytes || int64(len(raw)) != metadata.Size || controltransition.Digest(raw) != metadata.SHA256 || metadata.ETag == "" || metadata != head {
		return nil, false, errors.New("hostagent: remote plan bytes or metadata differ")
	}
	if err := observe(); err != nil {
		return nil, false, err
	}
	return raw, true, nil
}
