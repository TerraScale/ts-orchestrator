// Package transitionreceipts publishes and reads signed host acknowledgements
// independently of the control broker. It never authorizes retirement.
package transitionreceipts

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

// BucketObservationDigest defines the plan's ownership observation commitment:
// SHA-256 of the projected OCI bucket observation in deterministic Go JSON v2.
func BucketObservationDigest(observation provider.OCIBucketObservation) (string, error) {
	raw, err := json.Marshal(observation, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return controltransition.Digest(raw), nil
}

// PinObjectKey fixes the receipt location under the exact signed plan digest.
// node must be a host in that verified plan. A source/GRU co-host has one source
// acknowledgement, while a separate GRU destination has its own object.
func PinObjectKey(plan controltransition.VerifiedPlan, node string) (string, string, error) {
	p, err := plan.Plan()
	if err != nil {
		return "", "", err
	}
	region := ""
	if node == p.Source.NodeID {
		region = "gru"
	} else {
		for _, d := range p.Destinations {
			if d.NodeID == node {
				region = d.Region
			}
		}
	}
	for _, d := range p.Destinations {
		if region != "" && d.Region == region {
			return region, d.Objects.Prefix + "/" + plan.Digest() + "/plan-pinned/" + node + ".json", nil
		}
	}
	return "", "", errors.New("transitionreceipts: host is outside signed plan")
}

// ReadPlanPins requires all three regional transports and all distinct hosts.
// Each object is read from its host's region with signed OCI HTTP requests and
// an 8 KiB object cap. Bucket observations are checked before and after reads.
func ReadPlanPins(ctx context.Context, plan controltransition.VerifiedPlan, transports map[string]*provider.OCIHTTPTransport) (controltransition.VerifiedPlanPins, error) {
	var zero controltransition.VerifiedPlanPins
	bad := errors.New("transitionreceipts: incomplete or conflicting remote acknowledgements")
	if ctx == nil || len(transports) != 3 {
		return zero, bad
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if err := plan.Check(time.Now()); err != nil {
		return zero, err
	}
	p, err := plan.Plan()
	if err != nil {
		return zero, err
	}
	readers := map[string]*provider.OCIObjectStorageReader{}
	locations := map[string]controltransition.ObjectLocation{}
	for _, d := range p.Destinations {
		transport := transports[d.Region]
		if transport == nil || transport.Config.Region != d.Objects.OCIRegion {
			return zero, bad
		}
		reader, err := provider.NewOCIObjectStorageReader(transport, provider.ObjectReadScope{Namespace: d.Objects.Namespace, Bucket: d.Objects.Bucket, Prefix: d.Objects.Prefix + "/" + plan.Digest() + "/plan-pinned/", MaxObjectBytes: controltransition.PinReceiptMaximumBytes})
		if err != nil {
			return zero, err
		}
		readers[d.Region], locations[d.Region] = reader, d.Objects
	}
	observe := func() error {
		for _, d := range p.Destinations {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := plan.Check(time.Now()); err != nil {
				return err
			}
			observation, found, err := readers[d.Region].ObserveBucket(ctx)
			if err != nil {
				return err
			}
			digest, err := BucketObservationDigest(observation)
			o := d.Objects
			if err != nil || !found || observation.ID != o.BucketResourceID || observation.CompartmentID != o.CompartmentID || observation.Namespace != o.Namespace || observation.Name != o.Bucket || digest != o.OwnershipObservationSHA256 {
				return bad
			}
		}
		return nil
	}
	if err := observe(); err != nil {
		return zero, err
	}
	nodes := []string{p.Source.NodeID}
	for _, d := range p.Destinations {
		if d.NodeID != p.Source.NodeID {
			nodes = append(nodes, d.NodeID)
		}
	}
	signed := make([][]byte, 0, len(nodes))
	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if err := plan.Check(time.Now()); err != nil {
			return zero, err
		}
		region, key, err := PinObjectKey(plan, node)
		if err != nil {
			return zero, err
		}
		o := locations[region]
		body, metadata, err := readers[region].GetObject(ctx, provider.ObjectRef{Namespace: o.Namespace, Bucket: o.Bucket, Name: key})
		if err != nil {
			return zero, err
		}
		raw, readErr := io.ReadAll(io.LimitReader(body, controltransition.PinReceiptMaximumBytes+1))
		closeErr := body.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return zero, err
		}
		if len(raw) > controltransition.PinReceiptMaximumBytes || int64(len(raw)) != metadata.Size || controltransition.Digest(raw) != metadata.SHA256 {
			return zero, bad
		}
		receipt, err := controltransition.VerifyPinReceipt(plan, raw)
		if err != nil || receipt.NodeID != node {
			return zero, bad
		}
		signed = append(signed, raw)
	}
	if err := observe(); err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return controltransition.VerifyPlanPins(plan, signed, time.Now())
}
