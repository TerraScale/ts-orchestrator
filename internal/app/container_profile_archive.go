package app

import (
	"bytes"
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/nats-io/nats.go/jetstream"
)

// CaptureContainerProfile retains original public policy before the operation CAS.
func (h *nativeHistory) CaptureContainerProfile(ctx context.Context, intent delivery.Intent) (string, error) {
	if h == nil || h.js == nil || h.kv == nil || h.fencer == nil || h.services == nil || h.services.roots == nil || intent.Container == nil {
		return "", delivery.ErrPending
	}
	if err := h.fencer.Guard(ctx, intent.AuthorityEpoch); err != nil {
		return "", err
	}
	source, err := nativeLeaderGet(ctx, h.js, cellSpecBucket, cellSpecKey)
	if err != nil {
		return "", err
	}
	if source.Subject != "$KV."+cellSpecBucket+"."+cellSpecKey || source.Sequence == 0 || source.Header.Get("KV-Operation") != "" || source.Header.Get(jetstream.MarkerReasonHeader) != "" {
		return "", delivery.ErrPending
	}
	rootHead := h.services.roots.reply("").Head
	proof, err := containermaterial.VerifyProfile(source.Data, h.services.roots.current(), h.services.identity, intent)
	if err != nil {
		return "", err
	}
	reference, records, err := encodeNativeProfile(proof.Profile(), nativeProfileProvenance{Spec: bytes.Clone(source.Data)}, h.js.Conn().MaxPayload())
	if err != nil {
		return "", err
	}
	if err := h.writeProfileRecords(ctx, intent.AuthorityEpoch, records); err != nil {
		return "", err
	}
	current, err := nativeLeaderGet(ctx, h.js, cellSpecBucket, cellSpecKey)
	if err != nil {
		return "", err
	}
	if current.Subject != source.Subject || current.Sequence != source.Sequence || !bytes.Equal(current.Data, source.Data) || current.Header.Get("KV-Operation") != "" || current.Header.Get(jetstream.MarkerReasonHeader) != "" || h.services.roots.reply("").Head != rootHead {
		return "", delivery.ErrPending
	}
	if err := h.fencer.Guard(ctx, intent.AuthorityEpoch); err != nil {
		return "", err
	}
	return reference, nil
}

// ReadContainerProfile supplies immutable descriptive bytes, never current authority.
func (h *nativeHistory) ReadContainerProfile(ctx context.Context, reference string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || h == nil || h.js == nil {
		return nil, delivery.ErrPending
	}
	_, provenance, err := h.readProfile(ctx, reference)
	if err != nil {
		return nil, err
	}
	if len(provenance.Spec) == 0 || len(provenance.Manifest)+len(provenance.Config)+len(provenance.MaterialChain)+len(provenance.Identity) != 0 {
		return nil, delivery.ErrPending
	}
	return provenance.Spec, nil
}

func (h *nativeHistory) originalContainerProfile(ctx context.Context, intent delivery.Intent) ([]byte, error) {
	if h == nil || h.deliveries == nil {
		return nil, delivery.ErrPending
	}
	original, reference, err := h.deliveries.ContainerProvenance(ctx, intent.OperationID)
	if err != nil {
		return nil, err
	}
	fingerprint, err := original.Fingerprint()
	expected, expectedErr := intent.Fingerprint()
	if err != nil || expectedErr != nil || fingerprint != expected {
		return nil, delivery.ErrPending
	}
	return h.ReadContainerProfile(ctx, reference)
}
