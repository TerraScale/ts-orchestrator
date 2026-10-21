package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type containerIntentSelection struct {
	intent    delivery.Intent
	original  delivery.Intent
	reference string
	guard     func(context.Context) error
}

func currentContainerChannel(ctx context.Context, intent delivery.Intent, architecture string, read func(context.Context, string, string) (release.ContainerBundle, time.Time, error)) (func(context.Context) error, error) {
	if intent.Container == nil || read == nil {
		return nil, containermaterial.ErrPending
	}
	wanted, err := release.ContainerBundleSHA256(*intent.Container)
	if err != nil {
		return nil, err
	}
	guard := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, currentExpiry, err := read(ctx, intent.Role, architecture)
		if err != nil || !time.Now().UTC().Before(currentExpiry) {
			return errors.Join(containermaterial.ErrPending, err)
		}
		actual, err := release.ContainerBundleSHA256(current)
		if err != nil || actual != wanted {
			return errors.Join(containermaterial.ErrPending, err)
		}
		return ctx.Err()
	}
	return guard, guard(ctx)
}

// The existing channel record supplies only a locator. The exact protected
// operation must independently authorize its current actor on every read.
func selectContainerIntent(ctx context.Context, js jetstream.JetStream, service *delivery.Service, originalOperation string) (containerIntentSelection, error) {
	if js == nil || js.Conn() == nil || service == nil {
		return containerIntentSelection{}, containermaterial.ErrPending
	}
	original, reference, err := service.ContainerProvenance(ctx, originalOperation)
	if err != nil {
		return containerIntentSelection{}, err
	}
	key := releasechannel.ServiceStatusKey(strings.ToUpper(original.Cell), original.Role)
	entry, readErr := nativeLeaderGet(ctx, js, releasechannel.Bucket, key)
	if readErr != nil && !errors.Is(readErr, nats.ErrMsgNotFound) {
		return containerIntentSelection{}, readErr
	}
	operation := originalOperation
	var selectedFingerprint string
	if readErr == nil {
		if entry.Subject != "$KV."+releasechannel.Bucket+"."+key || entry.Sequence == 0 || len(entry.Data) == 0 || entry.Header.Get("KV-Operation") != "" || entry.Header.Get(jetstream.MarkerReasonHeader) != "" {
			return containerIntentSelection{}, containermaterial.ErrPending
		}
		var state serviceReleaseState
		if err := json.Unmarshal(entry.Data, &state, json.RejectUnknownMembers(true)); err != nil {
			return containerIntentSelection{}, err
		}
		if state.Intent == nil || state.Intent.Container == nil || state.Intent.Cell != original.Cell || state.Intent.Role != original.Role || state.Intent.Environment != original.Environment {
			return containerIntentSelection{}, containermaterial.ErrPending
		}
		operation = state.Intent.OperationID
		selectedFingerprint, err = state.Intent.Fingerprint()
		if err != nil {
			return containerIntentSelection{}, err
		}
	}
	intent, err := service.ContainerIntent(ctx, operation)
	if err != nil {
		return containerIntentSelection{}, err
	}
	ctx, stopProof, err := currentContainerIntentContext(ctx, intent)
	defer stopProof()
	if err != nil {
		return containerIntentSelection{}, err
	}
	fingerprint, err := intent.Fingerprint()
	if err != nil || selectedFingerprint != "" && fingerprint != selectedFingerprint {
		return containerIntentSelection{}, containermaterial.ErrPending
	}
	originalFingerprint, err := original.Fingerprint()
	if err != nil {
		return containerIntentSelection{}, err
	}
	selectorGuard := func(ctx context.Context) error {
		current, err := nativeLeaderGet(ctx, js, releasechannel.Bucket, key)
		if readErr != nil {
			if !errors.Is(err, nats.ErrMsgNotFound) {
				return containermaterial.ErrPending
			}
		} else if err != nil || current.Subject != entry.Subject || current.Sequence != entry.Sequence || !bytes.Equal(current.Data, entry.Data) || current.Header.Get("KV-Operation") != "" || current.Header.Get(jetstream.MarkerReasonHeader) != "" {
			return containermaterial.ErrPending
		}
		return ctx.Err()
	}
	guard := func(ctx context.Context) error {
		if err := selectorGuard(ctx); err != nil {
			return err
		}
		currentIntent, err := service.ContainerIntent(ctx, intent.OperationID)
		if err != nil {
			return err
		}
		currentFingerprint, err := currentIntent.Fingerprint()
		if err != nil || currentFingerprint != fingerprint {
			return containermaterial.ErrPending
		}
		originalNow, referenceNow, err := service.ContainerProvenance(ctx, originalOperation)
		if err != nil {
			return err
		}
		originalNowFingerprint, err := originalNow.Fingerprint()
		if err != nil || originalNowFingerprint != originalFingerprint || referenceNow != reference {
			return containermaterial.ErrPending
		}
		return selectorGuard(ctx)
	}
	selection := containerIntentSelection{intent: intent, original: original, reference: reference, guard: guard}
	return selection, guard(ctx)
}

func currentContainerIntentContext(ctx context.Context, intent delivery.Intent) (context.Context, context.CancelFunc, error) {
	if intent.Container == nil {
		return ctx, func() {}, containermaterial.ErrPending
	}
	envelope, err := trust.DecodeEnvelope(intent.Container.Claim)
	if err != nil {
		return ctx, func() {}, err
	}
	var claim release.ContainerClaim
	if err := protocol.DecodeStrict(envelope.Payload, &claim, trust.MaxPayloadBytes); err != nil {
		return ctx, func() {}, err
	}
	deadline := envelope.ExpiresAt
	for _, wire := range [][]byte{intent.Container.Delegation, claim.Production.Qualification, claim.Production.Delegation} {
		if len(wire) == 0 {
			continue
		}
		finite, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return ctx, func() {}, err
		}
		deadline = earlier(deadline, finite.ExpiresAt)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline.Add(-time.Nanosecond))
	return ctx, cancel, ctx.Err()
}
