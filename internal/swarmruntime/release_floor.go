package swarmruntime

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

// ServiceReleaseFloor describes retained admission evidence, not permission to retry.
type ServiceReleaseFloor struct {
	OperationID                   string
	Generation, ReleaseSequence   uint64
	ReleaseIdentity, IntentSHA256 string
}

// HistoricalServiceIntentSHA256 compares an independently authenticated original
// workload profile with retained evidence; it grants no current admission.
func HistoricalServiceIntentSHA256(intent ServiceIntent, historical release.HistoricalContainer) (string, error) {
	claim := historical.Claim()
	region, known := catalog.CellForOCIRegion(intent.Region)
	if !known || claim.Cell != region.Cell || claim.Role != intent.Role || claim.Environment != intent.Environment || claim.Architecture != intent.Architecture ||
		intent.Container == nil || claim.Image != intent.Container.Image || intent.Generation == 0 || !entityid.Valid(intent.OperationID) || claim.ReleaseSequence == 0 || !releaseFloorDigest(historical.ReleaseIdentity()) {
		return "", errors.New("historical intent fingerprint requires the original delivered workload and matching signed target")
	}
	intent.releaseSequence, intent.releaseFingerprint = claim.ReleaseSequence, historical.ReleaseIdentity()
	spec, err := intent.serviceSpec()
	if err != nil {
		return "", err
	}
	return serviceIntentFingerprint(spec)
}

// ReadServiceReleaseFloor only locates the original delivered intent. The caller
// must independently authenticate that intent and its current workload policy.
func ReadServiceReleaseFloor(ctx context.Context, client api.ControlReader, intent ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring) (ServiceReleaseFloor, bool, error) {
	current, err := readReleaseFloorRecord(ctx, client, intent, verified, roots)
	if err != nil || current == nil {
		return ServiceReleaseFloor{}, false, err
	}
	labels := current.Spec.Annotations.Labels
	generation, _ := strconv.ParseUint(labels[LabelIntentGeneration], 10, 64)
	if generation == 0 {
		return ServiceReleaseFloor{}, false, errors.New("release floor has no delivered service intent")
	}
	sequence, _ := strconv.ParseUint(labels[labelReleaseSequence], 10, 64)
	return ServiceReleaseFloor{OperationID: labels[LabelOperationID], Generation: generation, ReleaseSequence: sequence, ReleaseIdentity: labels[labelReleaseFingerprint], IntentSHA256: labels[labelIntentFingerprint]}, true, nil
}

func readReleaseFloorRecord(ctx context.Context, client api.ControlReader, intent ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring) (*api.Config, error) {
	if client == nil || !entityid.Valid(intent.ID) {
		return nil, errors.New("release floor requires an admitted manager and service identity")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	name, err := releaseFloorName(intent, verified)
	if err != nil {
		return nil, err
	}
	listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{name}}})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !verified.Valid(time.Now().UTC()) {
		return nil, errors.New("signed container authorization expired during floor observation")
	}
	if listed == nil {
		return nil, errors.New("durable release floor observation is unavailable")
	}
	if len(listed.Configs) == 0 {
		return nil, nil
	}
	if len(listed.Configs) != 1 || listed.Configs[0] == nil {
		return nil, errors.New("ambiguous durable release floor")
	}
	current := listed.Configs[0]
	labels := current.Spec.Annotations.Labels
	claim := verified.Claim()
	if current.ID == "" || current.Meta.Version.Index == 0 || current.Spec.Annotations.Name != name || labels[LabelIntentID] != intent.ID || labels[LabelRole] != intent.Role || labels[LabelRegion] != intent.Region || labels[LabelEnvironment] != intent.Environment {
		return nil, errors.New("release floor ownership mismatch")
	}
	if claim.Role == "function-worker" && labels[labelReleaseArchitecture] != claim.Architecture {
		return nil, errors.New("worker release floor architecture mismatch")
	}
	envelope, err := trust.DecodeEnvelope(current.Spec.Data)
	if err != nil {
		return nil, err
	}
	if _, err := release.VerifySequenceMigrationHistorical(envelope, roots, intent.Role, intent.Environment); err != nil {
		return nil, err
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		return nil, err
	}
	if fingerprint != claim.SequenceMigrationSHA256 {
		// shortcut: ordering namespace changes are refused, add root-authorized rotation when the producer signer rotates.
		return nil, errors.New("release ordering namespace differs from durable migration")
	}
	sequence, err := strconv.ParseUint(labels[labelReleaseSequence], 10, 64)
	if err != nil || sequence == 0 || strconv.FormatUint(sequence, 10) != labels[labelReleaseSequence] || !releaseFloorDigest(labels[labelReleaseFingerprint]) {
		return nil, errors.New("invalid durable release sequence or identity")
	}
	baseline, err := strconv.ParseUint(labels[labelReleaseBaseline], 10, 64)
	if err != nil || strconv.FormatUint(baseline, 10) != labels[labelReleaseBaseline] {
		return nil, errors.New("invalid durable release baseline")
	}
	if labels[LabelIntentGeneration] != "" || claim.Role != "function-worker" {
		generation, err := strconv.ParseUint(labels[LabelIntentGeneration], 10, 64)
		if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != labels[LabelIntentGeneration] || !releaseFloorDigest(labels[labelIntentFingerprint]) || !entityid.Valid(labels[LabelOperationID]) {
			return nil, errors.New("invalid durable release intent or original operation locator")
		}
	}
	if !verified.Valid(time.Now().UTC()) {
		return nil, errors.New("signed container authorization expired during floor validation")
	}
	return current, ctx.Err()
}

func releaseFloorDigest(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && len(value) == 64 && strings.ToLower(value) == value
}
