package swarmruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		if verified.Genesis().IsVerified() {
			witness, err := readGenesisReleaseWitness(ctx, client, intent, verified)
			if err != nil {
				return nil, err
			}
			if witness != nil {
				return nil, errors.New("established genesis release floor is missing")
			}
		}
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
	if err := verifyReleaseFloorData(current, verified, roots); err != nil {
		return nil, err
	}
	if verified.Genesis().IsVerified() {
		witness, err := readGenesisReleaseWitness(ctx, client, intent, verified)
		if err != nil {
			return nil, err
		}
		if witness != nil {
			if err := verifyGenesisReleaseWitness(witness, current, intent, verified); err != nil {
				return nil, err
			}
		}
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

type genesisFloorEvidence struct {
	Schema                string                  `json:"schema"`
	WorkloadGenesisSHA256 string                  `json:"workload_genesis_sha256"`
	Origin                release.WorkloadGenesis `json:"origin"`
}

func genesisReleaseFloorData(verified release.VerifiedContainer) ([]byte, error) {
	if !verified.Genesis().IsVerified() || verified.Claim().WorkloadGenesisSHA256 != verified.Genesis().Fingerprint() {
		return nil, errors.New("release floor requires verified original genesis")
	}
	return protocol.EncodeJSON(genesisFloorEvidence{"terrascale.release.genesis-floor.v1", verified.Genesis().Fingerprint(), verified.Genesis().Origin()})
}

func verifyReleaseFloorData(floor *api.Config, verified release.VerifiedContainer, roots trust.Keyring) error {
	if floor == nil || floor.ID == "" || floor.Meta.Version.Index == 0 {
		return errors.New("durable release floor is unavailable")
	}
	claim := verified.Claim()
	if verified.Genesis().IsVerified() {
		expected, err := genesisReleaseFloorData(verified)
		if err != nil {
			return err
		}
		if !bytes.Equal(floor.Spec.Data, expected) || floor.Spec.Annotations.Labels[labelReleaseGenesis] != claim.WorkloadGenesisSHA256 || floor.Spec.Annotations.Labels[labelReleaseMigration] != "" {
			return errors.New("release floor differs from original genesis")
		}
		return nil
	}
	if floor.Spec.Annotations.Labels[labelReleaseGenesis] != "" {
		return errors.New("migration cannot replace genesis release floor")
	}
	envelope, err := trust.DecodeEnvelope(floor.Spec.Data)
	if err != nil {
		return err
	}
	if _, err := release.VerifySequenceMigrationHistorical(envelope, roots, claim.Role, claim.Environment); err != nil {
		return err
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		return err
	}
	if fingerprint != claim.SequenceMigrationSHA256 {
		return errors.New("release ordering namespace differs from durable migration")
	}
	return nil
}

type genesisReleaseWitness struct {
	Schema                string                  `json:"schema"`
	WorkloadGenesisSHA256 string                  `json:"workload_genesis_sha256"`
	Origin                release.WorkloadGenesis `json:"origin"`
	FloorID               string                  `json:"floor_id"`
	FloorName             string                  `json:"floor_name"`
	ServiceID             string                  `json:"service_id"`
	Architecture          string                  `json:"architecture,omitempty"`
}

func genesisWitnessName(intent ServiceIntent, verified release.VerifiedContainer) (string, error) {
	floor, err := releaseFloorName(intent, verified)
	if err != nil || !verified.Genesis().IsVerified() {
		return "", errors.Join(err, errors.New("genesis witness requires authenticated origin"))
	}
	origin := verified.Genesis().Origin()
	identity := sha256.Sum256([]byte(verified.Genesis().Fingerprint() + "/" + origin.Cell + "/" + origin.Environment + "/" + origin.Role + "/" + floor))
	return fmt.Sprintf("ts-release-origin-%x", identity[:16]), nil
}

func genesisWitnessData(floor *api.Config, intent ServiceIntent, verified release.VerifiedContainer) ([]byte, error) {
	name, err := releaseFloorName(intent, verified)
	if err != nil || floor == nil || floor.ID == "" || floor.Spec.Annotations.Name != name {
		return nil, errors.Join(err, errors.New("genesis witness requires the exact retained floor"))
	}
	architecture := ""
	if verified.Claim().Role == "function-worker" {
		architecture = verified.Claim().Architecture
	}
	return protocol.EncodeJSON(genesisReleaseWitness{"terrascale.release.origin-witness.v1", verified.Genesis().Fingerprint(), verified.Genesis().Origin(), floor.ID, name, intent.ID, architecture})
}

func readGenesisReleaseWitness(ctx context.Context, client api.ControlReader, intent ServiceIntent, verified release.VerifiedContainer) (*api.Config, error) {
	name, err := genesisWitnessName(intent, verified)
	if err != nil {
		return nil, err
	}
	listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{name}}})
	if err != nil {
		return nil, err
	}
	if listed == nil || len(listed.Configs) > 1 || len(listed.Configs) == 1 && listed.Configs[0] == nil {
		return nil, errors.New("genesis origin witness is unavailable or ambiguous")
	}
	if len(listed.Configs) == 0 {
		return nil, nil
	}
	return listed.Configs[0], nil
}

func verifyGenesisReleaseWitness(witness, floor *api.Config, intent ServiceIntent, verified release.VerifiedContainer) error {
	name, err := genesisWitnessName(intent, verified)
	if err != nil {
		return err
	}
	expected, err := genesisWitnessData(floor, intent, verified)
	if err != nil {
		return err
	}
	if witness == nil || witness.ID == "" || witness.Meta.Version.Index == 0 || witness.Spec.Annotations.Name != name || len(witness.Spec.Annotations.Labels) != 0 || !bytes.Equal(witness.Spec.Data, expected) {
		return errors.New("original genesis witness pins a missing or replaced release floor")
	}
	return nil
}

// The immutable witness is written only after the ordinary CAS floor exists.
// A crash in between admits no effect and can finish the compatible witness.
func ensureGenesisReleaseWitness(ctx context.Context, client api.ControlClient, intent ServiceIntent, verified release.VerifiedContainer, floor *api.Config) error {
	if !verified.Genesis().IsVerified() {
		return nil
	}
	witness, err := readGenesisReleaseWitness(ctx, client, intent, verified)
	if err != nil {
		return err
	}
	if witness == nil {
		name, err := genesisWitnessName(intent, verified)
		if err != nil {
			return err
		}
		data, err := genesisWitnessData(floor, intent, verified)
		if err != nil {
			return err
		}
		if !verified.Valid(time.Now().UTC()) {
			return errors.New("genesis authority expired before witness creation")
		}
		_, err = client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: name}, Data: data}})
		if err != nil && status.Code(err) != codes.AlreadyExists {
			return err
		}
		witness, err = readGenesisReleaseWitness(ctx, client, intent, verified)
		if err != nil {
			return err
		}
	}
	return verifyGenesisReleaseWitness(witness, floor, intent, verified)
}

// Every service, registry and material effect must authenticate both records.
func authenticateReleaseFloor(ctx context.Context, client api.ControlReader, intent ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring, floor *api.Config) error {
	if err := verifyReleaseFloorData(floor, verified, roots); err != nil {
		return err
	}
	if verified.Genesis().IsVerified() {
		witness, err := readGenesisReleaseWitness(ctx, client, intent, verified)
		if err != nil {
			return err
		}
		if err := verifyGenesisReleaseWitness(witness, floor, intent, verified); err != nil {
			return err
		}
	}
	if !verified.Valid(time.Now().UTC()) {
		return errors.New("container authorization expired while authenticating release floor")
	}
	return ctx.Err()
}

func releaseFloorDigest(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && len(value) == 64 && strings.ToLower(value) == value
}
