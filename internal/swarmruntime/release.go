package swarmruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/moby/swarmkit/v2/api"
)

const labelReleaseBaseline = "terrascale.release-baseline"

// ApplySignedService is the production service admission boundary. The caller
// supplies the target from admitted membership and its retained legacy floor,
// never from untrusted release metadata. OCI child images have their own signed
// contract; native binary/tarball artifact records cannot enter this path.
func ApplySignedService(ctx context.Context, client api.ControlClient, intent ServiceIntent, bundle release.ContainerBundle, roots trust.Keyring, retained release.SequenceFloor, evidence func(context.Context, string) (io.ReadCloser, error)) (*api.Service, error) {
	operation, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	deadline, _ := operation.Deadline()
	if _, err := intent.serviceSpec(); err != nil {
		return nil, err
	}
	target := release.ContainerTarget{Cell: strings.ToUpper(intent.Region), Environment: intent.Environment, Role: intent.Role, Architecture: intent.Architecture}
	verified, err := release.VerifyContainerCurrent(operation, bundle, roots, target, time.Now().UTC(), deadline, evidence)
	if err != nil {
		return nil, err
	}
	claim := verified.Claim()
	if claim.Image != intent.Container.Image {
		return nil, errors.New("service image differs from signed OCI child manifest")
	}
	intent.releaseSequence = claim.ReleaseSequence
	intent.releaseFingerprint = verified.Fingerprint()
	spec, _ := intent.serviceSpec()
	services, err := client.ListServices(operation, &api.ListServicesRequest{Filters: &api.ListServicesRequest_Filters{Names: []string{spec.Annotations.Name}}})
	if err != nil {
		return nil, err
	}
	var baseline uint64
	if len(services.Services) > 1 {
		return nil, errors.New("ambiguous service identity")
	}
	if len(services.Services) == 1 {
		baseline = services.Services[0].Meta.Version.Index
	}
	floor, err := reserveReleaseFloor(operation, client, intent, verified, roots, retained, baseline)
	if err != nil {
		return nil, err
	}
	guard := func(ctx context.Context) error {
		current, err := client.GetConfig(ctx, &api.GetConfigRequest{ConfigID: floor.ID})
		if err != nil {
			return err
		}
		if current.Config.Spec.Annotations.Labels[labelReleaseSequence] != strconv.FormatUint(claim.ReleaseSequence, 10) || current.Config.Spec.Annotations.Labels[labelReleaseFingerprint] != verified.Fingerprint() {
			return errors.New("a newer signed release superseded this operation")
		}
		return nil
	}
	if len(services.Services) == 1 {
		current := services.Services[0]
		storedBaseline, err := strconv.ParseUint(floor.Spec.Annotations.Labels[labelReleaseBaseline], 10, 64)
		if err != nil {
			return nil, errors.New("invalid durable release baseline")
		}
		if current.UpdateStatus != nil && (current.UpdateStatus.State == api.UpdateStatus_ROLLBACK_COMPLETED || current.UpdateStatus.State == api.UpdateStatus_ROLLBACK_STARTED || current.UpdateStatus.State == api.UpdateStatus_ROLLBACK_PAUSED) && current.Meta.Version.Index > storedBaseline && current.Spec.Annotations.Labels[labelReleaseFingerprint] != verified.Fingerprint() {
			return nil, errors.New("signed release already rolled back; a newer signed release is required")
		}
	}
	return applyServiceGuarded(operation, client, intent, guard)
}

// The Raft config is release evidence, not a second task store. Its immutable
// data preserves the root-signed migration while CAS labels retain a high-water
// mark independently of SwarmKit's automatic previous-spec rollback.
func reserveReleaseFloor(ctx context.Context, client api.ControlClient, intent ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring, retained release.SequenceFloor, baseline uint64) (*api.Config, error) {
	identity := sha256.Sum256([]byte(intent.Environment + "/" + intent.Region + "/" + intent.Role))
	name := fmt.Sprintf("ts-release-%x", identity[:16])
	listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{name}}})
	if err != nil {
		return nil, err
	}
	claim := verified.Claim()
	if len(listed.Configs) == 0 {
		migration, err := release.VerifySequenceMigrationCurrent(verified.MigrationEnvelope(), roots, intent.Role, intent.Environment, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		_, digestErr := hex.DecodeString(retained.EvidenceSHA256)
		if retained.Cell != strings.ToUpper(intent.Region) || retained.RunNumber < 0 || retained.RunNumber == 0 && retained.IssuedAt.IsZero() || len(retained.EvidenceSHA256) != 64 || strings.ToLower(retained.EvidenceSHA256) != retained.EvidenceSHA256 || digestErr != nil || !migration.AdmitsLegacyFloor(retained.Cell, retained.RunNumber, retained.IssuedAt) {
			return nil, errors.New("signed migration does not cover retained local legacy release floor")
		}
		wire, err := trust.EncodeEnvelope(verified.MigrationEnvelope())
		if err != nil {
			return nil, err
		}
		labels := map[string]string{LabelIntentID: intent.ID, LabelRole: intent.Role, LabelRegion: intent.Region, LabelEnvironment: intent.Environment, labelReleaseSequence: strconv.FormatUint(claim.ReleaseSequence, 10), labelReleaseFingerprint: verified.Fingerprint(), labelReleaseBaseline: strconv.FormatUint(baseline, 10), "terrascale.legacy-run": strconv.FormatInt(retained.RunNumber, 10), "terrascale.legacy-issued": retained.IssuedAt.UTC().Format(time.RFC3339Nano), "terrascale.legacy-evidence": retained.EvidenceSHA256}
		created, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: api.Annotations{Name: name, Labels: labels}, Data: wire}})
		if err != nil {
			return nil, err
		}
		return created.Config, nil
	}
	if len(listed.Configs) != 1 {
		return nil, errors.New("ambiguous durable release floor")
	}
	current := listed.Configs[0]
	labels := current.Spec.Annotations.Labels
	if labels[LabelIntentID] != intent.ID || labels[LabelRole] != intent.Role || labels[LabelRegion] != intent.Region || labels[LabelEnvironment] != intent.Environment {
		return nil, errors.New("release floor ownership mismatch")
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
	floor, err := strconv.ParseUint(labels[labelReleaseSequence], 10, 64)
	if err != nil || floor == 0 {
		return nil, errors.New("invalid durable release sequence")
	}
	if claim.ReleaseSequence < floor || claim.ReleaseSequence == floor && labels[labelReleaseFingerprint] != verified.Fingerprint() {
		return nil, errors.New("stale or equivocating signed release")
	}
	if claim.ReleaseSequence == floor {
		return current, nil
	}
	spec := current.Spec.Copy()
	spec.Annotations.Labels[labelReleaseSequence] = strconv.FormatUint(claim.ReleaseSequence, 10)
	spec.Annotations.Labels[labelReleaseFingerprint] = verified.Fingerprint()
	spec.Annotations.Labels[labelReleaseBaseline] = strconv.FormatUint(baseline, 10)
	updated, err := client.UpdateConfig(ctx, &api.UpdateConfigRequest{ConfigID: current.ID, ConfigVersion: &current.Meta.Version, Spec: spec})
	if err != nil {
		return nil, err
	}
	return updated.Config, nil
}
