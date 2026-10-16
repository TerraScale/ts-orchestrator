package swarmruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LabelFunctionWorkerBundle pins the exact retained qualified worker bundle.
const LabelFunctionWorkerBundle = "terrascale.function-worker-bundle"

// SwarmKit's immutable Config data must remain below its 1000 KiB limit.
const maxFunctionWorkerBundleBytes = 1000*1024 - 1

func (i FunctionServiceIntent) workerBundleAnnotations(digest string, sequence string, identity string) (api.Annotations, error) {
	for _, value := range []string{digest, identity} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || value != strings.ToLower(value) {
			return api.Annotations{}, errors.New("function worker bundle requires exact SHA-256 references")
		}
	}
	number, err := strconv.ParseUint(sequence, 10, 64)
	if err != nil || number == 0 || strconv.FormatUint(number, 10) != sequence {
		return api.Annotations{}, errors.New("function worker bundle requires a canonical release sequence")
	}
	key := sha256.Sum256([]byte(i.Environment + "/" + i.Region + "/" + i.Architecture + "/" + digest))
	// Base32 retains the full digest within SwarmKit's 64-character name limit.
	name := "ts-fw-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key[:]))
	return api.Annotations{Name: name, Labels: map[string]string{
		LabelIntentID: entityid.Derive("function-worker-release", i.Environment, i.Region),
		LabelRole:     FunctionWorkerRole, LabelRegion: i.Region, LabelEnvironment: i.Environment,
		labelReleaseArchitecture: i.Architecture, labelReleaseSequence: sequence,
		labelReleaseFingerprint: identity, LabelFunctionWorkerBundle: digest,
	}}, nil
}

func workerBundleMatches(config *api.Config, annotations api.Annotations) bool {
	if config == nil || config.ID == "" || config.Spec.Annotations.Name != annotations.Name {
		return false
	}
	for key, value := range annotations.Labels {
		if config.Spec.Annotations.Labels[key] != value {
			return false
		}
	}
	return len(config.Spec.Data) > 0 && len(config.Spec.Data) <= maxFunctionWorkerBundleBytes && fmt.Sprintf("%x", sha256.Sum256(config.Spec.Data)) == annotations.Labels[LabelFunctionWorkerBundle]
}

func (i FunctionServiceIntent) retainWorkerBundle(ctx context.Context, client api.ControlClient, bundle release.ContainerBundle, worker release.VerifiedContainer) error {
	wire, err := protocol.EncodeJSON(bundle)
	if err != nil {
		return err
	}
	if len(wire) > maxFunctionWorkerBundleBytes || fmt.Sprintf("%x", sha256.Sum256(wire)) != worker.BundleSHA256() {
		return errors.New("function worker bundle differs from the independently verified bytes or exceeds manager storage")
	}
	annotations, err := i.workerBundleAnnotations(worker.BundleSHA256(), strconv.FormatUint(worker.Claim().ReleaseSequence, 10), worker.ReleaseIdentity())
	if err != nil {
		return err
	}
	listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{annotations.Name}}})
	if err != nil {
		return err
	}
	if listed == nil {
		return errors.New("function worker bundle manager returned no config listing")
	}
	if len(listed.Configs) == 0 {
		_, err := client.CreateConfig(ctx, &api.CreateConfigRequest{Spec: &api.ConfigSpec{Annotations: annotations, Data: wire}})
		if status.Code(err) != codes.AlreadyExists {
			return err
		}
		listed, err = client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{annotations.Name}}})
		if err != nil {
			return err
		}
	}
	if listed == nil || len(listed.Configs) != 1 || !workerBundleMatches(listed.Configs[0], annotations) || !bytes.Equal(listed.Configs[0].Spec.Data, wire) {
		return errors.New("retained function worker bundle conflicts with verified immutable bytes")
	}
	// shortcut: retain immutable proofs until manager-atomic deletion can protect current/previous recipes, live tasks and release floors.
	return nil
}

// WorkerBundleForTask loads the exact retained bytes pinned by a task. The result
// is untrusted: callers must VerifyContainerCurrent and VerifyFunctionRegistryTask.
func (i FunctionServiceIntent) WorkerBundleForTask(ctx context.Context, client api.ControlClient, task *api.Task) (release.ContainerBundle, error) {
	if client == nil || task == nil {
		return release.ContainerBundle{}, errors.New("function worker bundle requires a manager and task")
	}
	labels := task.ServiceAnnotations.Labels
	for key, value := range map[string]string{
		LabelIntentID: entityid.Derive("function-service", i.Environment, i.Region, i.TenantID, i.FunctionID),
		LabelRole:     FunctionWorkerRole, LabelRegion: i.Region, LabelEnvironment: i.Environment,
		LabelFunctionTenant: i.TenantID, LabelFunctionID: i.FunctionID,
	} {
		if labels[key] != value {
			return release.ContainerBundle{}, errors.New("function worker bundle task target differs")
		}
	}
	if _, err := DecodeContainer(task); err != nil {
		return release.ContainerBundle{}, err
	}
	annotations, err := i.workerBundleAnnotations(labels[LabelFunctionWorkerBundle], labels[labelReleaseSequence], labels[labelReleaseFingerprint])
	if err != nil {
		return release.ContainerBundle{}, err
	}
	listed, err := client.ListConfigs(ctx, &api.ListConfigsRequest{Filters: &api.ListConfigsRequest_Filters{Names: []string{annotations.Name}}})
	if err != nil {
		return release.ContainerBundle{}, err
	}
	if listed == nil || len(listed.Configs) != 1 || !workerBundleMatches(listed.Configs[0], annotations) {
		return release.ContainerBundle{}, errors.New("function worker task has no unique matching retained bundle")
	}
	var bundle release.ContainerBundle
	if err := protocol.DecodeStrict(listed.Configs[0].Spec.Data, &bundle, maxFunctionWorkerBundleBytes); err != nil {
		return release.ContainerBundle{}, err
	}
	return bundle, nil
}
