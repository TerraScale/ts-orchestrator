package app

import (
	"context"
	"crypto/tls"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/globalview"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

// observeFunctions reads current admitted intent, manager placement and OCI
// addresses. It creates no worker material, broker grant or observation store.
func (controller functionController) observeFunctions(ctx context.Context, hosts func(context.Context) ([]host.HostStatus, error), membership func(context.Context, string) (swarmruntime.VerifiedWorkerMembership, error)) ([]globalview.FunctionObservation, error) {
	if controller.config.Authority == nil || controller.config.Client == nil || controller.config.Material.Issuer == nil || hosts == nil || membership == nil {
		return nil, errors.New("authenticated function observation sources unavailable")
	}
	entries, err := controller.config.Authority.ListFunctionIntents(ctx)
	if err != nil {
		return nil, err
	}
	if len(entries) > 32 {
		return nil, errors.New("function observation inventory exceeds 32 admitted functions")
	}
	registered, err := hosts(ctx)
	if err != nil {
		return nil, err
	}
	services, err := controller.config.Client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return nil, err
	}
	var observations []globalview.FunctionObservation
	for _, entry := range entries {
		intent, err := authority.DecodeFunctionIntent(entry)
		if err != nil {
			return nil, err
		}
		claim := intent.Claim
		if claim.Cell != strings.ToUpper(controller.config.Cell) || claim.Environment != controller.config.Environment {
			return nil, release.ErrExpectationMismatch
		}
		observation := globalview.FunctionObservation{TenantID: claim.TenantID, FunctionID: claim.FunctionID, Revision: claim.Revision, Digest: claim.Digest, State: "unavailable"}
		proof, err := controller.config.Material.Reader.CurrentFunction(ctx, claim.TenantID, claim.FunctionID)
		if err != nil || proof.EnvelopeSHA256() != intent.EnvelopeSHA256 {
			observations = append(observations, observation)
			continue
		}
		var selected []*api.Service
		for _, service := range services.Services {
			labels := service.Spec.Annotations.Labels
			if labels[swarmruntime.LabelRole] == swarmruntime.FunctionWorkerRole && labels[swarmruntime.LabelFunctionTenant] == claim.TenantID && labels[swarmruntime.LabelFunctionID] == claim.FunctionID && labels[swarmruntime.LabelRegion] == catalog.OCIRegion(claim.Cell) && labels[swarmruntime.LabelEnvironment] == claim.Environment {
				selected = append(selected, service)
			}
		}
		if len(selected) == 0 {
			observation.State, observation.ObservedAt = "unplaced", time.Now().UTC()
			observations = append(observations, observation)
			continue
		}
		if len(selected) != 1 {
			return nil, errors.New("function observation has ambiguous managed services")
		}
		tasks, err := controller.config.Client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{selected[0].ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}}})
		if err != nil {
			return nil, err
		}
		if len(tasks.Tasks) == 0 {
			observation.State, observation.ObservedAt = "unplaced", time.Now().UTC()
			observations = append(observations, observation)
			continue
		}
		if len(tasks.Tasks) > 2 {
			return nil, errors.New("function observation exceeds bounded current task inventory")
		}
		for _, task := range tasks.Tasks {
			current := observation
			current.TaskID, current.NodeID = task.ID, task.NodeID
			if task.NodeID == "" {
				current.State, current.ObservedAt = "unplaced", time.Now().UTC()
			} else if task.Status.State == api.TaskStateRunning {
				snapshot, err := controller.observeFunctionTask(ctx, proof, task, registered, hosts, membership)
				if err == nil {
					current.State, current.Snapshot, current.ObservedAt = "observed", &snapshot, snapshot.ObservedAt
				}
			}
			observations = append(observations, current)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return observations, nil
}

func (controller functionController) observeFunctionTask(ctx context.Context, proof release.VerifiedFunction, task *api.Task, registered []host.HostStatus, hosts func(context.Context) ([]host.HostStatus, error), membership func(context.Context, string) (swarmruntime.VerifiedWorkerMembership, error)) (functions.Snapshot, error) {
	node, err := controller.config.Client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
	if err != nil || node == nil || node.Node == nil {
		return functions.Snapshot{}, errors.New("function task host observation unavailable")
	}
	index := slices.IndexFunc(registered, func(status host.HostStatus) bool {
		return status.Registration.ID == node.Node.Spec.Annotations.Name && status.Verified && !status.Retired
	})
	if index < 0 {
		return functions.Snapshot{}, errors.New("function task host is not currently admitted")
	}
	registration := registered[index].Registration
	member, err := membership(ctx, task.NodeID)
	if err != nil || member.Validate() != nil || member.NodeID() != task.NodeID || member.RegistrationID() != registration.ID ||
		member.OCIRegion() != catalog.OCIRegion(proof.Claim().Cell) || !strings.EqualFold(member.Cell(), proof.Claim().Cell) || member.Role() != "wasm" ||
		member.InstanceID() != node.Node.Spec.Annotations.Labels[swarmruntime.LabelInstanceID] ||
		member.Info().Generation != registration.Generation || member.Info().PublicKey != registration.PublicKey || member.Info().NATSUserPublicKey != registration.NATSUserPublicKey {
		return functions.Snapshot{}, errors.New("function task lacks current independent worker membership")
	}
	fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
	if err != nil {
		return functions.Snapshot{}, err
	}
	binding := functionmaterial.Binding{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, InstanceID: member.InstanceID(), Region: member.OCIRegion(), HostID: registration.ID, Fingerprint: fingerprint}
	before, err := controller.recipient(ctx, registration, binding)
	if err != nil || before.EnvelopeSHA256() != proof.EnvelopeSHA256() {
		return functions.Snapshot{}, errors.New("function snapshot recipient is no longer current")
	}
	ip, err := netip.ParseAddr(member.PrivateIP())
	if err != nil || !ip.Is4() || !ip.IsPrivate() {
		return functions.Snapshot{}, errors.New("function task OCI primary address is unavailable")
	}
	cert, key, ca, err := controller.config.Material.Issuer.IssueFunctionClientTLS(proof)
	if err != nil {
		return functions.Snapshot{}, err
	}
	defer clear(key)
	identity, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return functions.Snapshot{}, errors.New("function snapshot client identity unavailable")
	}
	snapshot, err := functions.ReadSnapshot(ctx, proof, netip.AddrPortFrom(ip, 8080), identity, ca)
	if err != nil {
		return functions.Snapshot{}, err
	}
	if snapshot.Architecture != member.Architecture() {
		return functions.Snapshot{}, errors.New("function snapshot differs from admitted worker architecture")
	}
	after, err := controller.recipient(ctx, registration, binding)
	if err != nil || after.EnvelopeSHA256() != proof.EnvelopeSHA256() {
		return functions.Snapshot{}, errors.New("function snapshot recipient changed while collecting")
	}
	confirmed, err := membership(ctx, task.NodeID)
	if err != nil || confirmed.Validate() != nil || member.Validate() != nil {
		return functions.Snapshot{}, errors.New("function snapshot worker membership unavailable after collection")
	}
	beforeInfo, afterInfo := member.Info(), confirmed.Info()
	beforeInfo.ObservedAt, beforeInfo.ExpiresAt, afterInfo.ObservedAt, afterInfo.ExpiresAt = time.Time{}, time.Time{}, time.Time{}, time.Time{}
	if beforeInfo != afterInfo {
		return functions.Snapshot{}, errors.New("function snapshot worker membership changed while collecting")
	}
	latest, err := hosts(ctx)
	if err != nil || !slices.ContainsFunc(latest, func(status host.HostStatus) bool {
		current := status.Registration
		return status.Verified && !status.Retired && current.ID == registration.ID && current.Generation == registration.Generation && current.PublicKey == registration.PublicKey && current.NATSUserPublicKey == registration.NATSUserPublicKey
	}) {
		return functions.Snapshot{}, errors.New("function snapshot host admission changed while collecting")
	}
	return snapshot, nil
}
