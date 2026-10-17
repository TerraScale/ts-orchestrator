package rootrelease

import (
	"bytes"
	"context"
	"errors"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
)

func (b *Backend) ready(ctx context.Context, s *Sources, client api.ControlClient, service *api.Service, expected swarmruntime.ServiceIntent, verified release.VerifiedContainer, roots trust.Keyring, profile containermaterial.Profile, signedSpec []byte, sessions map[string]*host.ContainerGenerationSession, controllers map[string]*bootstrapstart.ControllerHostRecipient) (time.Time, error) {
	spec, err := cellspec.VerifyHistorical(signedSpec, roots, profile.Identity())
	if err != nil || !spec.RootSigned {
		return time.Time{}, errors.Join(ErrPending, err)
	}
	hosts, err := s.Hosts.ListHosts(ctx)
	if err != nil {
		return time.Time{}, err
	}
	until, ok := ctx.Deadline()
	if !ok {
		return time.Time{}, ErrPending
	}

	listed, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{service.ID}, DesiredStates: []api.TaskState{api.TaskStateRunning}, UpToDate: true}})
	if err != nil || listed == nil {
		return time.Time{}, errors.Join(ErrPending, err)
	}
	type admittedTask struct {
		task         *api.Task
		address      netip.Addr
		registration host.Registration
		binding      host.ContainerMaterialBinding
		controller   *bootstrapstart.ControllerHostRecipient
	}
	admitted := map[string]admittedTask{}
	for _, task := range listed.Tasks {
		admit := func() error {

			reject := func(err error) error { return errors.Join(ErrPending, err) }
			if task == nil || task.NodeID == "" || task.ServiceID != service.ID {
				return reject(nil)
			}
			response, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
			if err != nil {
				return reject(err)
			}
			if response == nil || response.Node == nil {
				return reject(nil)
			}
			node := response.Node
			labels := node.Spec.Annotations.Labels
			var status *host.HostStatus

			hostNode := ""
			if node.Role == api.NodeRoleManager {
				for _, grant := range spec.HostGrants {
					if grant.Controller == node.Spec.Annotations.Name && grant.Environment == expected.Environment && slices.Contains(grant.Roles, expected.Role) {
						if hostNode != "" {
							return reject(nil)
						}
						hostNode = grant.Node
					}
				}
				if hostNode == "" {
					return reject(nil)
				}
			}
			for i := range hosts {
				if node.Role == api.NodeRoleManager && hosts[i].Registration.Node == hostNode || node.Role == api.NodeRoleWorker && hosts[i].Registration.ID == node.Spec.Annotations.Name {
					if status != nil {
						return reject(nil)
					}
					status = &hosts[i]
				}
			}
			if status == nil || status.Retired || !time.Now().Before(status.SessionExpiresAt) || !slices.Contains(status.Registration.Roles, expected.Role) {
				return reject(nil)
			}
			registration := status.Registration

			session := sessions[registration.Node]
			if session == nil {
				session, err = s.Hosts.AdmitContainerGenerationSession(ctx, registration.Node)
				if err != nil {
					return reject(err)
				}
				sessions[registration.Node] = session
			}
			if err := session.Guard(ctx); err != nil {
				return reject(err)
			}
			originalRegistration, err := session.Registration()
			if err != nil {
				return reject(err)
			}
			before, beforeErr := protocol.EncodeJSON(originalRegistration)
			after, afterErr := protocol.EncodeJSON(registration)
			if beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) {
				return reject(nil)
			}
			until = earlier(until, session.Deadline())
			if registration.Cell != strings.ToLower(verified.Claim().Cell) || registration.Environment != expected.Environment {
				return reject(nil)
			}
			until = earlier(until, status.SessionExpiresAt)
			address, err := netip.ParseAddr(node.Status.Addr)
			if err != nil || !address.Is4() || !address.IsPrivate() {
				return reject(nil)
			}
			fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
			if err != nil {
				return reject(err)
			}
			binding := host.ContainerMaterialBinding{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID, InstanceID: labels[swarmruntime.LabelInstanceID], Region: expected.Region, HostID: registration.ID, Fingerprint: fingerprint}
			var controller *bootstrapstart.ControllerHostRecipient
			if node.Role == api.NodeRoleManager {
				controller = controllers[registration.Node]
				if controller == nil {
					controller, err = bootstrapstart.ReadControllerHostRecipient(ctx, s.Authority, s.Accepted, signedSpec, registration.Node, binding.InstanceID, address.String())
					if err != nil {
						return reject(err)
					}
					controllers[registration.Node] = controller
				}
				if controller.InstanceID() != binding.InstanceID || controller.PrivateIP() != address.String() || controller.ControllerSlot() != node.Spec.Annotations.Name || !controller.Valid(time.Now()) {
					return reject(nil)
				}
				binding.HostID = controller.ControllerSlot()
				until = earlier(until, controller.Deadline())
			} else {
				if registration.ManagedOCI == nil || registration.ManagedOCI.InstanceID != binding.InstanceID {
					return reject(nil)
				}
				instances, err := s.Fleet.ObserveSelected(ctx, func(id, node string) bool { return id == binding.InstanceID })
				if err != nil {
					return reject(err)
				}
				if len(instances) != 1 {
					return reject(nil)
				}
				instance := instances[0]
				if instance.ID != binding.InstanceID || instance.Node != registration.Node || instance.PrivateIP != address.String() || instance.State != "running" && instance.State != "RUNNING" ||
					instance.Owner != registration.ManagedOCI.Owner || instance.Generation != registration.ManagedOCI.FleetGeneration || instance.CreateKey != registration.ManagedOCI.CreateKey {
					return reject(nil)
				}
			}
			if err := containermaterial.VerifyCurrentMaterialTask(ctx, client, task, expected, verified, roots, profile, registration, binding, controller); err != nil {
				return reject(err)
			}

			admitted[task.ID] = admittedTask{task.Copy(), address, registration, binding, controller}
			return nil
		}
		if err := admit(); err != nil {
			return time.Time{}, err
		}
	}
	ready, err := swarmruntime.ReadyService(ctx, client, service, func(ctx context.Context, task *api.Task) error {
		if task == nil {
			return ErrPending
		}
		previous, ok := admitted[task.ID]
		if !ok || !proto.Equal(task, previous.task) {
			return ErrPending
		}
		return swarmruntime.ProbeTask(ctx, task, previous.address)
	})
	if err != nil || !ready {
		return time.Time{}, errors.Join(ErrPending, err)
	}
	currentHosts, err := s.Hosts.ListHosts(ctx)
	if err != nil {
		return time.Time{}, err
	}
	for _, item := range admitted {
		current := false
		for _, status := range currentHosts {
			if status.Registration.ID != item.registration.ID {
				continue
			}
			before, beforeErr := protocol.EncodeJSON(item.registration)
			after, afterErr := protocol.EncodeJSON(status.Registration)
			if beforeErr != nil || afterErr != nil || !bytes.Equal(before, after) || status.Retired || !time.Now().Before(status.SessionExpiresAt) {
				return time.Time{}, ErrPending
			}
			until = earlier(until, status.SessionExpiresAt)
			current = true
		}

		if !current {
			return time.Time{}, ErrPending
		}
		if err := sessions[item.registration.Node].Guard(ctx); err != nil {
			return time.Time{}, err
		}
		if err := containermaterial.VerifyCurrentMaterialTask(ctx, client, item.task, expected, verified, roots, profile, item.registration, item.binding, item.controller); err != nil {
			return time.Time{}, err
		}
	}
	return until, ctx.Err()
}
