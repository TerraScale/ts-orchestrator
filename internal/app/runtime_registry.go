package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/containermaterial"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	ociregistry "github.com/TerraScale/ts-orchestrator/internal/ociregion/registry"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
)

const runtimeRegistrySourceCommand = "runtime-registry-admission-source"
const runtimeRegistrySourceBytes = 128 << 10

type runtimeRegistryQuery struct {
	OperationID  string `json:"operation_id"`
	Architecture string `json:"architecture"`
}

type runtimeRegistrySnapshot struct {
	Intent       delivery.Intent            `json:"intent"`
	Service      swarmruntime.ServiceIntent `json:"service"`
	Chain        trust.RootChain            `json:"root_chain"`
	SpecRevision uint64                     `json:"spec_revision"`
}

// The same-binary child reads controller-owned broker credentials at the
// controller UID. Neither broker credentials nor registry values cross stdout.
func runRuntimeRegistrySource(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	if len(args) != 0 || os.Geteuid() != int(uid) || os.Getegid() != int(gid) {
		return errors.New("registry source requires the fixed controller service account and no arguments")
	}
	wire, err := io.ReadAll(io.LimitReader(input, runtimeRegistrySourceBytes+1))
	if err != nil || len(wire) == 0 || len(wire) > runtimeRegistrySourceBytes {
		return errors.New("registry source query is missing or oversized")
	}
	var query runtimeRegistryQuery
	if err := json.Unmarshal(wire, &query, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	if !entityid.Valid(query.OperationID) || query.Architecture != "arm64" && query.Architecture != "amd64" {
		return errors.New("registry source requires exact operation and architecture locators")
	}
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil {
		return err
	}
	gate, accepted, err := acceptedControllerAdmissionGate(cfg, bootstrapstart.NewMarkerStore(), controllerClockCheck(controllerBrokerClockProbe()))
	if err != nil {
		return err
	}
	if _, err := gate.AdmitRestartLocal(ctx); err != nil {
		return err
	}
	broker := cfg.NATS
	broker.Embedded = nil
	broker.ClientRole = "controller"
	runtime, err := natscell.Start(ctx, broker)
	if err != nil {
		return err
	}
	defer runtime.Close()
	services, policy, err := runtimeRegistryPolicy(ctx, cfg, runtime.JetStream())
	if err != nil {
		return err
	}
	service, err := delivery.ConnectClient(ctx, delivery.Config{Conn: runtime.Conn(), JS: runtime.JetStream(), Cell: cfg.NATS.Cell,
		Verifier: policy.codec, Authorize: policy.authorizeIntent})
	if err != nil {
		return err
	}
	intent, err := service.ContainerIntent(ctx, query.OperationID)
	if err != nil {
		return err
	}
	adopted, err := services.kv.Get(ctx, cellSpecKey)
	if err != nil || adopted.Revision() != services.revision {
		return errors.New("registry service profile is not the current adopted revision")
	}
	profileProof, err := containermaterial.VerifyProfile(adopted.Value(), services.roots.current(), services.identity, intent)
	if err != nil {
		return err
	}
	profile := profileProof.Profile()
	entry, ok := catalog.CellForOCIRegion(catalog.OCIRegion(strings.ToUpper(accepted.Cell)))
	if !ok {
		return errors.New("registry source requires an admitted canonical OCI region")
	}
	expected, err := platformServiceIntent(intent, profile, entry.OCIRegion, query.Architecture)
	if err != nil {
		return err
	}
	freshServices, freshPolicy, err := runtimeRegistryPolicy(ctx, cfg, runtime.JetStream())
	if err != nil || freshServices.revision != services.revision || freshServices.roots.verified.Head != services.roots.verified.Head {
		return errors.New("current service authority changed during registry source observation")
	}
	freshService, err := delivery.ConnectClient(ctx, delivery.Config{Conn: runtime.Conn(), JS: runtime.JetStream(), Cell: cfg.NATS.Cell,
		Verifier: freshPolicy.codec, Authorize: freshPolicy.authorizeIntent})
	if err != nil {
		return err
	}
	confirmed, err := freshService.ContainerIntent(ctx, query.OperationID)
	if err != nil {
		return err
	}
	before, err := intent.Fingerprint()
	after, afterErr := confirmed.Fingerprint()
	if err != nil || afterErr != nil || before != after {
		return errors.New("container operation changed during source observation")
	}
	currentSpec, specErr := services.kv.Get(ctx, cellSpecKey)
	if specErr == nil && currentSpec.Revision() != services.revision ||
		errors.Is(specErr, jetstream.ErrKeyNotFound) && services.revision != 0 ||
		specErr != nil && !errors.Is(specErr, jetstream.ErrKeyNotFound) {
		return errors.New("adopted service profile changed during registry source observation")
	}
	wire, err = protocol.EncodeJSON(runtimeRegistrySnapshot{Intent: intent.Clone(), Service: expected, Chain: freshServices.roots.reply("").Chain, SpecRevision: freshServices.revision})
	if err != nil || len(wire) > runtimeRegistrySourceBytes {
		return errors.New("registry source response is oversized")
	}
	_, err = output.Write(wire)
	return err
}

func runtimeRegistryPolicy(ctx context.Context, cfg Config, js jetstream.JetStream) (*specRegistry, signerPolicy, error) {
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return nil, signerPolicy{}, err
	}
	managed, err := loadManagedControllerConfig(cfg)
	if err != nil || managed == nil {
		return nil, signerPolicy{}, errors.New("registry source requires the admitted managed controller")
	}
	services, err := newSpecRegistry(cfg, managed.placement.MemberRole)
	if err != nil {
		return nil, signerPolicy{}, err
	}
	services.ociRegion = &managed.region
	services.replaceSigners = policy.replaceSigners
	policy.services = services
	services.kv, err = js.KeyValue(ctx, cellSpecBucket)
	if err != nil {
		return nil, signerPolicy{}, err
	}
	rootKV, err := js.KeyValue(ctx, rootChainBucket)
	if err != nil {
		return nil, signerPolicy{}, err
	}
	rootEntry, err := rootKV.Get(ctx, rootChainKey)
	if err == nil {
		chain, err := trust.DecodeRootChain(rootEntry.Value())
		if err != nil {
			return nil, signerPolicy{}, err
		}
		if err := services.roots.adopt(chain); err != nil {
			return nil, signerPolicy{}, err
		}
	} else if !errors.Is(err, jetstream.ErrKeyNotFound) || len(services.roots.chain.Rotations) != 0 {
		return nil, signerPolicy{}, errors.New("registry source current root chain is unavailable")
	}
	entry, err := services.kv.Get(ctx, cellSpecKey)
	if err != nil {
		return nil, signerPolicy{}, errors.New("registry requires an adopted root-signed service profile")
	}
	if err := services.load(entry); err != nil {
		return nil, signerPolicy{}, err
	}
	channelKV, err := js.KeyValue(ctx, releasechannel.Bucket)
	if err != nil {
		return nil, signerPolicy{}, err
	}
	releases := serviceReleases{policy: policy, cell: cfg.NATS.Cell, environment: services.identity.Environment, roots: services.roots.current}
	if err := releases.trustReleaseDelegation(ctx, channelKV); err != nil {
		return nil, signerPolicy{}, err
	}
	return services, policy, nil
}

func readRuntimeRegistrySource(ctx context.Context, query runtimeRegistryQuery) (runtimeRegistrySnapshot, error) {
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return runtimeRegistrySnapshot{}, err
	}
	wire, err := protocol.EncodeJSON(query)
	if err != nil {
		return runtimeRegistrySnapshot{}, err
	}
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(childCtx, "/proc/self/exe", runtimeRegistrySourceCommand)
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	command.Stdin = bytes.NewReader(wire)
	var output runtimeRegistryOutput
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return runtimeRegistrySnapshot{}, errors.New("current authenticated container admission source unavailable")
	}
	var snapshot runtimeRegistrySnapshot
	if err := json.Unmarshal(output.data, &snapshot, json.RejectUnknownMembers(true)); err != nil {
		return runtimeRegistrySnapshot{}, err
	}
	return snapshot, nil
}

type runtimeRegistryOutput struct{ data []byte }

func (output *runtimeRegistryOutput) Write(wire []byte) (int, error) {
	if len(output.data)+len(wire) > runtimeRegistrySourceBytes {
		return 0, errors.New("registry source response is oversized")
	}
	output.data = append(output.data, wire...)
	return len(wire), nil
}

func managedRuntimeRegistryResolver(ctx context.Context, cfg Config, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity, node *swarmruntime.Node) (swarmruntime.RegistryResolver, error) {
	if os.Geteuid() != 0 || reader == nil || node == nil {
		return nil, errors.New("registry requires the current root-owned regional runtime")
	}
	authority, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	identity := authority.Identity()
	factory, err := ociclient.InstancePrincipal(identity.OCIRegion)
	if err != nil {
		return nil, err
	}
	services, err := newSpecRegistry(cfg, "")
	if err != nil {
		return nil, err
	}
	rootState := services.roots
	// The fixed controller child owns persistence of the manager's root chain.
	rootState.path = ""
	return swarmruntime.NewOCIRegistryResolver(factory, func(ctx context.Context, task *api.Task) (*swarmruntime.RegistryAdmission, error) {
		if task == nil || !entityid.Valid(task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID]) {
			return nil, errors.New("registry task has no authenticated operation locator")
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		current, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
		if err != nil || current.Identity() != identity {
			return nil, errors.New("registry regional runtime authority changed")
		}
		client, err := node.ControlClient(ctx)
		if err != nil {
			return nil, err
		}
		assigned, err := client.GetNode(ctx, &api.GetNodeRequest{NodeID: task.NodeID})
		if err != nil || assigned.Node == nil || assigned.Node.Description == nil || assigned.Node.Description.Platform == nil {
			return nil, errors.New("registry task node admission is unavailable")
		}
		query := runtimeRegistryQuery{OperationID: task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID], Architecture: assigned.Node.Description.Platform.Architecture}
		snapshot, err := readRuntimeRegistrySource(ctx, query)
		if err != nil {
			return nil, err
		}
		intent := snapshot.Intent
		expected := snapshot.Service
		if intent.Validate() != nil || intent.Container == nil || intent.Cell != strings.ToLower(identity.Cell) || intent.Environment != identity.Environment ||
			expected.ID != entityid.Derive("platform-service", intent.Role, identity.Environment, identity.OCIRegion) ||
			expected.OperationID != intent.OperationID || expected.Role != intent.Role || expected.Region != identity.OCIRegion || expected.Environment != identity.Environment {
			return nil, errors.New("registry source differs from admitted service identity")
		}
		baked, err := bootstrapstart.LoadBakedInputs()
		if err != nil {
			return nil, err
		}
		if err := rootState.adopt(baked.Chain); err != nil {
			return nil, err
		}
		if err := rootState.adopt(snapshot.Chain); err != nil {
			return nil, err
		}
		rootHead := rootState.reply("").Head
		roots := rootState.current()
		location, err := instancePrincipalChannel(identity.OCIRegion, identity.Cell).get(ctx)
		if err != nil {
			return nil, err
		}
		deadline, _ := ctx.Deadline()
		target := release.ContainerTarget{Cell: identity.Cell, Environment: identity.Environment, Role: intent.Role, Architecture: expected.Architecture}
		allocations, err := currentContainerAllocations(ctx, factory, *intent.Container, roots, target)
		if err != nil {
			return nil, err
		}
		verified, err := release.VerifyContainerCurrent(ctx, *intent.Container, roots, target,
			time.Now().UTC(), deadline, func(ctx context.Context, digest string) (io.ReadCloser, error) {
				return releasechannel.ReadContainerEvidence(ctx, location, intent.Role, digest)
			}, allocations)
		if err != nil {
			return nil, err
		}
		if err := swarmruntime.VerifyRegistryTask(ctx, client, task, expected, verified, roots); err != nil {
			return nil, err
		}
		admission, err := runtimeRegistryPullAdmission(ctx, factory, task, expected, verified, rootState)
		if err != nil {
			return nil, err
		}
		confirmed, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
		if err != nil || confirmed.Identity() != identity {
			return nil, errors.New("registry runtime authority changed during credential admission")
		}
		confirmedSnapshot, err := readRuntimeRegistrySource(ctx, query)
		if err != nil {
			return nil, err
		}
		before, beforeErr := intent.Fingerprint()
		after, afterErr := confirmedSnapshot.Intent.Fingerprint()
		confirmedRoots, rootsErr := trust.VerifyRootChain(baked.Genesis, baked.Identity.ChainIdentity(), confirmedSnapshot.Chain)
		if beforeErr != nil || afterErr != nil || before != after || confirmedSnapshot.SpecRevision != snapshot.SpecRevision || rootsErr != nil || confirmedRoots.Head != rootHead || rootState.reply("").Head != rootHead {
			return nil, errors.New("registry manager authority changed during credential admission")
		}
		if err := swarmruntime.VerifyRegistryTask(ctx, client, task, expected, verified, roots); err != nil {
			return nil, err
		}
		return admission, nil
	})
}

// runtimeRegistryPullAdmission derives Vault references exclusively from the
// fresh root-signed OCI issuer binding, never from a task or controller reply.
func runtimeRegistryPullAdmission(ctx context.Context, factory *ociclient.Factory, task *api.Task, expected swarmruntime.ServiceIntent, verified release.VerifiedContainer, roots *rootRegistry) (*swarmruntime.RegistryAdmission, error) {
	name, digest, ok := strings.Cut(verified.Claim().Image, "@")
	if !ok || name == "" || digest == "" {
		return nil, errors.New("signed release has no exact registry repository and digest")
	}
	secrets, err := ociregistry.NewPullSecrets(factory)
	if err != nil {
		return nil, err
	}
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	foundations, err := region.NewFoundationDiscovery(factory, local.anchor, roots.current())
	if err != nil {
		return nil, err
	}
	issuer, err := foundations.OCIRIssuer(ctx, name)
	if err != nil {
		return nil, err
	}
	if issuer.Intent().OCIRegion != expected.Region || issuer.ImageRepository() != name {
		return nil, errors.New("registry issuer differs from admitted OCI region or signed image repository")
	}
	approved := issuer.Intent()
	host := approved.RegistryHost
	repository := approved.RegistryNamespace + "/" + approved.RepositoryName
	if name != host+"/"+repository {
		return nil, errors.New("signed release does not use the root-owned registry repository")
	}
	owned := ociregistry.PullSecret{RegistryHost: host, Repository: repository, Ref: vaultsecret.Ref{Vault: approved.VaultTarget.VaultID, Name: approved.SecretName}}
	scope := ociregistry.PullScope{RegistryHost: host, Repository: repository, Digest: digest, TaskPrincipal: expected.ID}
	claim, err := secrets.Describe(ctx, scope, owned, issuer.Generation())
	if err != nil {
		return nil, err
	}
	fresh, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return nil, err
	}
	currentRoots, err := trust.VerifyRootChain(fresh.Genesis, fresh.Identity.ChainIdentity(), fresh.Chain)
	if err != nil || currentRoots.Head != roots.reply("").Head {
		return nil, errors.New("registry trusted roots changed during credential admission")
	}
	freshFoundations, err := region.NewFoundationDiscovery(factory, local.anchor, currentRoots.Current)
	if err != nil {
		return nil, err
	}
	if err := freshFoundations.GuardOCIRIssuer(ctx, issuer); err != nil {
		return nil, err
	}

	if !verified.Valid(time.Now().UTC()) {
		return nil, errors.New("registry release authorization expired during credential admission")
	}
	return &swarmruntime.RegistryAdmission{ServiceID: task.ServiceID, Environment: expected.Environment, Region: expected.Region, Scope: scope, Secret: owned, Claim: claim}, nil
}

func (controller *containerMaterialController) registryAdmission(ctx context.Context, registration host.Registration, binding host.ContainerMaterialBinding) (host.RegistryAdmissionDocument, error) {
	recipient, err := controller.registryRecipient(ctx, registration, binding)
	if err != nil {
		return host.RegistryAdmissionDocument{}, err
	}
	document, err := protocol.EncodeJSON(runtimeRegistrySnapshot{Intent: recipient.Intent.Clone(), Service: recipient.Expected,
		Chain: controller.config.Specs.roots.reply("").Chain, SpecRevision: recipient.SpecRevision})
	if err != nil || len(document) > runtimeRegistrySourceBytes {
		return host.RegistryAdmissionDocument{}, errors.New("registry admission source document is oversized")
	}
	expires := time.Now().UTC().Truncate(time.Minute).Add(2 * time.Minute)
	if recipient.Verified.ExpiresAt().Before(expires) {
		expires = recipient.Verified.ExpiresAt()
	}
	return host.RegistryAdmissionDocument{Document: document, ExpiresAt: expires}, nil
}

// The same live Agent that owns worker execution supplies current controller
// admission. The signed enrollment fixes the recipient but grants no OCI writes.
func workerRuntimeRegistryResolver(ctx context.Context, cfg Config, agent *host.Agent, accepted hostenroll.VerifiedSwarmWorker) (swarmruntime.RegistryResolver, error) {
	signed := accepted.Worker()
	if os.Geteuid() != 0 || agent == nil || signed.Role != "container" || len(accepted.Wire()) == 0 || signed.Validate(time.Now().UTC()) != nil {
		return nil, errors.New("registry worker requires current signed enrollment and its live host agent")
	}
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	if local.instanceID != signed.InstanceID || local.factory.Region() != signed.OCIRegion ||
		local.baked.Identity.DeploymentID != signed.DeploymentID || local.baked.Identity.Environment != signed.Environment ||
		!strings.EqualFold(string(local.baked.Identity.Cell), signed.Cell) || cfg.NATS.Cell != strings.ToLower(signed.Cell) {
		return nil, errors.New("registry worker differs from its root-owned OCI identity")
	}
	roots, err := newRootRegistry(local.baked.Genesis, local.baked.Identity.ChainIdentity(), local.baked.Chain, bootstrapstart.RootChainFile)
	if err != nil {
		return nil, err
	}
	return swarmruntime.NewOCIRegistryResolver(local.factory, func(ctx context.Context, task *api.Task) (*swarmruntime.RegistryAdmission, error) {
		if task == nil || !entityid.Valid(task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID]) {
			return nil, errors.New("registry worker task has no durable operation locator")
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		fingerprint, err := swarmruntime.ContainerTaskFingerprint(task)
		if err != nil {
			return nil, err
		}
		binding := host.ContainerMaterialBinding{TaskID: task.ID, ServiceID: task.ServiceID, NodeID: task.NodeID,
			InstanceID: signed.InstanceID, Region: signed.OCIRegion, HostID: signed.RegistrationID, Fingerprint: fingerprint}
		document, err := agent.CurrentRegistryAdmission(ctx, binding)
		if err != nil {
			return nil, err
		}
		var snapshot runtimeRegistrySnapshot
		if err := protocol.DecodeStrict(document.Document, &snapshot, runtimeRegistrySourceBytes); err != nil {
			return nil, err
		}
		baked, err := bootstrapstart.LoadBakedInputs()
		if err != nil {
			return nil, err
		}
		if err := roots.adopt(baked.Chain); err != nil {
			return nil, err
		}
		if err := roots.adopt(snapshot.Chain); err != nil {
			return nil, err
		}
		rootHead := roots.reply("").Head
		intent, expected := snapshot.Intent, snapshot.Service
		if intent.Validate() != nil || intent.Container == nil || intent.Cell != strings.ToLower(signed.Cell) || intent.Environment != signed.Environment ||
			expected.ID != entityid.Derive("platform-service", intent.Role, signed.Environment, signed.OCIRegion) ||
			expected.OperationID != intent.OperationID || expected.OperationID != task.ServiceAnnotations.Labels[swarmruntime.LabelOperationID] ||
			expected.Role != intent.Role || expected.Region != signed.OCIRegion || expected.Environment != signed.Environment || expected.Architecture != signed.Architecture {
			return nil, errors.New("registry worker source differs from enrolled recipient and task")
		}
		location, err := instancePrincipalChannel(signed.OCIRegion, strings.ToUpper(signed.Cell)).get(ctx)
		if err != nil {
			return nil, err
		}
		deadline, _ := ctx.Deadline()
		currentRoots := roots.current()
		target := release.ContainerTarget{Cell: strings.ToUpper(signed.Cell), Environment: signed.Environment, Role: intent.Role, Architecture: signed.Architecture}
		allocations, err := currentContainerAllocations(ctx, local.factory, *intent.Container, currentRoots, target)
		if err != nil {
			return nil, err
		}
		verified, err := release.VerifyContainerCurrent(ctx, *intent.Container, currentRoots, target,
			time.Now().UTC(), deadline, func(ctx context.Context, digest string) (io.ReadCloser, error) {
				return releasechannel.ReadContainerEvidence(ctx, location, intent.Role, digest)
			}, allocations)
		if err != nil {
			return nil, err
		}
		spec, err := swarmruntime.DecodeContainer(task)
		if err != nil || expected.Container == nil || expected.Container.Image != verified.Claim().Image || spec.Image != verified.Claim().Image {
			return nil, errors.New("registry worker task differs from signed OCI image")
		}
		admission, err := runtimeRegistryPullAdmission(ctx, local.factory, task, expected, verified, roots)
		if err != nil {
			return nil, err
		}
		confirmedDocument, err := agent.CurrentRegistryAdmission(ctx, binding)
		if err != nil {
			return nil, err
		}
		var confirmed runtimeRegistrySnapshot
		if err := protocol.DecodeStrict(confirmedDocument.Document, &confirmed, runtimeRegistrySourceBytes); err != nil {
			return nil, err
		}
		before, err := intent.Fingerprint()
		after, afterErr := confirmed.Intent.Fingerprint()
		currentRoots, rootsErr := trust.VerifyRootChain(baked.Genesis, baked.Identity.ChainIdentity(), confirmed.Chain)
		if err != nil || afterErr != nil || before != after || confirmed.SpecRevision != snapshot.SpecRevision || rootsErr != nil || currentRoots.Head != rootHead || roots.reply("").Head != rootHead ||
			!time.Now().Before(document.ExpiresAt) || !time.Now().Before(confirmedDocument.ExpiresAt) || !verified.Valid(time.Now().UTC()) {
			return nil, errors.New("registry worker authority changed during credential admission")
		}
		return admission, nil
	})
}
