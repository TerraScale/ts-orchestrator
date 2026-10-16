package app

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/functionmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
)

// The caller installs the returned controller's providers in the existing host
// session and its demand source in the existing regional scaler.
func startAutomaticFunctions(ctx context.Context, cfg Config, runtime *natscell.Runtime, control *authority.Runtime,
	client api.ControlClient, roots *rootRegistry, factory *ociclient.Factory, artifacts jetstream.ObjectStore,
	accounts *brokerauth.Store, hosts func(context.Context) ([]host.HostStatus, error),
	membership func(context.Context, string) (swarmruntime.VerifiedWorkerMembership, error),
) (functionController, func(), error) {
	fail := func(err error) (functionController, func(), error) { return functionController{}, nil, err }
	if runtime == nil || control == nil || client == nil || roots == nil || factory == nil || artifacts == nil || accounts == nil || hosts == nil || membership == nil {
		return fail(errors.New("automatic functions require current regional authority, stores, manager and worker membership"))
	}
	local, startup, present, err := installedAutomaticStartup(ctx)
	if err != nil || !present {
		return fail(errors.Join(errors.New("automatic functions require genuine sealed startup authority"), err))
	}
	manifest := startup.Manifest()
	if strings.ToLower(string(manifest.Cell)) != cfg.NATS.Cell || manifest.Slot != cfg.NATS.Instance || manifest.Environment != roots.identity.Environment ||
		factory.Region() != catalog.OCIRegion(string(manifest.Cell)) || local.factory.Region() != factory.Region() ||
		roots.identity.DeploymentID != manifest.DeploymentID {
		return fail(errors.New("function startup differs from the current regional identity"))
	}
	template, err := bootstrap.VerifyBoundRegionalStartupTemplate(ctx, factory, startup.GrantWire(), roots.current(), local.anchor, manifest.Cell, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	address, err := template.SlotPrivateIP(manifest.Slot)
	if err != nil || cfg.NATS.URL != "tls://"+address+":4222" {
		return fail(errors.Join(errors.New("function broker endpoint differs from its signed controller slot"), err))
	}
	foundation, err := local.foundations.Resolve(ctx, string(manifest.Cell))
	if err != nil {
		return fail(err)
	}
	target, err := foundation.VaultTarget()
	if err != nil {
		return fail(err)
	}
	signed := template.VaultTarget()
	if signed.CompartmentOCID != target.CompartmentID || signed.VaultOCID != target.VaultID || signed.KMSKeyOCID != target.KeyID {
		return fail(errors.New("function Vault target differs from signed regional startup"))
	}
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return fail(err)
	}
	directory, err := unix.Open(bootstrap.MaterialDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	defer unix.Close(directory)
	var info unix.Stat_t
	if unix.Fstat(directory, &info) != nil || info.Uid != uid || info.Gid != gid || info.Mode&0o777 != 0o700 {
		return fail(errors.New("function issuer directory ownership or mode is invalid"))
	}
	files := map[string][]byte{}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	read := func(name string) ([]byte, error) {
		if body, ok := files[name]; ok {
			return body, nil
		}
		body, err := readExactControllerFile(directory, name, uid, gid, 0o600, bootstrap.MaxSecretBytes)
		if err != nil {
			return nil, err
		}
		files[name] = body
		return body, nil
	}
	issuer, err := bootstrapmaterial.LoadStartupControllerIssuer(ctx, startup, read, time.Now().UTC())
	if err != nil {
		return fail(err)
	}
	public, err := functionmaterial.NewStartupPublicTrust(ctx, startup, files["operator.jwt"], files["ca.pem"], cfg.NATS.URL)
	if err != nil {
		issuer.Wipe()
		return fail(err)
	}
	management, bundles, err := automaticVaultClients(factory)
	if err != nil {
		issuer.Wipe()
		return fail(err)
	}
	channel := instancePrincipalChannel(factory.Region(), strings.ToUpper(cfg.NATS.Cell))
	config := functionControllerConfig{Authority: control, Startup: startup, Client: client, Roots: roots, Factory: factory,
		Cell: cfg.NATS.Cell, Environment: manifest.Environment, Channel: channel, Retirement: management,
		Material: functionmaterial.Controller{Authority: control, Conn: runtime.Conn(), Issuer: issuer,
			Vault: management, Versions: management, Target: target,
			Reader: functionmaterial.Reader{Authority: control, Artifacts: artifacts, Roots: roots.current,
				Accounts: accounts, Bundles: bundles, VaultID: target.VaultID, Trust: public}}}
	config.Evidence = func(ctx context.Context, digest string) (io.ReadCloser, error) {
		location, err := channel.get(ctx)
		if err != nil {
			return nil, err
		}
		return releasechannel.ReadContainerEvidence(ctx, location, swarmruntime.FunctionWorkerRole, digest)
	}
	config.Worker = func(ctx context.Context, proof release.VerifiedFunction) (functionWorkerRelease, error) {
		if err := startup.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
			return functionWorkerRelease{}, err
		}
		location, err := channel.get(ctx)
		if err != nil {
			return functionWorkerRelease{}, err
		}
		var failures []error
		for _, architecture := range []string{"arm64", "amd64"} {
			bundle, found, err := releasechannel.ReadContainerBundle(ctx, location, swarmruntime.FunctionWorkerRole, architecture)
			if err != nil || !found {
				failures = append(failures, errors.Join(errors.New("qualified function worker publication unavailable"), err))
				continue
			}
			target := release.ContainerTarget{Cell: string(manifest.Cell), Environment: manifest.Environment, Role: swarmruntime.FunctionWorkerRole, Architecture: architecture}
			allocations, err := currentContainerAllocations(ctx, factory, bundle, roots.current(), target)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			verified, err := release.VerifyContainerCurrent(ctx, bundle, roots.current(), target, time.Now().UTC(), proof.ExpiresAt(), config.Evidence, allocations)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			for _, floor := range verified.Migration().Regions {
				if floor.Cell == string(manifest.Cell) {
					return functionWorkerRelease{Architecture: architecture, Bundle: bundle, Floor: floor}, nil
				}
			}
			return functionWorkerRelease{}, errors.New("function worker migration lacks its signed regional floor")
		}
		return functionWorkerRelease{}, errors.Join(failures...)
	}
	var controller functionController
	config.Probe = func(ctx context.Context, task *api.Task) error {
		if task == nil {
			return errors.New("function readiness requires an actual task")
		}
		registered, err := hosts(ctx)
		if err != nil {
			return err
		}
		labels := task.ServiceAnnotations.Labels
		proof, err := config.Material.Reader.CurrentFunction(ctx, labels[swarmruntime.LabelFunctionTenant], labels[swarmruntime.LabelFunctionID])
		if err != nil {
			return err
		}
		_, err = controller.observeFunctionTask(ctx, proof, task, registered, hosts, membership)
		return err
	}
	controller.config = config
	_, stop, err := startFunctionController(ctx, config)
	if err != nil {
		issuer.Wipe()
		return fail(err)
	}
	return controller, func() { stop(); issuer.Wipe() }, nil
}
