package swarmruntime

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/moby/swarmkit/v2/agent/exec"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const swarmStateDirectory = "/var/lib/terrascale-orchestrator-host/swarm"
const swarmManagerPort = "2377"

// ReadAcceptedManagerAdmission allows deferred material providers to be bound
// before startup. Material still requires its own current recipient authority.
func ReadAcceptedManagerAdmission(ctx context.Context, reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity) (Admission, error) {
	authority, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return Admission{}, err
	}
	return managerAdmission(authority.Identity()), nil
}

func managerAdmission(identity bootstrapstart.RuntimeIdentity) Admission {
	return Admission{Region: identity.OCIRegion, HostID: identity.Slot, InstanceID: identity.InstanceID, FounderID: identity.SeedSlot, Role: "manager"}
}

type bootstrapScope struct {
	DeploymentID, ClusterID, Environment, Cell, OCIRegion, SeedSlot string
}

type bootstrapJoinMaterial struct {
	Version                                                   uint8
	Scope                                                     bootstrapScope
	ManagerAddress, SwarmID, CAPEM, ManagerToken, WorkerToken string
}

// StartAcceptedNode starts only an exact currently authorized controller slot.
// accepted must come from the ordinary live Gate, not local restart checks alone.
// Vault clients use the admitted instance principal; foundation discovery is the
// concrete signed-grant reader and never a serving-health discovery fallback.
func StartAcceptedNode(ctx context.Context, reader *bootstrapstart.CurrentFounderAuthorityReader,
	accepted bootstrapstart.AcceptedIdentity, foundations region.FoundationResolver,
	vault vaultsecret.VaultClient, bundles vaultsecret.BundleClient, executor exec.Executor,
) (*Node, error) {
	authority, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	identity := authority.Identity()
	foundation, err := foundations.Resolve(ctx, strings.ToUpper(identity.Cell))
	if err != nil {
		return nil, err
	}
	if foundation.OCIRegion != authority.Anchor().Anchor().OCIRegion {
		return nil, errors.New("SwarmKit foundation differs from signed regional authority")
	}
	target, err := foundation.VaultTarget()
	if err != nil {
		return nil, err
	}
	if vault == nil || bundles == nil {
		return nil, errors.New("SwarmKit bootstrap requires the reconciled regional Vault target and clients")
	}
	refresh := func(ctx context.Context) error {
		current, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
		if err != nil {
			return err
		}
		if current.Identity() != identity {
			return errors.New("SwarmKit runtime authority changed during startup")
		}
		fresh, err := foundations.Resolve(ctx, strings.ToUpper(identity.Cell))
		if err != nil {
			return err
		}
		freshTarget, err := fresh.VaultTarget()
		if err != nil {
			return err
		}
		if fresh.OCIRegion != foundation.OCIRegion || freshTarget != target {
			return errors.New("SwarmKit regional Vault foundation changed during startup")
		}
		return nil
	}
	launch, err := bootstrapstart.LoadAcceptedHostLaunchMaterial(accepted)
	if err != nil {
		return nil, err
	}
	bundle, err := hostenroll.ParsePublicBundle(launch.HostEnrollment)
	if err != nil {
		return nil, err
	}
	public, err := bundle.ResponsePublicKey()
	if err != nil {
		return nil, err
	}
	observer, err := reader.RuntimeInstanceObserver(ctx, accepted)
	if err != nil {
		return nil, err
	}
	homeIAM, err := region.NewRuntimeHomeIAMAuthority(ctx, reader, accepted, foundations)
	if err != nil {
		return nil, err
	}
	n, err := startAcceptedNodeAt(ctx, swarmStateDirectory, identity, target, vault, bundles, executor, refresh)
	if err != nil {
		return nil, err
	}
	n.workerAuthority = &workerAuthority{identity: identity, public: public, target: target, vault: vault, bundles: bundles, observer: observer, refresh: refresh, homeIAM: homeIAM, foundations: foundations}
	return n, nil
}

func startAcceptedNodeAt(ctx context.Context, stateDir string, identity bootstrapstart.RuntimeIdentity,
	target vaultsecret.Target, vault vaultsecret.VaultClient, bundles vaultsecret.BundleClient,
	executor exec.Executor, refresh func(context.Context) error,
) (*Node, error) {
	if err := refresh(ctx); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	lock := flock.New(filepath.Join(stateDir, "bootstrap.lock"))
	locked, err := lock.TryLock()
	if err != nil || !locked {
		return nil, errors.New("SwarmKit bootstrap state is already in use")
	}
	defer lock.Unlock()
	if err := bindBootstrapScope(stateDir, identity); err != nil {
		return nil, err
	}
	scope := bootstrapScope{DeploymentID: identity.DeploymentID, ClusterID: identity.ClusterID,
		Environment: identity.Environment, Cell: identity.Cell, OCIRegion: identity.OCIRegion, SeedSlot: identity.SeedSlot}
	name := vaultsecret.Name(strings.ToLower(identity.Cell)+"-"+strings.ToLower(identity.ClusterID), "TS_ORCHESTRATOR_SWARM_JOIN")
	wire, readErr := vaultsecret.Read(ctx, bundles, target.VaultID, name)
	var published bootstrapJoinMaterial
	if readErr == nil {
		if err := json.Unmarshal([]byte(wire), &published, json.RejectUnknownMembers(true)); err != nil ||
			published.Version != 1 || published.Scope != scope || published.SwarmID == "" || published.CAPEM == "" ||
			published.ManagerAddress != net.JoinHostPort(identity.SeedPrivateIP, swarmManagerPort) {
			return nil, errors.New("Vault SwarmKit join material differs from signed regional scope")
		}
		for _, token := range []string{published.ManagerToken, published.WorkerToken} {
			if _, err := ca.ParseJoinToken(token); err != nil {
				return nil, errors.New("Vault SwarmKit join material has an invalid upstream token")
			}
		}
	} else if !vaultsecret.Absent(readErr) {
		return nil, readErr
	}
	admission := managerAdmission(identity)
	nodeDir := filepath.Join(stateDir, "node")
	if identity.Slot == identity.SeedSlot {
		if readErr == nil {
			if _, err := os.Stat(filepath.Join(nodeDir, "certificates", "swarm-node.crt")); err != nil {
				return nil, errors.New("regional SwarmKit cluster already exists; restore founder state")
			}
		}
	} else {
		if readErr != nil {
			return nil, errors.New("regional SwarmKit founder has not published join material")
		}
		admission.ManagerAddress, admission.JoinToken = published.ManagerAddress, published.ManagerToken
	}
	if err := refresh(ctx); err != nil {
		return nil, err
	}
	n, err := StartNode(ctx, NodeConfig{StateDir: nodeDir,
		ListenAddress:    net.JoinHostPort(identity.PrivateIP, swarmManagerPort),
		AdvertiseAddress: net.JoinHostPort(identity.PrivateIP, swarmManagerPort), Admission: admission}, executor)
	if err != nil {
		return nil, err
	}
	var startupErr error
	defer func() {
		if startupErr != nil {
			stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = n.Stop(stopCtx)
		}
	}()
	client, err := n.ControlClient(ctx)
	if err != nil {
		startupErr = err
		return nil, err
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		startupErr = errors.New("SwarmKit did not expose one regional cluster")
		return nil, startupErr
	}
	cluster := clusters.Clusters[0]
	actual := bootstrapJoinMaterial{Version: 1, Scope: scope,
		ManagerAddress: net.JoinHostPort(identity.SeedPrivateIP, swarmManagerPort),
		SwarmID:        cluster.ID, CAPEM: string(cluster.RootCA.CACert),
		ManagerToken: cluster.RootCA.JoinTokens.Manager, WorkerToken: cluster.RootCA.JoinTokens.Worker}
	if readErr == nil && published != actual {
		startupErr = errors.New("running SwarmKit cluster differs from create-once Vault material; restore its matching state")
		return nil, startupErr
	}
	if err := refresh(ctx); err != nil {
		startupErr = err
		return nil, err
	}
	if identity.Slot == identity.SeedSlot {
		stored, err := vaultsecret.Ensure(ctx, vault, target, name, "Regional SwarmKit upstream join material", func(ctx context.Context) (string, error) {
			if err := refresh(ctx); err != nil {
				return "", err
			}
			data, err := json.Marshal(actual)
			return string(data), err
		})
		if err != nil {
			startupErr = err
			return nil, err
		}
		readback, err := vaultsecret.ReadBack(ctx, bundles, target.VaultID, name, stored.Created || stored.Provisioning)
		var saved bootstrapJoinMaterial
		if err != nil || json.Unmarshal([]byte(readback), &saved, json.RejectUnknownMembers(true)) != nil || saved != actual {
			startupErr = errors.New("Vault SwarmKit create-once readback differs from running cluster")
			return nil, startupErr
		}
	}
	if err := refresh(ctx); err != nil {
		startupErr = err
		return nil, err
	}
	if _, err := AdmitNode(ctx, client, n.ID(), admission); err != nil {
		startupErr = err
		return nil, err
	}
	return n, nil
}

func bindBootstrapScope(directory string, identity bootstrapstart.RuntimeIdentity) error {
	path := filepath.Join(directory, "scope.json")
	data, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	stored, err := os.ReadFile(path)
	if err == nil {
		var previous bootstrapstart.RuntimeIdentity
		if json.Unmarshal(stored, &previous, json.RejectUnknownMembers(true)) != nil || previous != identity {
			return errors.New("SwarmKit persistent signed cluster scope differs from admitted identity")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(filepath.Join(directory, "node")); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("SwarmKit state exists without its signed scope binding; restore matching state")
	}
	file, err := os.CreateTemp(directory, ".scope-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
