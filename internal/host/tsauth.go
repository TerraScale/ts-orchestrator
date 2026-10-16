package host

import (
	"context"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
)

// ts-auth replicas are generic native workloads of role "ts-auth" on a host
// configured with a ts-auth root. Like a C# TerraBase member, the host
// prepares the replica's directory, adds the Vault secrets its profile names
// to its environment, reports it running only once /healthz and /readyz
// answer, and stops it with SIGTERM before the cgroup is killed.

// tsAuthDrain bounds a replica's graceful shutdown (ASP.NET Core drains for
// 30 s); the host unit's TimeoutStopSec leaves room for it.
const tsAuthDrain = 45 * time.Second

// tsAuthReplica reports whether this host launches d as a ts-auth replica.
func (a *Agent) tsAuthReplica(d Desired) bool {
	return a.cfg.TSAuthRoot != "" && d.Role == tsauth.Role && d.ManagedMember == nil && !d.Withdrawn
}

// tsAuthMisplaced reports a ts-auth desired on a host without a ts-auth root:
// launched generically it would run without its bundle directory and report
// running without a probe, so the host refuses it.
func (a *Agent) tsAuthMisplaced(d Desired) bool {
	return a.cfg.TSAuthRoot == "" && d.Role == tsauth.Role && d.ManagedMember == nil && !d.Withdrawn
}

// prepareTSAuth creates the replica's directories and returns its launch
// environment: the signed profile, the secrets read from the Vault and the
// host-owned settings. The secrets never enter desired state, reports or logs.
func (a *Agent) prepareTSAuth(d Desired, secrets map[string]string) (map[string]string, error) {
	if err := tsauth.ValidateProfile(d.Cell, d.Args, d.Env, d.Secrets); err != nil {
		return nil, err
	}
	if err := tsauth.ValidateSecrets(secrets); err != nil {
		return nil, err
	}
	root, identity := a.cfg.TSAuthRoot, a.cfg.WorkloadIdentity
	// Recheck the ancestors right before the privileged effects below.
	if err := validateWorkloadRoot("ts-auth", root, identity, a.cfg.InstallRoot, a.cfg.StateRoot, a.cfg.TerraBaseRoot); err != nil {
		return nil, err
	}
	layout := tsauth.Layout(root)
	if err := ensureOwnedDir(root, os.Geteuid(), int(identity.GID), 0o750); err != nil {
		return nil, err
	}
	if err := ensureOwnedDir(layout.Bundle(), int(identity.UID), int(identity.GID), 0o700); err != nil {
		return nil, err
	}
	return layout.Env(d.Env, secrets, a.tsAuthPort()), nil
}

// tsAuthRunningReport reports a launched replica running only while it is
// alive and ready, and starting with the probe error otherwise.
func (a *Agent) tsAuthRunningReport(ctx context.Context, d Desired) Report {
	if err := tsauth.Probe(ctx, a.tsAuthPort()); err != nil {
		return a.reportFor(d, "starting", err)
	}
	return a.reportFor(d, "running", nil)
}

func (a *Agent) tsAuthPort() int {
	if a.cfg.TSAuthPort != 0 {
		return a.cfg.TSAuthPort
	}
	return tsauth.Port
}
