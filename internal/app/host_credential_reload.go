package app

import (
	"crypto/ed25519"
	"errors"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

// hostCredentialReloader lets a running host agent present credentials that
// host-setup renewed after start. Renewal keeps the identity, NATS seed and TLS
// key and only re-issues the JWT and certificate into a new directory, so the
// agent must never be restarted for it: a restart stops every supervised
// TerraBase member. Any other host.json change is refused here and only takes
// effect on the next deliberate restart.
func hostCredentialReloader(path string, running Config, identity ed25519.PrivateKey) func() (natscell.ClientMaterial, error) {
	return func() (natscell.ClientMaterial, error) {
		reloaded, err := LoadConfig(path)
		if err != nil {
			return natscell.ClientMaterial{}, err
		}
		if err := sameHostIdentityConfig(running, reloaded); err != nil {
			return natscell.ClientMaterial{}, err
		}
		key, err := readPrivateKey(reloaded.Host.IdentityKeyFile)
		if err != nil {
			return natscell.ClientMaterial{}, err
		}
		if !identity.Equal(key) {
			return natscell.ClientMaterial{}, errors.New("reloaded host identity key differs from the running agent")
		}
		return natscell.ClientMaterial{CredentialsFile: reloaded.NATS.CredentialsFile, TLS: reloaded.NATS.TLS}, nil
	}
}

// sameHostIdentityConfig accepts only credential path changes.
func sameHostIdentityConfig(running, reloaded Config) error {
	left, right := running.NATS, reloaded.NATS
	if left.Cell != right.Cell || left.Instance != right.Instance || left.Replicas != right.Replicas ||
		left.Lab != right.Lab || left.URL != right.URL || left.NKeySeedFile != right.NKeySeedFile ||
		left.Embedded != nil || right.Embedded != nil {
		return errors.New("reloaded host NATS configuration changes more than credentials")
	}
	hostLeft, hostRight := running.Host, reloaded.Host
	if !slices.Equal(hostLeft.Roles, hostRight.Roles) || hostLeft.Node != hostRight.Node ||
		hostLeft.Environment != hostRight.Environment || hostLeft.ControllerPublicKey != hostRight.ControllerPublicKey ||
		hostLeft.InstallRoot != hostRight.InstallRoot || hostLeft.StateRoot != hostRight.StateRoot ||
		hostLeft.ManagedRuntimeRoot != hostRight.ManagedRuntimeRoot || hostLeft.WorkloadUID != hostRight.WorkloadUID ||
		hostLeft.WorkloadGID != hostRight.WorkloadGID || hostLeft.PollMillis != hostRight.PollMillis ||
		hostLeft.SessionTrace != hostRight.SessionTrace || hostLeft.LoadTelemetrySeconds != hostRight.LoadTelemetrySeconds {
		return errors.New("reloaded host configuration changes more than credentials")
	}
	return nil
}
