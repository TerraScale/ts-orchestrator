package hostagent

import (
	"context"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"
)

// initializeManifestAuthority runs after receiver ownership is acquired and
// before restoring state or starting any reconciliation effects.
func (t *NatsTransport) initializeManifestAuthority() error {
	if !t.requireManifestAdmission {
		return nil
	}
	data, err := readRegularFileBounded(t.manifestPath, hostmanifest.MaximumManifestBytes)
	if err != nil {
		return err
	}
	manifest, err := hostmanifest.ParseHostManifest(data)
	if err != nil {
		return err
	}
	digest, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil {
		return err
	}
	runtime, admissionErr := t.epochs.AdmittedManifest(digest)
	if admissionErr == nil && runtime {
		return t.lifecycle.HydrateDesired(manifest.Components)
	}
	bootstrap, ok := t.authorizer.(*BootstrapAuthority)
	if !ok {
		return errors.New("hostagent: initial manifest requires a pinned signed bootstrap grant")
	}
	if digest != bootstrap.manifestDigest {
		return errors.New("hostagent: initial manifest differs from signed bootstrap grant")
	}
	now := time.Now().UTC()
	if now.Before(bootstrap.grant.IssuedAt) || !now.Before(bootstrap.grant.ExpiresAt) {
		return errors.New("hostagent: initial bootstrap grant expired")
	}
	if err := t.validateBootstrapInitialState(bootstrap); err != nil {
		return err
	}
	if err := t.epochs.AdmitBootstrap(bootstrap.digest, bootstrap.manifestDigest); err != nil {
		return err
	}
	return t.lifecycle.HydrateDesired(manifest.Components)
}

// reconcileAdmittedManifest serializes manifest admission and effects with
// command execution and runtime handoff. A copied or edited manifest cannot
// obtain install/unit privileges from a valid signature on its binary alone.
func (t *NatsTransport) reconcileAdmittedManifest(ctx context.Context, manifest hostmanifest.HostManifest) error {
	t.commandMutex.Lock()
	defer t.commandMutex.Unlock()
	select {
	case <-t.closing:
		return errors.New("hostagent: receiver closed")
	default:
	}
	digest, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil {
		return err
	}
	runtime, err := t.epochs.AdmittedManifest(digest)
	if err != nil {
		return err
	}
	// The watcher can have read an older file before waiting for this mutex.
	data, err := readRegularFileBounded(t.manifestPath, hostmanifest.MaximumManifestBytes)
	if err != nil {
		return err
	}
	current, err := hostmanifest.ParseHostManifest(data)
	if err != nil {
		return err
	}
	currentDigest, err := hostmanifest.HostManifestSha256(current)
	if err != nil || currentDigest != digest {
		return errors.New("hostagent: desired manifest changed before reconciliation")
	}
	if !runtime {
		bootstrap, ok := t.authorizer.(*BootstrapAuthority)
		if !ok || bootstrap.manifestDigest != digest {
			return errors.New("hostagent: bootstrap manifest authority missing")
		}
		now := time.Now().UTC()
		if now.Before(bootstrap.grant.IssuedAt) || !now.Before(bootstrap.grant.ExpiresAt) {
			return errors.New("hostagent: bootstrap install authority expired")
		}
		if err = t.validateBootstrapInitialState(bootstrap); err != nil {
			return err
		}
		if err = t.epochs.AdmitBootstrap(bootstrap.digest, digest); err != nil {
			return err
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, bootstrap.grant.ExpiresAt)
		defer cancel()
	}
	return t.lifecycle.ApplyDesired(ctx, manifest.Components)
}

func (t *NatsTransport) admitBootstrapCommand(grantDigest, manifestDigest string) error {
	bootstrap, ok := t.authorizer.(*BootstrapAuthority)
	if !ok || bootstrap.digest != grantDigest || bootstrap.manifestDigest != manifestDigest {
		return errors.New("hostagent: bootstrap authority differs from configured grant")
	}
	desiredDigest, err := hostmanifest.HostManifestSha256(hostmanifest.HostManifest{Components: t.lifecycle.Desired()})
	if err != nil || desiredDigest != manifestDigest {
		return errors.New("hostagent: bootstrap desired manifest differs")
	}
	if err := t.validateBootstrapInitialState(bootstrap); err != nil {
		return err
	}
	return t.epochs.AdmitBootstrap(grantDigest, manifestDigest)
}

func (t *NatsTransport) validateBootstrapInitialState(bootstrap *BootstrapAuthority) error {
	for _, spec := range bootstrap.grant.Manifest.Components {
		current, err := CurrentVersion(t.lifecycle.installRoot, spec.Name)
		if err != nil {
			return err
		}
		if current != "" && current != spec.Version {
			return errors.New("hostagent: bootstrap cannot replace an existing release")
		}
	}

	discovered, err := t.lifecycle.discoverManagedComponents()
	if err != nil {
		return err
	}
	for _, name := range discovered {
		allowed := false
		for _, spec := range bootstrap.grant.Manifest.Components {
			allowed = allowed || name == spec.Name
		}
		if !allowed {
			return errors.New("hostagent: initial bootstrap cannot retire an existing component")
		}
	}
	return nil
}
