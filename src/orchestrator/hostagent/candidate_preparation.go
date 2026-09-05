package hostagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func candidateComponent(manifest hostmanifest.HostManifest) (hostmanifest.ComponentSpec, transitiongrant.Config, bool, error) {
	for _, spec := range manifest.Components {
		c, found, e := transitiongrant.ComponentConfig(spec)
		if e != nil {
			return spec, c, true, e
		}
		if found {
			return spec, c, true, nil
		}
	}
	return hostmanifest.ComponentSpec{}, transitiongrant.Config{}, false, nil
}
func readCandidateOwnerFile(path string) ([]byte, error) {
	if !hostmanifest.SafeAbsolutePath(path) {
		return nil, errors.New("hostagent: invalid preparation proof path")
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil {
			return nil, e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || (info.Mode().Perm()&0022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return nil, errors.New("hostagent: preparation proof ancestry is not host-owned")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != 0 || st.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Size() > transitiongrant.MaximumBytes {
		return nil, errors.New("hostagent: unsafe preparation proof")
	}
	return io.ReadAll(io.LimitReader(f, transitiongrant.MaximumBytes+1))
}
func (t *NatsTransport) initializeCandidatePreparation(manifest hostmanifest.HostManifest, digest string) (bool, error) {
	spec, c, found, e := candidateComponent(manifest)
	if e != nil || !found {
		return found, e
	}
	bootstrap, ok := t.authorizer.(*BootstrapAuthority)
	if !ok || bootstrap.manifestDigest != digest || bootstrap.grant.NodeID != c.NodeID {
		return true, errors.New("hostagent: candidate requires original host bootstrap proof")
	}
	if err := t.validateBootstrapInitialState(bootstrap); err != nil {
		return true, err
	}
	if err := validateCandidateCurrent(t.lifecycle, spec); err != nil {
		return true, err
	}
	if runtime, err := t.epochs.AdmittedManifest(digest); err == nil && runtime {
		return true, t.lifecycle.HydrateDesired(nil)
	}
	if _, e = t.epochs.ResumeCandidatePreparation(t.context(), c, bootstrap.digest, digest); e == nil {
		return true, t.lifecycle.HydrateDesired(manifest.Components)
	} else if !os.IsNotExist(e) {
		return true, e
	}
	now := time.Now()
	if now.Before(bootstrap.grant.IssuedAt) || !now.Before(bootstrap.grant.ExpiresAt) {
		return true, errors.New("hostagent: first candidate admission requires live initial grant")
	}
	public, e := readCandidateOwnerFile(c.GrantPublicKeyFile)
	if e != nil {
		return true, e
	}
	// BootstrapAuthority retains only its verified key fingerprint. Reverify the
	// separate preparation signature and compare this immutable owner identity.
	signed, e := readCandidateOwnerFile(c.GrantFile)
	if e != nil {
		return true, e
	}
	v, e := transitiongrant.VerifyGrant(public, signed)
	if e != nil {
		return true, e
	}
	if v.OwnerKeyID != bootstrap.verifier.OwnerKeyID() {
		return true, errors.New("hostagent: preparation signer differs from bootstrap owner")
	}
	if e = bootstrap.verifier.CheckAt(now); e != nil {
		return true, e
	}
	if e = t.epochs.AdmitBootstrap(bootstrap.digest, digest); e != nil {
		return true, e
	}
	if _, e = t.epochs.AdmitCandidatePreparation(t.context(), public, signed, c, bootstrap.digest, digest); e != nil {
		return true, e
	}
	return true, t.lifecycle.HydrateDesired(manifest.Components)
}

// ResumeLocalCandidatePreparation runs only the pinned inert candidate after
// its original initial grant expires. It cannot execute other pending commands
// or reconcile unrelated components. A still-live initial grant uses the
// ordinary local bootstrap executor instead.
func ResumeLocalCandidatePreparation(ctx context.Context, lifecycle *Lifecycle, node string, public, signed []byte, manifestPath string) (bool, error) {
	if ctx == nil || lifecycle == nil {
		return false, errors.New("hostagent: candidate recovery context and lifecycle required")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	authority, e := parseBootstrapAuthority(node, public, signed)
	if e != nil {
		return false, e
	}
	spec, c, found, e := candidateComponent(authority.grant.Manifest)
	if e != nil || !found {
		return found, e
	}
	if time.Now().Before(authority.grant.ExpiresAt) {
		return false, nil
	}
	if manifestPath != filepath.Join(lifecycle.dataRoot, hostmanifest.TsNodeComponentName, "manifest.json") {
		return true, errors.New("hostagent: candidate manifest path differs")
	}
	journal, e := newCommandJournal(filepath.Join(lifecycle.dataRoot, hostmanifest.TsNodeComponentName, "command-journal"))
	if e != nil {
		return true, e
	}
	if e = journal.initialize(); e != nil {
		return true, e
	}
	epochs, e := nodeauthority.NewEpochStore(journal.dir, node)
	if e != nil {
		return true, e
	}
	defer epochs.Close()
	raw, e := readRegularFileBounded(manifestPath, hostmanifest.MaximumManifestBytes)
	if e != nil {
		return true, e
	}
	expected, e := hostmanifest.CanonicalHostManifestJSON(authority.grant.Manifest)
	if e != nil || !bytes.Equal(raw, expected) {
		return true, errors.New("hostagent: candidate restart manifest differs")
	}
	if runtime, err := epochs.AdmittedManifest(authority.manifestDigest); err == nil && runtime {
		return true, nil
	}
	receipt, e := epochs.ResumeCandidatePreparation(ctx, c, authority.digest, authority.manifestDigest)
	if e != nil {
		return true, e
	}
	bounded, cancel := context.WithDeadline(ctx, receipt.ExpiresAt)
	defer cancel()
	if e = lifecycle.HydrateDesired([]hostmanifest.ComponentSpec{spec}); e != nil {
		return true, e
	}
	return true, resumeCandidateActivation(bounded, lifecycle, journal, spec, receipt)
}

func validateCandidateCurrent(l *Lifecycle, spec hostmanifest.ComponentSpec) error {
	current, e := CurrentVersion(l.installRoot, spec.Name)
	if e != nil {
		return e
	}
	if current != "" {
		if current != spec.Version {
			return errors.New("hostagent: candidate cannot activate a prior release")
		}
		return verifyExpectedLaunch(VersionDir(l.installRoot, spec.Name, current), spec)
	}
	return nil
}
func resumeCandidateActivation(ctx context.Context, l *Lifecycle, journal *commandJournal, spec hostmanifest.ComponentSpec, receipt nodeauthority.CandidatePreparationReceipt) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if e := validateCandidateCurrent(l, spec); e != nil {
		return e
	}
	if e := l.ensureComponentLocked(ctx, spec); e != nil {
		return e
	}
	if e := verifyExpectedLaunch(VersionDir(l.installRoot, spec.Name, spec.Version), spec); e != nil {
		return e
	}
	id := "prepare-" + receipt.GrantSHA256[:24]
	command := DeployCommand{CommandId: id, Component: spec.Name, Version: spec.Version}
	request, e := json.Marshal(command)
	if e != nil {
		return e
	}
	record, found, e := journal.find(commandKindDeploy, id, request)
	if e != nil {
		return e
	}
	plan := transitionPlan{Spec: spec, ExpectedSha256: spec.Sha256}
	if !found {
		record, e = journal.begin(commandKindDeploy, id, request, &plan)
		if e != nil {
			return e
		}
	}
	if record.State == commandJournalPending {
		if record.Plan == nil || *record.Plan != plan {
			return errors.New("hostagent: candidate activation journal plan differs")
		}
		if e = l.applyTransitionLocked(ctx, plan); e != nil {
			return e
		}
		response, _ := json.Marshal(struct {
			CommandID string `json:"commandId"`
			Phase     string `json:"phase"`
		}{id, "candidate-activated"})
		if e = journal.complete(record, response); e != nil {
			return e
		}
	}
	current, e := CurrentVersion(l.installRoot, spec.Name)
	if e != nil {
		return e
	}
	if current != spec.Version {
		return errors.New("hostagent: completed candidate activation has no matching release")
	}
	active, e := l.systemd.UnitActive(ctx, UnitName(spec.Name))
	if e != nil {
		return e
	}
	if !active {
		return l.installer.withVerifiedCurrentTransition(ctx, spec, func(ctx context.Context, _ string) error { return l.systemd.StartUnit(ctx, UnitName(spec.Name)) })
	}
	return nil
}

// Keep full signed desired inventory for facts and manifest CAS, but never
// replay its broad drain/release effects using an expired initial grant.
func (t *NatsTransport) resumeExpiredCandidateStartup(ctx context.Context) (bool, error) {
	bootstrap, ok := t.authorizer.(*BootstrapAuthority)
	if !ok {
		return false, nil
	}
	// A later ordinary manifest uses its own persisted runtime admission.
	manifest := hostmanifest.HostManifest{Components: t.lifecycle.Desired()}
	spec, c, candidate, err := candidateComponent(manifest)
	if err != nil || !candidate {
		return candidate, err
	}
	digest, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil || digest != bootstrap.manifestDigest {
		return true, errors.New("hostagent: startup candidate manifest differs")
	}
	runtime, err := t.epochs.AdmittedManifest(digest)
	if err != nil {
		return true, err
	}
	if runtime {
		return true, nil
	}
	if time.Now().Before(bootstrap.grant.ExpiresAt) {
		bounded, cancel := context.WithDeadline(ctx, bootstrap.grant.ExpiresAt)
		defer cancel()
		return true, t.restoreRecordedDrain(bounded)
	}
	receipt, err := t.epochs.ResumeCandidatePreparation(ctx, c, bootstrap.digest, digest)
	if err != nil {
		return true, err
	}
	bounded, cancel := context.WithDeadline(ctx, receipt.ExpiresAt)
	defer cancel()
	return true, resumeCandidateActivation(bounded, t.lifecycle, t.journal, spec, receipt)
}
