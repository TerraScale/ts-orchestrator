package hostagent

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"

	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
)

// OpenLocalBootstrap authenticates immutable initial state and prepares its
// installation. handoff receives only the verified component service user and full
// manifest digest, after account creation and before any service can start.
func OpenLocalBootstrap(ctx context.Context, lifecycle *Lifecycle, node string, public, grant []byte, path string, handoff func(context.Context, string, string) error) (session *nodebootstrap.InitialSession[hostmanifest.HostManifest], result error) {
	if ctx == nil || lifecycle == nil {
		return nil, errors.New("hostagent: invalid local bootstrap configuration")
	}
	authority, err := parseBootstrapAuthority(node, public, grant)
	if err != nil {
		return nil, err
	}
	if path != filepath.Join(lifecycle.dataRoot, hostmanifest.TsNodeComponentName, "manifest.json") {
		return nil, errors.New("hostagent: local bootstrap manifest path differs from reserved state")
	}
	journal, err := newCommandJournal(filepath.Join(lifecycle.dataRoot, hostmanifest.TsNodeComponentName, "command-journal"))
	if err != nil {
		return nil, err
	}
	if err = journal.initialize(); err != nil {
		return nil, err
	}
	epochs, err := nodeauthority.NewEpochStore(journal.dir, node)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			_ = epochs.Close()
		}
	}()
	// Only existing journal executor methods are used; no network is created.
	executor := &NatsTransport{commandContext: ctx, authorizer: authority, epochs: epochs, nodeId: NodeId{Value: node}, lifecycle: lifecycle, journal: journal, manifestPath: path, requireManifestAdmission: true, closing: make(chan struct{})}
	if err = executor.initializeManifestAuthority(); err != nil {
		return nil, err
	}
	manifest := hostmanifest.HostManifest{Components: lifecycle.Desired()}
	digest, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil {
		return nil, err
	}
	retired, err := epochs.AdmittedManifest(digest)
	if err != nil {
		return nil, err
	}
	session = &nodebootstrap.InitialSession[hostmanifest.HostManifest]{Manifest: hostmanifest.HostManifest{Components: append([]hostmanifest.ComponentSpec(nil), manifest.Components...)}, ExpiresAt: authority.grant.ExpiresAt, Retired: retired, Close: epochs.Close}
	if retired {
		return session, nil
	}
	ctx, cancel := context.WithDeadline(ctx, authority.grant.ExpiresAt)
	defer cancel()
	if handoff != nil {
		for _, spec := range manifest.Components {
			if spec.Name == "orchestrator" || spec.Name == "terrabase" {
				if err = executor.admitBootstrapCommand(authority.digest, digest); err != nil {
					return nil, err
				}
				if err = lifecycle.users.EnsureUser(ctx, spec.User); err != nil {
					return nil, err
				}
				if err = handoff(ctx, spec.User, digest); err != nil {
					return nil, err
				}
			}
		}
	}
	if err = executor.prepareLifecycleForStartup(); err != nil {
		return nil, err
	}
	if err = executor.reconcileAdmittedManifest(ctx, manifest); err != nil {
		return nil, err
	}
	commands, err := BootstrapCommands(authority.grant)
	if err != nil {
		return nil, err
	}
	session.Execute = func(ctx context.Context, index int) error {
		if index < 0 || index >= len(commands) {
			return errors.New("hostagent: local step outside grant")
		}
		kind := commandKindDrain
		if index%2 == 1 {
			kind = commandKindDeploy
		}
		if kind == commandKindDeploy && !lifecycle.Quiesced(ctx) {
			return errors.New("hostagent: local initial activation is not quiesced")
		}
		return executor.executeLocalBootstrapStep(ctx, authority, commands[index], kind)
	}
	session.Ready = func(ctx context.Context) (bool, error) {
		if err := executor.admitBootstrapCommand(authority.digest, digest); err != nil {
			return false, err
		}
		ready := lifecycle.State() == NodeStateServing
		for _, spec := range manifest.Components {
			current, currentErr := CurrentVersion(lifecycle.installRoot, spec.Name)
			active, activeErr := lifecycle.systemd.UnitActive(ctx, UnitName(spec.Name))
			ready = ready && currentErr == nil && current == spec.Version && activeErr == nil && active
			if ready {
				ready = lifecycle.installer.withVerifiedCurrentTransition(ctx, spec, func(ctx context.Context, _ string) error { return nil }) == nil
			}
		}
		return ready, nil
	}
	return session, nil
}

func (t *NatsTransport) executeLocalBootstrapStep(ctx context.Context, authority *BootstrapAuthority, step BootstrapCommand, kind string) error {
	ctx, cancel := context.WithDeadline(ctx, authority.grant.ExpiresAt)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	// This executor has exclusive lifetime ownership, so no transport can accept
	// a regional epoch concurrently. Still check the durable floor for each step.
	if err := t.admitBootstrapCommand(authority.digest, authority.manifestDigest); err != nil {
		return err
	}
	var commandID string
	var plan *transitionPlan
	if kind == commandKindDrain {
		command, err := decodeDrainCommand(step.Command)
		if err != nil {
			return err
		}
		commandID = command.CommandId
	} else {
		command, err := decodeDeployCommand(step.Command)
		if err != nil {
			return err
		}
		commandID = command.CommandId
	}
	record, found, err := t.journal.find(kind, commandID, step.Command)
	if err != nil {
		return err
	}
	if found && record.State == commandJournalDone {
		return nil
	}
	if !found {
		if kind == commandKindDeploy {
			command, _ := decodeDeployCommand(step.Command)
			prepared, err := t.lifecycle.prepareDeploy(ctx, command.Component, command.Version)
			if err != nil {
				return err
			}
			plan = &prepared
		}
		record, err = t.journal.begin(kind, commandID, step.Command, plan)
		if err != nil {
			return err
		}
	}
	response, err := t.executeJournalRecord(ctx, record)
	if err != nil {
		return err
	}
	if kind == commandKindDeploy {
		var receipt DeployReceipt
		if json.Unmarshal(response, &receipt) != nil || !receipt.Accepted {
			return errors.New("hostagent: local initial deploy has not completed")
		}
	} else {
		var receipt DrainReceipt
		command, _ := decodeDrainCommand(step.Command)
		if json.Unmarshal(response, &receipt) != nil || receipt.Draining != command.Drain || command.Drain && !receipt.Quiesced {
			return errors.New("hostagent: local initial drain has not completed")
		}
	}
	return t.journal.complete(record, response)
}
