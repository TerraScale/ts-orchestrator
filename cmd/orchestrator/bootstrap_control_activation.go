package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/nats-io/nats.go"
	"io"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type bootstrapControlActivation struct {
	HostID              string `json:"hostId"`
	GrantFile           string `json:"grantFile"`
	OwnerPublicKeyFile  string `json:"ownerPublicKeyFile"`
	OwnerSigningKeyFile string `json:"ownerSigningKeyFile"`
}
type loadedControlActivation struct {
	grant      hostagent.BootstrapGrant
	signed     []byte
	signer     *security.CommandSignatureSigner
	ownerKeyID string
}

func loadControlActivation(input bootstrapControlActivation) (loadedControlActivation, error) {
	var result loadedControlActivation
	signed, err := readBootstrapControlFile(input.GrantFile, true, 2<<20)
	if err != nil {
		return result, err
	}
	public, err := readBootstrapControlFile(input.OwnerPublicKeyFile, false, 64<<10)
	if err != nil {
		return result, err
	}
	grant, err := hostagent.VerifyBootstrapGrant(input.HostID, public, signed)
	if err != nil {
		return result, err
	}
	block, _ := pem.Decode(public)
	if block == nil {
		return result, errors.New("control: missing activation public key")
	}
	ownerDigest := sha256.Sum256(block.Bytes)
	var signer *security.CommandSignatureSigner
	if input.OwnerSigningKeyFile != "" {
		if _, err := readBootstrapControlFile(input.OwnerSigningKeyFile, true, 64<<10); err != nil {
			return result, err
		}
		signer, err = security.LoadCommandSignatureSignerPEM(input.OwnerSigningKeyFile)
		if err != nil {
			return result, err
		}
		block, _ := pem.Decode(public)
		if block == nil {
			return result, errors.New("control: missing activation public key")
		}
		digest := sha256.Sum256(block.Bytes)
		if signer.PublicKeyID() != hex.EncodeToString(digest[:]) {
			return result, errors.New("control: activation signer differs from owner grant")
		}
	}
	return loadedControlActivation{grant: grant, signed: signed, signer: signer, ownerKeyID: hex.EncodeToString(ownerDigest[:])}, nil
}

type bootstrapActivationRuntime struct {
	*bootstrap.NATSControlRuntime
	plans       []bootstrap.ControlRuntimeActionPlan
	grants      map[string]loadedControlActivation
	clients     map[string]*hostcontrol.Client
	connections map[string]*nats.Conn
	memberHosts map[string]string
	hostRegions map[string]string
	hostStores  map[string]string
}

func (r *bootstrapActivationRuntime) Execute(ctx context.Context, request bootstrap.ControlActionRequest) (bootstrap.ControlRuntimeEvidence, error) {
	for _, plan := range r.plans {
		if plan.Kind != request.Action.Kind || plan.Region != request.Action.Region || plan.ExpectedEpoch != request.Action.ExpectedEpoch || plan.TargetEpoch != request.Action.TargetEpoch {
			continue
		}
		for _, handoff := range plan.Handoffs {
			host := r.memberHosts[handoff.MemberID]
			activation, ok := r.grants[host]
			if !ok {
				continue
			}
			desired, err := hostmanifest.HostManifestSha256(handoff.Manifest)
			if err != nil {
				return bootstrap.ControlRuntimeEvidence{}, err
			}
			allowed, err := hostmanifest.HostManifestSha256(activation.grant.Manifest)
			if err != nil {
				return bootstrap.ControlRuntimeEvidence{}, err
			}
			if desired != allowed {
				continue
			}
			if host != activation.grant.NodeID {
				return bootstrap.ControlRuntimeEvidence{}, errors.New("control: activation host mismatch")
			}
			region := r.hostRegions[host]
			if err := sendControlActivation(ctx, r.connections[r.hostStores[region]], r.clients[region], activation); err != nil {
				return bootstrap.ControlRuntimeEvidence{}, err
			}
		}
	}
	return r.NATSControlRuntime.Execute(ctx, request)
}
func sendControlActivation(ctx context.Context, connection *nats.Conn, client *hostcontrol.Client, activation loadedControlActivation) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	grant := activation.grant
	desired, err := hostmanifest.HostManifestSha256(grant.Manifest)
	if err != nil {
		return err
	}
	report, err := client.Status(ctx, grant.NodeID)
	if err != nil {
		return err
	}
	if activationReady(report, grant, true) {
		return nil
	}
	if activation.signer == nil {
		return errors.New("control: offline owner-grant activation has not produced running services")
	}
	if report.Facts.ManifestSha256 != desired {
		return errors.New("control: initial grant manifest is not installed on host")
	}
	if err := waitControlActivation(ctx, client, grant, false, false); err != nil {
		return err
	}
	commands, err := hostagent.BootstrapCommands(grant)
	if err != nil {
		return err
	}
	node, _ := hostagent.NewNodeId(grant.NodeID)
	drainSubject, _ := hostagent.NodeDrainSubject(node)
	for index := 0; index < len(commands); index++ {
		step := commands[index]
		now := time.Now().UTC()
		expires := now.Add(30 * time.Second)
		if expires.After(grant.ExpiresAt) {
			expires = grant.ExpiresAt
		}
		if now.Before(grant.IssuedAt) || !expires.After(now) {
			return errors.New("control: initial grant is outside its admitted lifetime")
		}
		// Status validates the authenticated connection again before each finite
		// mutation and binds the current host to the admitted manifest.
		status, err := client.Status(ctx, grant.NodeID)
		if err != nil {
			return err
		}
		if status.Facts.ManifestSha256 != desired {
			return errors.New("control: bootstrap manifest changed")
		}
		if step.Subject == drainSubject && index+1 < len(commands) {
			var drain hostagent.DrainCommand
			var deploy hostagent.DeployCommand
			if json.Unmarshal(step.Command, &drain) == nil && drain.Drain && json.Unmarshal(commands[index+1].Command, &deploy) == nil {
				activated := false
				for _, fact := range status.Facts.Components {
					if fact.Name == deploy.Component && fact.Version == deploy.Version && fact.Installed {
						activated = true
					}
				}
				if activated {
					index++
					continue
				}
			}
		}
		wire, err := hostagent.SignBootstrapCommand(activation.signer, activation.signed, step.Subject, step.Command, now, expires)
		if err != nil {
			return err
		}
		bounded, stop := context.WithTimeout(ctx, 30*time.Second)
		reply, err := connection.RequestWithContext(bounded, step.Subject, wire)
		stop()
		if err != nil {
			return err
		}
		if step.Subject == drainSubject {
			var command hostagent.DrainCommand
			var receipt hostagent.DrainReceipt
			if json.Unmarshal(step.Command, &command) != nil || decodeControlActivationReply(reply.Data, &receipt) != nil {
				return errors.New("control: invalid bootstrap drain reply")
			}
			if _, err := hostagent.NewDrainReceipt(receipt.CommandId, receipt.NodeId, receipt.Draining, receipt.Quiesced, receipt.Detail); err != nil {
				return err
			}
			if receipt.CommandId != command.CommandId || receipt.NodeId != grant.NodeID || receipt.Draining != command.Drain {
				return errors.New("control: bootstrap drain receipt mismatch")
			}
			if command.Drain {
				if err := waitControlActivation(ctx, client, grant, false, true); err != nil {
					return err
				}
			}
		} else {
			var command hostagent.DeployCommand
			var receipt hostagent.DeployReceipt
			if json.Unmarshal(step.Command, &command) != nil || decodeControlActivationReply(reply.Data, &receipt) != nil {
				return errors.New("control: invalid bootstrap deploy reply")
			}
			if _, err := hostagent.NewDeployReceipt(receipt.CommandId, receipt.NodeId, receipt.Accepted, receipt.Current, receipt.Detail); err != nil {
				return err
			}
			if !receipt.Accepted || receipt.CommandId != command.CommandId || receipt.NodeId != grant.NodeID || receipt.Current != command.Version {
				return errors.New("control: bootstrap deploy receipt mismatch")
			}
		}
	}
	return waitControlActivation(ctx, client, grant, true, false)
}
func decodeControlActivationReply(raw []byte, value any) error {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("control: invalid activation reply size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("control: invalid activation reply")
	}
	return nil
}
func activationReady(report hostagent.NodeStatusReport, grant hostagent.BootstrapGrant, running bool) bool {
	desired, err := hostmanifest.HostManifestSha256(grant.Manifest)
	if err != nil || report.Facts.ClockUnhealthy || report.Facts.ManifestSha256 != desired {
		return false
	}
	for _, component := range grant.Manifest.Components {
		found := false
		for _, fact := range report.Facts.Components {
			if fact.Name == component.Name && fact.Installed && fact.Desired == component.Version && (!running || (fact.Version == component.Version && fact.UnitActive)) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func waitControlActivation(ctx context.Context, client *hostcontrol.Client, grant hostagent.BootstrapGrant, running, quiesced bool) error {
	for {
		report, err := client.Status(ctx, grant.NodeID)
		if err != nil {
			return err
		}
		if activationReady(report, grant, running) && (!quiesced || report.Quiesced) {
			return nil
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
