//go:build linux

package host

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

type volumeInitQuery struct {
	Role                 string `json:"role"`
	DesiredRevision      uint64 `json:"desired_revision"`
	RegistrationRevision uint64 `json:"registration_revision"`
}

// volumeInitPermit is transported inside a controller-signed host RPC
// response. The helper verifies the envelope, session, IMDS and exact device
// before acting; possession of this struct alone grants no authority.
type volumeInitPermit struct {
	Desired              Desired               `json:"desired"`
	Registration         Registration          `json:"registration"`
	DesiredRevision      uint64                `json:"desired_revision"`
	RegistrationRevision uint64                `json:"registration_revision"`
	SessionID            string                `json:"session_id"`
	Observation          VolumeInitObservation `json:"observation"`
	expiresAt            time.Time
}

func (c *Controller) serveVolumeInit(ctx context.Context, req request, registration Registration, currentSession session) (any, error) {
	ctx = authority.WithActiveWorkloadEffectContext(ctx)
	if c.volumeInspector == nil || c.managedVerifier == nil || c.managedEffectGate == nil || registration.ManagedPlacement == nil ||
		registration.ManagedOCI == nil || registration.ManagedMember == nil {
		return nil, errors.New("managed volume inspection is unavailable")
	}
	var query volumeInitQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if query.DesiredRevision == 0 || query.RegistrationRevision == 0 || !slices.Contains(registration.Roles, query.Role) {
		return nil, errors.New("managed volume query has no current role or revision")
	}
	scope := authority.WorkloadScope{DatabaseID: registration.ManagedPlacement.DatabaseID,
		PartitionID: registration.ManagedPlacement.PartitionID}
	authorityEpoch := c.authorityEpoch()
	release, err := c.managedEffectGate(ctx, authorityEpoch, scope)
	if err != nil {
		return nil, err
	}
	defer release()
	currentRegistration, registrationRevision, found, err := c.readRegistration(ctx, req.Node)
	if err != nil || !found || registrationRevision != query.RegistrationRevision ||
		!sameJSON(currentRegistration, registration) || currentRegistration.Generation != currentSession.RegistrationGeneration {
		return nil, errors.New("managed volume registration changed")
	}
	desired, desiredRevision, found, err := c.readDesired(ctx, req.Node, query.Role)
	if err != nil || !found || desiredRevision != query.DesiredRevision || desired.Withdrawn ||
		desired.AuthorityEpoch != authorityEpoch || desired.ManagedMember == nil || desired.ManagedMember.Runtime == nil {
		return nil, errors.New("managed volume desired changed or is incomplete")
	}
	if err := validateDesired(desired, c.cell, registration); err != nil {
		return nil, err
	}
	if err := c.managedVerifier.VerifyManagedRegistration(ctx, registration); err != nil {
		return nil, fmt.Errorf("verify current managed host registration: %w", err)
	}
	launch := *desired.ManagedMember
	if launch.OCI != *registration.ManagedOCI || launch.Member != *registration.ManagedMember ||
		launch.OCI.InstanceID == "" || launch.VolumeID == "" || launch.AttachmentID == "" ||
		launch.AttachmentETag == "" || launch.Runtime.DevicePath == "" {
		return nil, errors.New("managed volume desired differs from registered instance")
	}
	observation, err := c.volumeInspector(ctx, desired, registration)
	if err != nil {
		return nil, fmt.Errorf("inspect owned OCI volume: %w", err)
	}
	if !lowerHex(observation.BootDescriptorSHA256, 64) {
		return nil, errors.New("managed OCI volume observation lacks boot binding")
	}
	if err := c.guard(ctx, authorityEpoch); err != nil {
		return nil, err
	}
	latest, latestRevision, found, err := c.readDesired(ctx, req.Node, query.Role)
	if err != nil || !found || latestRevision != desiredRevision || !sameJSON(latest, desired) {
		return nil, errors.New("managed volume desired changed during OCI inspection")
	}
	currentRegistration, currentRevision, found, err := c.readRegistration(ctx, req.Node)
	if err != nil || !found || currentRevision != registrationRevision ||
		!sameJSON(currentRegistration, registration) {
		return nil, errors.New("managed volume registration changed during OCI inspection")
	}
	currentKey, err := decodePublicKey(currentRegistration.PublicKey)
	if err != nil || verifyRequest(req, currentKey, c.cell, time.Now().UTC()) != nil {
		return nil, errors.New("managed volume request expired during OCI inspection")
	}
	latestSession, _, found, err := c.sessionSnapshot(ctx, sessionKey(c.cell, req.Node))
	if err != nil || !found || !currentAuthorizedSession(latestSession, currentRegistration, req, time.Now()) {
		return nil, errors.New("managed volume session changed during OCI inspection")
	}
	if err := c.guard(ctx, authorityEpoch); err != nil {
		return nil, err
	}
	return volumeInitPermit{Desired: desired, Registration: registration,
		DesiredRevision: desiredRevision, RegistrationRevision: registrationRevision,
		SessionID: currentSession.SessionID, Observation: observation}, nil
}

func (a *Agent) ensureManagedVolume(ctx context.Context, desired Desired, target desiredReply) error {
	launch := desired.ManagedMember
	if launch == nil || launch.Runtime == nil || target.Registration == nil {
		return errors.New("managed volume initialization lacks signed desired")
	}
	paths, err := runtimePaths(a.cfg.ManagedRuntimeRoot, *launch)
	if err != nil {
		return err
	}
	if mount, err := verifyManagedMount(paths, *launch.Runtime, a.cfg.WorkloadIdentity); err == nil {
		mount.close()
		claimed, claimErr := managedVolumeHasExactClaim(paths, *launch)
		if claimErr != nil {
			return claimErr
		}
		if claimed {
			return nil
		}
	}
	socket := a.cfg.VolumeInitSocket
	if socket == "" {
		socket = volumeInitSocketPath
	}
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socket)
	if err != nil {
		return fmt.Errorf("connect fixed volume initializer: %w", err)
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if err := connection.SetDeadline(time.Now().Add(20 * time.Minute)); err != nil {
		return err
	}
	latest := desiredReply{}
	if err := a.request(ctx, "desired", struct {
		Role string `json:"role"`
	}{desired.Role}, &latest); err != nil {
		return err
	}
	if err := a.validateDesiredReply(latest); err != nil || !sameDesiredReplyBinding(target, latest) {
		return errors.New("managed desired changed before volume initialization")
	}
	currentSession, _, err := a.executionLease()
	if err != nil {
		return err
	}
	var permit volumeInitPermit
	var signed protocol.Envelope
	if _, err := a.sendToLeader(ctx, "volume-init", volumeInitQuery{Role: desired.Role,
		DesiredRevision: target.Revision, RegistrationRevision: target.RegistrationRevision},
		&permit, &signed, nil); err != nil {
		return err
	}
	if !sameJSON(permit.Desired, desired) || !sameJSON(permit.Registration, *target.Registration) ||
		permit.DesiredRevision != target.Revision || permit.RegistrationRevision != target.RegistrationRevision ||
		permit.SessionID != currentSession.SessionID || signed.Epoch != currentSession.Epoch {
		return errors.New("volume initialization permit differs from current host session or desired")
	}
	latestSession, _, err := a.executionLease()
	if err != nil {
		return err
	}
	if latestSession.SessionID != currentSession.SessionID || latestSession.Epoch != currentSession.Epoch ||
		latestSession.RegistrationGeneration != currentSession.RegistrationGeneration {
		return errors.New("managed volume host session changed before helper handoff")
	}
	wire, err := protocol.EncodeJSON(signed)
	if err != nil || len(wire) == 0 || len(wire) > 64<<10 {
		return errors.New("volume initialization permit exceeds wire bound")
	}
	if err := exchangeVolumeInit(connection, wire); err != nil {
		return errors.New("fixed volume initializer did not establish the signed mount")
	}
	mount, err := verifyManagedMount(paths, *launch.Runtime, a.cfg.WorkloadIdentity)
	if err != nil {
		return fmt.Errorf("volume initializer mount readback: %w", err)
	}
	mount.close()
	return nil
}

// exchangeVolumeInit sends one length-prefixed request to the fixed volume
// initializer and reads its result; zero means it succeeded. A first-format
// request additionally returns the durable initializer attempt's 32-byte ID.
func exchangeVolumeInit(connection net.Conn, wire []byte) error {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(wire)))
	if _, err := connection.Write(size[:]); err != nil {
		return err
	}
	if _, err := connection.Write(wire); err != nil {
		return err
	}
	var result [1]byte
	if _, err := io.ReadFull(connection, result[:]); err != nil {
		return err
	}
	switch result[0] {
	case 0:
		return nil
	case volumeInitNeedsGrant:
		var attempt [26]byte
		if _, err := io.ReadFull(connection, attempt[:]); err != nil {
			return err
		}
		if !entityid.Valid(string(attempt[:])) {
			return errors.New("volume initializer returned an invalid first-format attempt")
		}
		return terraBaseFormatNeeded{AttemptID: string(attempt[:])}
	}
	return errors.New("volume initializer refused the request")
}
