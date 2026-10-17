//go:build linux

package host

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// ContainerMaterialEvidence contains only the original public host signature.
// It grants no authority until the root reader independently admits it.
type ContainerMaterialEvidence struct {
	Request protocol.Envelope `json:"request"`
}

// ContainerMaterialSession pins root's original admission, including its deadline.
type ContainerMaterialSession struct {
	reader       *Reader
	original     context.Context
	request      request
	registration []byte
	binding      ContainerMaterialBinding
	deadline     time.Time
}

func (s *ContainerMaterialSession) Binding() ContainerMaterialBinding { return s.binding }
func (s *ContainerMaterialSession) Deadline() time.Time               { return s.deadline }

func (s *ContainerMaterialSession) Registration() (Registration, error) {
	var registration Registration
	err := protocol.DecodeStrict(s.registration, &registration, 64<<10)
	return registration, err
}

// AdmitContainerMaterialSession performs the actual material admission in root.
// A renewed session cannot extend this admission's original deadline.
func (r *Reader) AdmitContainerMaterialSession(ctx context.Context, evidence ContainerMaterialEvidence) (*ContainerMaterialSession, error) {
	if r == nil || r.controller == nil || ctx.Err() != nil {
		return nil, errors.New("container material session source is unavailable")
	}
	wire, err := protocol.EncodeJSON(evidence.Request)
	if err != nil || len(wire) > 64<<10 {
		return nil, errors.New("container material request exceeds host protocol bounds")
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, 64<<10); err != nil {
		return nil, err
	}
	var req request
	if err := protocol.DecodeStrict(envelope.Payload, &req, 64<<10); err != nil {
		return nil, err
	}
	req.Envelope = envelope
	var query containerMaterialQuery
	if req.Operation != "container-material" || decodeStrict(req.Payload, &query) != nil {
		return nil, errors.New("root material admission requires the original container operation")
	}
	region, known := catalog.CellForOCIRegion(query.Binding.Region)
	if validateContainerMaterialBinding(query.Binding) != nil || !known || region.Name() != r.controller.cell ||
		query.Offset < 0 || query.Offset >= maxContainerMaterialBytes || query.Length < 1 || query.Length > materialChunkBytes ||
		len(query.EphemeralPublicKey) != 32 {
		return nil, errors.New("container material request differs from the host protocol bounds")
	}
	registration, current, err := r.currentContainerMaterialSession(ctx, req)
	if err != nil {
		return nil, err
	}
	if query.RegistrationGeneration != registration.Generation || query.Binding.HostID != registration.ID {
		return nil, errors.New("container material request differs from the current registration")
	}
	registrationWire, err := protocol.EncodeJSON(registration)
	if err != nil {
		return nil, err
	}
	deadline := containerMaterialDeadline(current.ExpiresAt, containerMaterialDeadline(req.IssuedAt.Add(requestTTL), envelope.ExpiresAt))
	if callerDeadline, ok := ctx.Deadline(); ok {
		deadline = containerMaterialDeadline(deadline, callerDeadline)
	}
	admitted := &ContainerMaterialSession{reader: r, original: ctx, request: req, registration: registrationWire, binding: query.Binding, deadline: deadline}
	if err := admitted.Guard(ctx); err != nil {
		return nil, err
	}
	return admitted, nil
}

func containerMaterialDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *ContainerMaterialSession) Guard(ctx context.Context) error {
	if s == nil || s.reader == nil || s.original == nil || s.original.Err() != nil || ctx.Err() != nil || !time.Now().Before(s.deadline) {
		return errors.New("original container material admission expired or was cancelled")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.original, cancel)
	defer cancel()
	defer stop()
	registration, _, err := s.reader.currentContainerMaterialSession(ctx, s.request)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(registration)
	if err != nil || !bytes.Equal(wire, s.registration) || !time.Now().Before(s.deadline) || s.original.Err() != nil {
		return errors.New("original container material registration or deadline changed")
	}
	return ctx.Err()
}

func (r *Reader) currentContainerMaterialSession(ctx context.Context, req request) (Registration, session, error) {
	c := r.controller
	registration, err := c.registration(ctx, req.Node)
	if err != nil {
		return Registration{}, session{}, err
	}
	retired, _, err := c.readRetirement(ctx, req.Node)
	if err != nil || retired.Retired || registration.NATSUserPublicKey != req.NATSUserPublicKey {
		return Registration{}, session{}, errors.New("container material host registration is not admitted")
	}
	key, err := decodePublicKey(registration.PublicKey)
	if err != nil {
		return Registration{}, session{}, err
	}
	if err := verifyRequest(req, key, c.cell, time.Now().UTC()); err != nil {
		return Registration{}, session{}, err
	}
	if registration.ManagedPlacement != nil && c.credentialFloor == nil {
		return Registration{}, session{}, errors.New("container material managed credential floor is unavailable")
	}
	if err := c.verifyCredentialProtocol(ctx, req, registration); err != nil {
		return Registration{}, session{}, err
	}
	current, _, exists, err := c.sessionSnapshot(ctx, sessionKey(c.cell, req.Node))
	if err != nil {
		return Registration{}, session{}, err
	}
	if !exists || !currentAuthorizedSession(current, registration, req, time.Now()) {
		return Registration{}, session{}, errors.New("original container material host session is not current")
	}
	return registration, current, nil
}
