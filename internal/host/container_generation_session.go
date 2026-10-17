//go:build linux

package host

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// ContainerGenerationSession authorizes metadata observation only. It cannot
// substitute for a signed container-material request in delivery admission.
type ContainerGenerationSession struct {
	reader       *Reader
	original     context.Context
	node         string
	registration []byte
	session      session
	deadline     time.Time
}

func (s *ContainerGenerationSession) Deadline() time.Time { return s.deadline }

func (s *ContainerGenerationSession) Registration() (Registration, error) {
	var registration Registration
	err := protocol.DecodeStrict(s.registration, &registration, 64<<10)
	return registration, err
}

func (r *Reader) AdmitContainerGenerationSession(ctx context.Context, node string) (*ContainerGenerationSession, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, errors.New("container generation observation was cancelled")
	}
	registration, current, err := r.currentContainerGenerationSession(ctx, node)
	if err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(registration)
	if err != nil {
		return nil, err
	}
	deadline := current.ExpiresAt
	if original, ok := ctx.Deadline(); ok {
		deadline = containerMaterialDeadline(deadline, original)
	}
	admitted := &ContainerGenerationSession{reader: r, original: ctx, node: node, registration: wire, session: current, deadline: deadline}
	if err := admitted.Guard(ctx); err != nil {
		return nil, err
	}
	return admitted, nil
}

func (s *ContainerGenerationSession) Guard(ctx context.Context) error {
	if s == nil || s.reader == nil || s.original == nil || ctx == nil || s.original.Err() != nil || ctx.Err() != nil || !time.Now().Before(s.deadline) {
		return errors.New("original container generation session expired or was cancelled")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.original, cancel)
	defer cancel()
	defer stop()
	registration, current, err := s.reader.currentContainerGenerationSession(ctx, s.node)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(registration)
	if err != nil || !bytes.Equal(wire, s.registration) || current.RegistrationGeneration != s.session.RegistrationGeneration ||
		current.SessionID != s.session.SessionID || current.Epoch != s.session.Epoch || !time.Now().Before(s.deadline) || s.original.Err() != nil {
		return errors.New("original container generation recipient changed")
	}
	return ctx.Err()
}

func (r *Reader) currentContainerGenerationSession(ctx context.Context, node string) (Registration, session, error) {
	if r == nil || r.controller == nil {
		return Registration{}, session{}, errors.New("container generation host source is unavailable")
	}
	c := r.controller
	registration, err := c.registration(ctx, node)
	if err != nil {
		return Registration{}, session{}, err
	}
	retired, _, err := c.readRetirement(ctx, node)
	if err != nil || retired.Retired {
		return Registration{}, session{}, errors.New("container generation host is retired or unavailable")
	}
	if registration.ManagedPlacement != nil {
		if c.credentialFloor == nil {
			return Registration{}, session{}, errors.New("container generation credential floor is unavailable")
		}
		if floor, err := c.credentialFloor(ctx, registration); err != nil || floor == 0 {
			return Registration{}, session{}, errors.New("container generation credential floor is not current")
		}
	}
	current, _, exists, err := c.sessionSnapshot(ctx, sessionKey(c.cell, node))
	if err != nil {
		return Registration{}, session{}, err
	}
	if !exists || current.RegistrationGeneration != registration.Generation || current.SessionID == "" || current.Epoch == 0 || !time.Now().Before(current.ExpiresAt) {
		return Registration{}, session{}, errors.New("container generation host has no current session")
	}
	return registration, current, nil
}
