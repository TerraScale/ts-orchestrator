package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const maxRegistrationBytes = 64 << 10
const maxRegistrationWireBytes = maxRegistrationBytes + 4096

func hostRegistrationSubject(cell string) string { return protocol.HostRegisterSubject(cell) }

func hostRegistrationID(r host.Registration) string {
	return fmt.Sprintf("host-register.%s.%d", r.Node, r.Generation)
}

func operatorHostRegister(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, output io.Writer) error {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxRegistrationBytes {
		return errors.New("host registration file exceeds size limit")
	}
	var registration host.Registration
	if err := json.Unmarshal(data, &registration, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("parse host registration: %w", err)
	}
	if registration.Cell == "" {
		registration.Cell = cfg.NATS.Cell
	}
	if registration.Cell != cfg.NATS.Cell {
		return errors.New("host registration belongs to another cell")
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return err
	}
	grant, exists := policy.grants[cfg.Operator.Actor]
	if !exists || !grant.CanRegisterHosts || !slices.Contains(grant.Environments, registration.Environment) {
		return errors.New("operator is not authorized to register hosts in this environment")
	}
	for _, role := range registration.Roles {
		if slices.Contains(grant.Roles, role) {
			continue
		}
		// The cell spec may let this operator release the role.
		reply, err := requestCellSpec(ctx, cfg, runtime, cellSpecGetKind, []byte("{}"))
		service, found := reply.Spec.Find(role)
		if err != nil || !found || reply.Spec.Environment != registration.Environment ||
			!slices.Contains(service.Releasers, cfg.Operator.Actor) {
			return fmt.Errorf("operator is not authorized to register role %q", role)
		}
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return err
	}
	snapshot, err := authority.Observe(ctx, runtime.JetStream(), cfg.NATS.Cell)
	if err != nil {
		return err
	}
	if !snapshot.Ready || snapshot.Reason != "observed" || snapshot.Epoch == 0 || !time.Now().Before(snapshot.ExpiresAt) {
		return errors.New("regional authority lease is not current")
	}
	payload, err := json.Marshal(registration)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: "host.registration", Actor: cfg.Operator.Actor,
		OperationID: hostRegistrationID(registration), Generation: registration.Generation, Epoch: snapshot.Epoch,
	}, now, now.Add(time.Minute), codec.PrivateKey)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return err
	}
	for attempt := range 3 {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		message, requestErr := runtime.Conn().RequestWithContext(requestCtx, hostRegistrationSubject(cfg.NATS.Cell), wire)
		cancel()
		if requestErr == nil {
			var response hostRegistrationResponse
			if err := json.Unmarshal(message.Data, &response, json.RejectUnknownMembers(true)); err != nil {
				return fmt.Errorf("decode host registration reply: %w", err)
			}
			if response.Error != "" {
				return errors.New(response.Error)
			}
			return printJSON(output, response.Receipt)
		}
		if (!errors.Is(requestErr, nats.ErrTimeout) && !errors.Is(requestErr, context.DeadlineExceeded)) || attempt == 2 {
			return fmt.Errorf("request host registration: %w", requestErr)
		}
	}
	return errors.New("host registration request exhausted")
}

type hostRegistrationResponse struct {
	Receipt host.Receipt `json:"receipt"`
	Error   string       `json:"error,omitempty"`
}

// All controllers observe the request. Only the current leader replies; a
// follower cannot cause a fast false failure in a replicated regional cell.
func serveHostEnrollment(ctx context.Context, conn *nats.Conn, cell string, policy signerPolicy,
	fencer authority.Fencer, controller *host.Controller, managed *managedHostEnrollment, services *specRegistry,
) (*nats.Subscription, error) {
	return conn.Subscribe(hostRegistrationSubject(cell), func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > maxRegistrationWireBytes || !fencer.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var envelope protocol.Envelope
		decodeErr := protocol.DecodeStrict(message.Data, &envelope, maxRegistrationWireBytes)
		if decodeErr == nil && envelope.Kind == cellSpecPublishKind {
			// The global leader answers it (serveCellSpecRelay).
			return
		}
		if decodeErr == nil && services != nil &&
			(envelope.Kind == cellSpecGetKind || envelope.Kind == cellSpecDiffKind || envelope.Kind == cellSpecApplyKind) {
			reply, err := services.serve(requestCtx, message.Data, policy, fencer, controller)
			if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || !fencer.Current().CanMutate() {
				return
			}
			if err != nil {
				reply = specReply{Error: err.Error()}
			}
			if wire, marshalErr := json.Marshal(reply); marshalErr == nil {
				_ = message.Respond(wire)
			}
			return
		}
		if decodeErr == nil && policy.rollouts != nil && strings.HasPrefix(envelope.Kind, "rollout.") {
			reply, err := policy.rollouts.serve(requestCtx, message.Data, policy, fencer)
			if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || !fencer.Current().CanMutate() {
				return
			}
			if err != nil {
				reply = rolloutReply{Error: err.Error()}
			}
			if wire, marshalErr := json.Marshal(reply); marshalErr == nil {
				_ = message.Respond(wire)
			}
			return
		}
		if decodeErr == nil && services != nil && services.roots != nil &&
			(envelope.Kind == rootListKind || envelope.Kind == rootRotateKind) {
			reply, err := services.roots.serve(requestCtx, message.Data, policy, fencer)
			if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || !fencer.Current().CanMutate() {
				return
			}
			if err != nil {
				reply = rootChainReply{Error: err.Error()}
			}
			if wire, marshalErr := json.Marshal(reply); marshalErr == nil {
				_ = message.Respond(wire)
			}
			return
		}
		if decodeErr == nil && envelope.Kind == "host.enrollment.revoke" {
			receipt, err := verifyAndRevokeHostEnrollment(requestCtx, message.Data, cell, policy, managed)
			if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || !fencer.Current().CanMutate() {
				return
			}
			reply := hostEnrollmentRevokeReply{Receipt: receipt}
			if err != nil {
				reply.Receipt = hostEnrollmentRevokeReceipt{}
				reply.Error = err.Error()
			}
			if wire, marshalErr := json.Marshal(reply); marshalErr == nil {
				_ = message.Respond(wire)
			}
			return
		}
		receipt, err := verifyAndRegister(requestCtx, message.Data, cell, policy, fencer, controller)
		if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || !fencer.Current().CanMutate() {
			return
		}
		response := hostRegistrationResponse{Receipt: receipt}
		if err != nil {
			response.Receipt = host.Receipt{}
			response.Error = err.Error()
		}
		wire, err := json.Marshal(response)
		if err == nil {
			_ = message.Respond(wire)
		}
	})
}

func verifyAndRegister(ctx context.Context, wire []byte, cell string, policy signerPolicy, fencer authority.Fencer, controller *host.Controller) (host.Receipt, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxRegistrationWireBytes); err != nil {
		return host.Receipt{}, err
	}
	var registration host.Registration
	if err := protocol.DecodeStrict(envelope.Payload, &registration, maxRegistrationBytes); err != nil {
		return host.Receipt{}, err
	}
	grant, exists := policy.grants[envelope.Actor]
	if !exists || !grant.CanRegisterHosts || registration.Cell != cell || !slices.Contains(grant.Environments, registration.Environment) {
		return host.Receipt{}, errors.New("host registration actor is unauthorized")
	}
	for _, role := range registration.Roles {
		if !slices.Contains(grant.Roles, role) && !policy.services.releaser(envelope.Actor, role, registration.Environment) {
			return host.Receipt{}, errors.New("host registration role is unauthorized")
		}
	}
	trusted, exists := policy.codec.Trusted[envelope.KeyID]
	if !exists || trusted.Actor != envelope.Actor {
		return host.Receipt{}, errors.New("host registration signing key is untrusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: cell, Kind: "host.registration", Actor: trusted.Actor,
		OperationID: hostRegistrationID(registration), Generation: registration.Generation, Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return host.Receipt{}, err
	}
	if envelope.Epoch == 0 || fencer.Current().Epoch != envelope.Epoch {
		return host.Receipt{}, authority.ErrFenced
	}
	if err := fencer.Guard(ctx, envelope.Epoch); err != nil {
		return host.Receipt{}, err
	}
	return controller.Register(ctx, registration)
}
