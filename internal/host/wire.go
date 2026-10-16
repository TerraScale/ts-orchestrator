package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var errSessionOwned = errors.New("another process owns the host session")
var errSessionRequestDenied = errors.New("host session request was denied")

// errControllerNotLeader reports a request answered by a follower controller.
var errControllerNotLeader = errors.New("host request reached a follower controller")
var errSessionBackendUnavailable = errors.New("host session backend temporarily unavailable")

func transientSessionTransport(err error) bool {
	if api, ok := errors.AsType[*nats.APIError](err); ok && api.Code == 503 && api.ErrorCode == 10008 {
		// A surviving JetStream quorum can briefly report no metadata leader.
		return true
	}
	if api, ok := errors.AsType[*jetstream.APIError](err); ok && api.Code == 503 && api.ErrorCode == 10008 {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) ||
		errors.Is(err, nats.ErrNoResponders) || errors.Is(err, nats.ErrDisconnected) ||
		errors.Is(err, jetstream.ErrNoStreamResponse)
}

// sessionErrorClass is deliberately closed over fixed labels so diagnostics
// never expose broker URLs, signed requests, reply inboxes, or secret values.
func sessionErrorClass(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		return "timeout"
	case errors.Is(err, nats.ErrDisconnected), errors.Is(err, nats.ErrStaleConnection):
		return "disconnected"
	case errors.Is(err, nats.ErrNoResponders):
		return "no_responder"
	case errors.Is(err, nats.ErrAuthorization):
		return "authorization"
	case errors.Is(err, errSessionOwned):
		return "owned"
	case errors.Is(err, errSessionContention):
		return "contention"
	case errors.Is(err, errSessionBackendUnavailable), errors.Is(err, jetstream.ErrNoStreamResponse):
		return "backend_unavailable"
	case errors.Is(err, errSessionRequestDenied):
		return "denied"
	default:
		if api, ok := errors.AsType[*nats.APIError](err); ok && api.Code >= 500 {
			return "backend_unavailable"
		}
		if api, ok := errors.AsType[*jetstream.APIError](err); ok && api.Code >= 500 {
			return "backend_unavailable"
		}
		return "other"
	}
}

type request struct {
	Version            int               `json:"version"`
	CredentialProtocol uint64            `json:"credential_protocol,omitzero"`
	Node               string            `json:"node"`
	NATSUserPublicKey  string            `json:"nats_user_public_key"`
	Operation          string            `json:"operation"`
	SessionID          string            `json:"session_id"`
	Epoch              uint64            `json:"epoch"`
	Nonce              string            `json:"nonce"`
	IssuedAt           time.Time         `json:"issued_at"`
	Payload            json.RawMessage   `json:"payload"`
	Envelope           protocol.Envelope `json:"-"`
}

type response struct {
	Nonce     string          `json:"nonce"`
	Node      string          `json:"node"`
	SessionID string          `json:"session_id"`
	Epoch     uint64          `json:"epoch"`
	Operation string          `json:"operation"`
	Error     string          `json:"error,omitempty"`
	Retryable bool            `json:"retryable,omitzero"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type session struct {
	RegistrationGeneration uint64    `json:"registration_generation"`
	SessionID              string    `json:"session_id"`
	Epoch                  uint64    `json:"epoch"`
	ExpiresAt              time.Time `json:"expires_at"`
	LastNonce              string    `json:"last_nonce"`
	LastIssuedAt           time.Time `json:"last_issued_at"`
}

type desiredReply struct {
	Desired              *Desired      `json:"desired,omitempty"`
	Revision             uint64        `json:"revision"`
	Registration         *Registration `json:"registration,omitempty"`
	RegistrationRevision uint64        `json:"registration_revision"`
}
type artifactQuery struct {
	Role   string `json:"role"`
	Digest string `json:"digest"`
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
}
type artifactReply struct {
	Digest string `json:"digest"`
	Offset int64  `json:"offset"`
	Total  int64  `json:"total"`
	Data   []byte `json:"data"`
}
type cycleQuery struct {
	Role           string `json:"role"`
	Digest         string `json:"digest"`
	Generation     uint64 `json:"generation"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	Attempt        string `json:"attempt"`
	CycleID        string `json:"cycle_id,omitempty"`
	Fence          uint64 `json:"fence,omitempty"`
	Succeeded      bool   `json:"succeeded,omitzero"`
}
type cycleReply struct {
	CycleID   string    `json:"cycle_id"`
	Fence     uint64    `json:"fence"`
	State     string    `json:"state"`
	NotBefore time.Time `json:"not_before,omitzero"`
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}

func randomID() (string, error) { return entityid.New(), nil }

func randomNonce() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}

func signRequest(r *request, key ed25519.PrivateKey, cell string) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid host identity key")
	}
	payload, err := json.Marshal(r)
	if err != nil {
		return err
	}
	r.Envelope, err = protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: cell, Kind: "host." + r.Operation, Actor: r.Node, OperationID: entityid.Derive("host-request", r.Nonce), Epoch: r.Epoch}, r.IssuedAt, r.IssuedAt.Add(requestTTL), key)
	return err
}

func verifyRequest(r request, key ed25519.PublicKey, cell string, now time.Time) error {
	if r.Version != 1 || !lowerHex(r.Nonce, 32) || !entityid.Valid(r.SessionID) || r.IssuedAt.IsZero() || r.IssuedAt.After(now.Add(maxClockSkew)) || now.Sub(r.IssuedAt) >= requestTTL {
		return errors.New("invalid or expired host request")
	}
	if !r.Envelope.IssuedAt.Equal(r.IssuedAt) || r.Envelope.Epoch != r.Epoch {
		return errors.New("host request envelope binding mismatch")
	}
	return protocol.VerifyEnvelope(r.Envelope, protocol.EnvelopeScope{Region: cell, Kind: "host." + r.Operation, Actor: r.Node, OperationID: entityid.Derive("host-request", r.Nonce), Epoch: r.Epoch}, key, now, protocol.VerifyPolicy{MaxLifetime: requestTTL, ClockSkew: maxClockSkew})
}

func decodeStrict(data []byte, destination any) error {
	return protocol.DecodeStrict(data, destination, 512<<10)
}

func exchange(ctx context.Context, conn *nats.Conn, cell string, controllerKey ed25519.PublicKey, r request, out any) error {
	return exchangeWithEnvelope(ctx, conn, cell, controllerKey, r, out, nil)
}

func exchangeWithEnvelope(ctx context.Context, conn *nats.Conn, cell string, controllerKey ed25519.PublicKey,
	r request, out any, signedOut *protocol.Envelope,
) error {
	if conn == nil {
		return errors.New("NATS connection is required")
	}
	data, err := protocol.EncodeJSON(r.Envelope)
	if err != nil {
		return err
	}
	if len(data) > 64<<10 {
		return errors.New("host request is too large")
	}
	subject, err := protocol.AgentObservationSubject(cell, r.NATSUserPublicKey, r.Operation)
	if err != nil {
		return err
	}
	timeout := 5 * time.Second
	if r.Operation == "material" || r.Operation == "volume-init" || r.Operation == "runtime-effect" {
		timeout = 30 * time.Second
	}
	deadline, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	msg, err := conn.RequestMsgWithContext(deadline, &nats.Msg{Subject: subject, Data: data, Header: observability.TraceHeader(ctx, nil)})
	if err != nil {
		return err
	}
	if len(msg.Data) > 512<<10 {
		return errors.New("host response is too large")
	}
	var signed protocol.Envelope
	if err := protocol.DecodeStrict(msg.Data, &signed, 512<<10); err != nil {
		return err
	}
	if err := protocol.VerifyEnvelope(signed, protocol.EnvelopeScope{Region: cell, Kind: "host.response." + r.Operation, Actor: "controller", OperationID: entityid.Derive("host-request", r.Nonce), Epoch: r.Epoch}, controllerKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: requestTTL, ClockSkew: maxClockSkew}); err != nil {
		return err
	}
	var result response
	if err := decodeStrict([]byte(signed.Payload), &result); err != nil {
		return err
	}
	if result.Nonce != r.Nonce || result.Node != r.Node || result.SessionID != r.SessionID || result.Epoch != r.Epoch || result.Operation != r.Operation {
		return errors.New("host response binding mismatch")
	}
	if result.Error != "" {
		if strings.HasPrefix(result.Error, authority.ErrNotLeader.Error()) {
			return fmt.Errorf("%w: %s", errControllerNotLeader, result.Error)
		}
		if result.Retryable {
			if result.Error == errSessionContention.Error() {
				return errSessionContention
			}
			if r.Operation == "session" {
				return fmt.Errorf("%w: %s", errSessionBackendUnavailable, result.Error)
			}
			return errArtifactPreparing
		}
		if r.Operation == "session" {
			if result.Error == errSessionOwned.Error() {
				return errSessionOwned
			}
			return fmt.Errorf("%w: %s", errSessionRequestDenied, result.Error)
		}
		return fmt.Errorf("host request denied: %s", result.Error)
	}
	if out != nil {
		if err := decodeStrict(result.Payload, out); err != nil {
			return err
		}
	}
	if signedOut != nil {
		*signedOut = signed
	}
	return nil
}
