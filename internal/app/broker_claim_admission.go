package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/brokerauth"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
)

const maxBrokerClaimWireBytes = 72 << 10

func brokerClaimApplySubject(cell string) string {
	return protocol.BrokerClaimApplySubject(cell)
}

type brokerClaimApply struct {
	Cell             string `json:"cell"`
	Account          string `json:"account"`
	JWT              string `json:"jwt"`
	ExpectedSequence uint64 `json:"expectedSequence"`
}

type brokerClaimApplyResponse struct {
	Cell             string   `json:"cell"`
	Account          string   `json:"account"`
	RequestHash      string   `json:"requestHash"`
	ExpectedSequence uint64   `json:"expectedSequence"`
	Status           string   `json:"status"`
	Sequence         uint64   `json:"sequence"`
	Hash             string   `json:"hash"`
	Pending          []string `json:"pending,omitempty"`
}

// Only a verified leader receipt is authoritative. An unsigned error reply
// can stop this attempt, but it can never make the CLI report success.
type brokerClaimApplyReply struct {
	Proof *protocol.Envelope `json:"proof,omitempty"`
	Error string             `json:"error,omitempty"`
}

func brokerClaimOperationID(raw string) string {
	return entityid.Derive("broker-claim", raw)
}

// verifyBrokerClaimReply checks a claim-apply reply against the exact
// request: it must be a strict, signed broker.claim.receipt from the broker
// controller key for this operation and authority epoch, and its signed
// response must bind the cell, account, request hash, expected sequence and
// JWT digest. The caller still confirms the durable claim and the current
// authority before trusting a fenced or pending outcome.
func verifyBrokerClaimReply(data []byte, cell, account, raw string, wire []byte, expected, epoch uint64,
	public ed25519.PublicKey, now time.Time) (brokerClaimApplyReply, brokerClaimApplyResponse, error) {
	var reply brokerClaimApplyReply
	if err := json.Unmarshal(data, &reply, json.RejectUnknownMembers(true)); err != nil {
		return reply, brokerClaimApplyResponse{}, fmt.Errorf("decode untrusted broker claim reply: %w", err)
	}
	if reply.Proof == nil {
		return reply, brokerClaimApplyResponse{}, errors.New("unsigned broker claim reply")
	}
	var response brokerClaimApplyResponse
	if err := protocol.DecodeStrict(reply.Proof.Payload, &response, 4096); err != nil {
		return reply, response, err
	}
	if err := protocol.VerifyEnvelope(*reply.Proof, protocol.EnvelopeScope{
		Region: cell, Kind: "broker.claim.receipt", Actor: "broker-controller",
		OperationID: brokerClaimOperationID(raw), Generation: response.Sequence, Epoch: epoch,
	}, public, now, protocol.VerifyPolicy{MaxLifetime: time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return reply, response, err
	}
	digest := sha256.Sum256([]byte(raw))
	requestDigest := sha256.Sum256(wire)
	if response.Cell != cell || response.Account != account ||
		response.RequestHash != hex.EncodeToString(requestDigest[:]) || response.ExpectedSequence != expected ||
		response.Sequence == 0 || response.Hash != hex.EncodeToString(digest[:]) ||
		response.Status != "fenced" && response.Status != "pending" ||
		response.Status == "fenced" && len(response.Pending) != 0 ||
		response.Status == "pending" && len(response.Pending) == 0 {
		return reply, response, errors.New("signed broker claim receipt does not match the request")
	}
	return reply, response, nil
}

func operatorBrokerClaimApply(ctx context.Context, cfg Config, runtime *natscell.Runtime, path, expectedText string, output io.Writer) error {
	if !cfg.NATS.Lab {
		if err := natscell.ValidateBrokerOperatorCredentials(cfg.NATS.CredentialsFile, cfg.NATS.Cell); err != nil {
			return err
		}
	}
	if cfg.Operator.BrokerTicketPublicKeyFile == "" {
		return errors.New("broker claim apply requires a pinned ticket public key")
	}
	publicRaw, err := os.ReadFile(cfg.Operator.BrokerTicketPublicKeyFile)
	if err != nil {
		return fmt.Errorf("read pinned broker ticket public key: %w", err)
	}
	public, err := decodePublicKey(string(publicRaw))
	if err != nil {
		return fmt.Errorf("decode pinned broker ticket public key: %w", err)
	}
	expected, err := strconv.ParseUint(expectedText, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid broker claim expected sequence: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() > 64<<10 {
		return errors.New("broker account JWT file is unavailable or too large")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read broker account JWT: %w", err)
	}
	raw := strings.TrimSpace(string(data))
	decoded, err := jwt.DecodeAccountClaims(raw)
	if err != nil {
		return err
	}
	if _, err := brokerauth.DecodeAccountJWT(raw, decoded.Subject); err != nil {
		return err
	}
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return err
	}
	grant, exists := policy.grant(cfg.Operator.Actor)
	if !exists || !grant.CanRotateBrokerAccount {
		return errors.New("operator is not authorized to rotate the broker account")
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
	request := brokerClaimApply{Cell: cfg.NATS.Cell, Account: decoded.Subject, JWT: raw, ExpectedSequence: expected}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
		Region: cfg.NATS.Cell, Kind: "broker.claim.apply", Actor: cfg.Operator.Actor,
		OperationID: brokerClaimOperationID(raw), Generation: expected, Epoch: snapshot.Epoch,
	}, now, now.Add(time.Minute), codec.PrivateKey)
	if err != nil {
		return err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return err
	}
	active := runtime
	for attempt := range 3 {
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		message, requestErr := active.Conn().RequestWithContext(requestCtx, brokerClaimApplySubject(cfg.NATS.Cell), wire)
		cancel()
		if requestErr == nil {
			var reply brokerClaimApplyReply
			var response brokerClaimApplyResponse
			reply, response, requestErr = verifyBrokerClaimReply(message.Data, cfg.NATS.Cell, decoded.Subject, raw, wire,
				expected, snapshot.Epoch, public, time.Now().UTC())
			if requestErr == nil {
				store, err := brokerauth.OpenStore(ctx, active.JetStream(), cfg.NATS.Cell, nil)
				if err == nil {
					var current brokerauth.Claim
					current, err = store.Read(ctx, decoded.Subject)
					if err == nil && (current.Sequence != response.Sequence || current.Hash != response.Hash || current.JWT != raw) {
						err = errors.New("durable claim differs from signed receipt")
					}
				}
				if err == nil {
					var lease authority.Snapshot
					lease, err = authority.Observe(ctx, active.JetStream(), cfg.NATS.Cell)
					if err == nil && (!lease.Ready || lease.Epoch != reply.Proof.Epoch || !time.Now().Before(lease.ExpiresAt)) {
						err = errors.New("regional authority changed after the signed broker receipt")
					}
				}
				if err == nil {
					if err := printJSON(output, response); err != nil {
						return err
					}
					if response.Status == "pending" {
						return ErrBrokerFencePending
					}
					return nil
				}
				requestErr = err
			}
		}
		if attempt == 2 || ctx.Err() != nil {
			digest := sha256.Sum256([]byte(raw))
			return fmt.Errorf("broker claim outcome unknown (jwt_sha256=%x expected_sequence=%d): %w", digest, expected, requestErr)
		}
		// Fencing the broker may sever the requester's socket. A new
		// connection retries the same signed, idempotent request; only a
		// fresh acknowledgement can establish completed fencing.
		if active != runtime {
			_ = active.Close()
		}
		connection := cfg.NATS
		connection.ClientRole = "operator"
		connection, err = externalNATS(connection)
		if err != nil {
			digest := sha256.Sum256([]byte(raw))
			return fmt.Errorf("broker claim outcome unknown (jwt_sha256=%x expected_sequence=%d): %w", digest, expected, err)
		}
		active, err = natscell.Start(ctx, connection)
		if err != nil {
			digest := sha256.Sum256([]byte(raw))
			return fmt.Errorf("broker claim outcome unknown (jwt_sha256=%x expected_sequence=%d); reconnect: %w", digest, expected, err)
		}
		defer active.Close()
	}
	return errors.New("broker claim outcome unknown")
}

func serveBrokerClaimAdmission(ctx context.Context, conn *nats.Conn, cell string, policy signerPolicy, gate *brokerGate) (*nats.Subscription, error) {
	return conn.Subscribe(brokerClaimApplySubject(cell), func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) == 0 || len(message.Data) > maxBrokerClaimWireBytes ||
			gate == nil || !gate.control.Current().CanMutate() {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		response, err := verifyAndApplyBrokerClaim(requestCtx, message.Data, cell, policy, gate)
		if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) || !gate.control.Current().CanMutate() {
			return
		}
		if err != nil {
			wire, marshalErr := json.Marshal(brokerClaimApplyReply{Error: err.Error()})
			if marshalErr == nil {
				_ = message.Respond(wire)
			}
			return
		}
		var envelope protocol.Envelope
		if decodeErr := protocol.DecodeStrict(message.Data, &envelope, maxBrokerClaimWireBytes); decodeErr != nil {
			return
		}
		if err := gate.control.Guard(requestCtx, envelope.Epoch); err != nil {
			return
		}
		local := gate.control.Current()
		observed, err := authority.Observe(requestCtx, gate.runtime.JetStream(), cell)
		if err != nil || !observed.Ready || observed.Epoch != envelope.Epoch ||
			observed.CandidateID != local.CandidateID || observed.OwnerID != local.OwnerID ||
			!time.Now().Before(observed.ExpiresAt) {
			return
		}
		current, err := gate.store.Read(requestCtx, gate.account)
		if err != nil || current.Sequence != response.Sequence || current.Hash != response.Hash {
			return
		}
		payload, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			return
		}
		if err := gate.control.Guard(requestCtx, envelope.Epoch); err != nil {
			return
		}
		now := time.Now().UTC()
		expires := now.Add(time.Minute)
		if observed.ExpiresAt.Before(expires) {
			expires = observed.ExpiresAt
		}
		if !expires.After(now) {
			return
		}
		proof, signErr := protocol.SignEnvelope(payload, protocol.EnvelopeScope{
			Region: cell, Kind: "broker.claim.receipt", Actor: "broker-controller",
			OperationID: envelope.OperationID, Generation: response.Sequence, Epoch: envelope.Epoch,
		}, now, expires, gate.issuer.Key)
		if signErr != nil {
			return
		}
		wire, marshalErr := json.Marshal(brokerClaimApplyReply{Proof: &proof})
		if marshalErr == nil {
			_ = message.Respond(wire)
		}
	})
}

func verifyAndApplyBrokerClaim(ctx context.Context, wire []byte, cell string, policy signerPolicy, gate *brokerGate) (brokerClaimApplyResponse, error) {
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(wire, &envelope, maxBrokerClaimWireBytes); err != nil {
		return brokerClaimApplyResponse{}, err
	}
	var request brokerClaimApply
	if err := protocol.DecodeStrict(envelope.Payload, &request, maxBrokerClaimWireBytes-4096); err != nil {
		return brokerClaimApplyResponse{}, err
	}
	if request.Cell != cell || request.Account != gate.account {
		return brokerClaimApplyResponse{}, errors.New("broker claim belongs to another cell or account")
	}
	claim, err := brokerauth.DecodeAccountJWT(request.JWT, request.Account)
	if err != nil || !gate.runtime.SignedByPinnedOperator(claim) {
		return brokerClaimApplyResponse{}, errors.New("broker account JWT is not signed by the pinned operator")
	}
	grant, exists := policy.grant(envelope.Actor)
	if !exists || !grant.CanRotateBrokerAccount {
		return brokerClaimApplyResponse{}, errors.New("broker claim actor is unauthorized")
	}
	trusted, exists := policy.trusted(envelope.KeyID)
	if !exists || trusted.Actor != envelope.Actor {
		return brokerClaimApplyResponse{}, errors.New("broker claim signing key is untrusted")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{
		Region: cell, Kind: "broker.claim.apply", Actor: trusted.Actor,
		OperationID: brokerClaimOperationID(request.JWT), Generation: request.ExpectedSequence, Epoch: envelope.Epoch,
	}, trusted.PublicKey, time.Now().UTC(), protocol.VerifyPolicy{MaxLifetime: 5 * time.Minute, ClockSkew: 30 * time.Second}); err != nil {
		return brokerClaimApplyResponse{}, err
	}
	if envelope.Epoch == 0 || gate.control.Current().Epoch != envelope.Epoch {
		return brokerClaimApplyResponse{}, authority.ErrFenced
	}
	result, err := gate.commitAndFence(ctx, request.JWT, request.ExpectedSequence)
	if err != nil && !errors.Is(err, ErrBrokerFencePending) {
		return brokerClaimApplyResponse{}, err
	}
	requestDigest := sha256.Sum256(wire)
	response := brokerClaimApplyResponse{Cell: cell, Account: request.Account,
		RequestHash: hex.EncodeToString(requestDigest[:]), ExpectedSequence: request.ExpectedSequence,
		Status: "fenced", Sequence: result.Claim.Sequence, Hash: result.Claim.Hash}
	if errors.Is(err, ErrBrokerFencePending) {
		response.Status, response.Pending = "pending", result.Pending
	}
	return response, nil
}
