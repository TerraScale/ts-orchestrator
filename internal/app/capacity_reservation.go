package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

type capacitySpendAuthority interface {
	InfrastructureSpend(context.Context) (region.VerifiedInfrastructureSpend, error)
}

// Regions send recipes, never sealed authority, quotes or inventory snapshots.
type capacityReservationRequest struct {
	Nonce       string                       `json:"nonce"`
	Request     budget.ReservationRequest    `json:"request"`
	Recipe      nodescale.Recipe             `json:"recipe"`
	Image       nodescale.ImageQualification `json:"image"`
	Receipt     *budget.Reservation          `json:"receipt,omitempty"`
	ResourceIDs []string                     `json:"resource_ids,omitempty"`
	Pool        *capacityPoolRequest         `json:"pool,omitempty"`
}

type capacityReservationResponse struct {
	Nonce   string                `json:"nonce"`
	Receipt *budget.Reservation   `json:"receipt,omitempty"`
	Error   string                `json:"error,omitempty"`
	Pool    *capacityPoolResponse `json:"pool,omitempty"`
}

type capacityReservations struct {
	cell, user, environment string
	conn                    *nats.Conn
	global                  *globalControl
	spending                capacitySpendAuthority
	workers                 capacityWorkerAuthority
	caFile                  string
	specs                   *specRegistry
	responseKey             ed25519.PrivateKey
	homeKey                 func(context.Context) (ed25519.PublicKey, error)
}

func (r *capacityReservations) exchange(ctx context.Context, action string, request capacityReservationRequest) (capacityReservationResponse, error) {
	if r == nil || r.conn == nil {
		return capacityReservationResponse{}, fmt.Errorf("%w: home capacity authority is unavailable", nodescale.ErrCapacityPending)
	}
	if r.homeKey == nil {
		return capacityReservationResponse{}, fmt.Errorf("%w: independently verified current home response key is unavailable", nodescale.ErrCapacityPending)
	}
	public, err := r.homeKey(ctx)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return capacityReservationResponse{}, fmt.Errorf("%w: current home response authority is unavailable: %v", nodescale.ErrCapacityPending, err)
	}
	request.Nonce = entityid.New()
	reply := protocol.CapacityReservationReplySubject(r.cell, r.user, request.Nonce)
	if reply == "" {
		return capacityReservationResponse{}, errors.New("capacity reply identity is invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	subscription, err := r.conn.SubscribeSync(reply)
	if err != nil {
		return capacityReservationResponse{}, err
	}
	defer subscription.Unsubscribe()
	if err := r.conn.FlushWithContext(ctx); err != nil {
		return capacityReservationResponse{}, err
	}
	wire, err := protocol.EncodeJSON(request)
	if err != nil {
		return capacityReservationResponse{}, err
	}
	if err := r.conn.PublishRequest(protocol.CapacityReservationSubject(r.cell, action), reply, wire); err != nil {
		return capacityReservationResponse{}, err
	}
	message, err := subscription.NextMsgWithContext(ctx)
	if err != nil {
		return capacityReservationResponse{}, err
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(message.Data, &envelope, 128<<10); err != nil {
		return capacityReservationResponse{}, err
	}
	currentPublic, err := r.homeKey(ctx)
	if err != nil {
		return capacityReservationResponse{}, fmt.Errorf("%w: current home response authority: %v", nodescale.ErrCapacityPending, err)
	}
	if !slices.Equal(public, currentPublic) {
		return capacityReservationResponse{}, errors.New("home response authority changed during the original request")
	}
	if envelope.Epoch == 0 {
		return capacityReservationResponse{}, errors.New("capacity response lacks home authority epoch")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{Region: r.cell, Kind: "capacity." + action + ".response",
		Actor: "capacity-home", OperationID: request.Nonce, Epoch: envelope.Epoch}, public, time.Now().UTC(),
		protocol.VerifyPolicy{MaxLifetime: 30 * time.Second}); err != nil {
		return capacityReservationResponse{}, fmt.Errorf("verify current home capacity response: %w", err)
	}
	var response capacityReservationResponse
	if err := protocol.DecodeStrict(envelope.Payload, &response, 112<<10); err != nil {
		return capacityReservationResponse{}, err
	}
	if response.Nonce != request.Nonce || response.Error != "" {
		return capacityReservationResponse{}, fmt.Errorf("%w: home capacity reservation: %s", nodescale.ErrCapacityPending, response.Error)
	}
	return response, nil
}
