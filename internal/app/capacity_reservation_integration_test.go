package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// Even a publisher reaching a victim's reply subject cannot manufacture home authority.
func TestCapacityReservationSignedReplyNATS(t *testing.T) {
	// An open broker: this proves the signed reply checks, not the broker grants.
	conn := startEmbeddedNATS(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(identity.Wipe)
	user, err := identity.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"current home", "wrong signer", "wrong source", "wrong action", "wrong nonce", "wrong recipe", "mixed pool reply", "changed pin", "expired", "missing pin", "unavailable pin"} {
		t.Run(scenario, func(t *testing.T) {
			request := capacityReservationRequest{Recipe: nodescale.Recipe{Cell: "fra"},
				Request: budget.ReservationRequest{OperationID: entityid.New()}}
			request.Request.RecipeSHA256 = request.Recipe.SHA256()
			responses := make(chan error, 1)
			subscription, err := conn.Subscribe(protocol.CapacityReservationSubject("fra", "reserve"), func(message *nats.Msg) {
				var incoming capacityReservationRequest
				if err := protocol.DecodeStrict(message.Data, &incoming, 128<<10); err != nil {
					responses <- err
					return
				}
				response := capacityReservationResponse{Nonce: incoming.Nonce, Receipt: &budget.Reservation{
					OperationID: incoming.Request.OperationID, RecipeSHA256: incoming.Recipe.SHA256()}}
				scope := protocol.EnvelopeScope{Region: "fra", Kind: "capacity.reserve.response", Actor: "capacity-home", OperationID: incoming.Nonce, Epoch: 7}
				key := private
				now := time.Now().UTC()
				if scenario == "wrong signer" {
					key = attacker
				}
				if scenario == "wrong source" {
					scope.Region = "gru"
				}
				if scenario == "wrong action" {
					scope.Kind = "capacity.observe.response"
				}
				if scenario == "wrong nonce" {
					scope.OperationID = entityid.New()
				}
				if scenario == "wrong recipe" {
					response.Receipt.RecipeSHA256 = "altered"
				}
				if scenario == "mixed pool reply" {
					response.Pool = &capacityPoolResponse{Operation: rootoci.OperationAdvancePoolChild}
				}
				if scenario == "expired" {
					now = now.Add(-time.Minute)
				}
				payload, err := protocol.EncodeJSON(response)
				if err != nil {
					responses <- err
					return
				}
				envelope, err := protocol.SignEnvelope(payload, scope, now, now.Add(30*time.Second), key)
				if err != nil {
					responses <- err
					return
				}
				wire, err := protocol.EncodeJSON(envelope)
				if err == nil {
					err = message.Respond(wire)
				}
				responses <- err
			})
			if err != nil {
				t.Fatal(err)
			}
			defer subscription.Unsubscribe()
			r := &capacityReservations{conn: conn, cell: "fra", user: user,
				homeKey: func(context.Context) (ed25519.PublicKey, error) { return public, nil }}
			if scenario == "changed pin" {
				reads := 0
				r.homeKey = func(context.Context) (ed25519.PublicKey, error) {
					reads++
					if reads > 1 {
						return attacker.Public().(ed25519.PublicKey), nil
					}
					return public, nil
				}
			}
			if scenario == "missing pin" {
				r.homeKey = nil
			}
			if scenario == "unavailable pin" {
				r.homeKey = func(context.Context) (ed25519.PublicKey, error) {
					return nil, errors.New("home public material is pending")
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			receipt, err := r.request(ctx, "reserve", request)
			if scenario == "current home" {
				if err != nil || receipt.OperationID != request.Request.OperationID {
					t.Fatalf("current home reply: %+v, %v", receipt, err)
				}
			} else if err == nil {
				t.Fatal("untrusted or mismatched home reply authorized capacity")
			}
			if scenario != "missing pin" && scenario != "unavailable pin" {
				select {
				case err := <-responses:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal("NATS response did not cross the broker")
				}
			}
		})
	}
}
