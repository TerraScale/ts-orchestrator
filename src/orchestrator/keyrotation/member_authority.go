package keyrotation

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
)

// NewMemberPeerAuthority checks the live stream-leader lease on each request.
// The read-only connection must belong to the global authority account. Pins
// bind separately provisioned controller TLS keys to election candidate IDs.
func NewMemberPeerAuthority(connection *nats.Conn, pins map[string]string) (func(context.Context, string) error, error) {
	if rotationTransport(connection) != nil || len(pins) == 0 {
		return nil, ErrStateUnavailable
	}
	candidates := maps.Clone(pins)
	for pin, candidate := range candidates {
		if len(pin) != 64 || !rotationToken(candidate) {
			return nil, ErrStateUnavailable
		}
	}
	return func(ctx context.Context, pin string) error {
		candidate, ok := candidates[pin]
		if !ok || rotationTransport(connection) != nil {
			return ErrStateFenced
		}
		payload, _ := json.Marshal(struct {
			Subject string `json:"last_by_subj"`
		}{rotationLeaseSubject})
		reply, err := connection.RequestWithContext(ctx, "$JS.API.STREAM.MSG.GET."+rotationStream, payload)
		if err != nil || reply == nil || len(reply.Data) > 16384 {
			return ErrStateUnavailable
		}
		var response struct {
			Message rotationRawMessage `json:"message"`
			Error   jsontext.Value     `json:"error"`
		}
		if json.Unmarshal(reply.Data, &response) != nil || len(response.Error) != 0 || response.Message.Subject != rotationLeaseSubject || response.Message.Sequence == 0 || len(response.Message.Headers) != 0 {
			return ErrStateUnavailable
		}
		var lease authority.RegionalAuthorityLeaseDocument
		if json.Unmarshal(response.Message.Data, &lease, json.RejectUnknownMembers(true)) != nil || lease.CandidateId != candidate || !rotationLeaseLive(lease, time.Now().UTC()) {
			return ErrStateFenced
		}
		return nil
	}, nil
}
