package hostagent

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
)

const internalCommandProof = "Ts-Node-Internal-Proof"

func (t *NatsTransport) authorizedHandler(handler func(*nats.Msg)) func(*nats.Msg) {
	return func(message *nats.Msg) {
		select {
		case <-t.closing:
			return
		default:
		}
		authorization, err := t.authorizer.Authorize(t.context(), message.Subject, message.Data)
		if err != nil {
			t.replyEnvelopeError(message, err)
			return
		}
		if authorization.NodeID != t.nodeId.Value {
			t.replyEnvelopeError(message, errors.New("signed command targets another node"))
			return
		}
		// The internal header is newly constructed after verification; an incoming
		// sender cannot supply this proof channel or bypass signed-body parsing.
		inner := *message
		inner.Data = authorization.Command
		inner.Header = nats.Header{internalCommandProof: []string{base64.StdEncoding.EncodeToString(message.Data)}}
		handler(&inner)
	}
}
func (t *NatsTransport) authorizeLocked(message *nats.Msg) (context.Context, context.CancelFunc, error) {
	select {
	case <-t.closing:
		return nil, nil, errors.New("hostagent: receiver closed")
	default:
	}
	proof, err := base64.StdEncoding.DecodeString(message.Header.Get(internalCommandProof))
	if err != nil || len(proof) == 0 {
		return nil, nil, errors.New("hostagent: signed command proof missing")
	}
	authorization, err := t.authorizer.Authorize(t.context(), message.Subject, proof)
	if err != nil {
		return nil, nil, err
	}
	if authorization.NodeID != t.nodeId.Value || !bytes.Equal(authorization.Command, message.Data) || !time.Now().Before(authorization.ExpiresAt) {
		return nil, nil, errors.New("hostagent: command authority expired or changed")
	}
	if err := t.epochs.Admit(authorization); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithDeadline(t.context(), authorization.ExpiresAt)
	return ctx, cancel, nil
}
