package journal

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const (
	Endpoint        = "/v1/netbird/account-journal"
	Domain          = "terrascale.netbird.account-journal.v1"
	SignatureHeader = "X-TerraScale-NetBird-Journal-Signature"
	MaxMessageBytes = 96 << 10
)

type Action string

const (
	Ready    Action = "ready"
	Reserve  Action = "reserve"
	Complete Action = "complete"
)

var ErrAction = errors.New("invalid NetBird journal action")

// Request is data to authenticate; decoding it never grants dispatch authority.
type Request struct {
	SchemaVersion int          `json:"schemaVersion"`
	Domain        string       `json:"domain"`
	Action        Action       `json:"action"`
	Binding       Binding      `json:"binding"`
	OperationID   string       `json:"operationId"`
	Nonce         string       `json:"nonce"`
	StartedAt     time.Time    `json:"startedAt"`
	FirstDeadline time.Time    `json:"firstDeadline"`
	Reservation   *Reservation `json:"reservation,omitempty"`
	Completion    *Completion  `json:"completion,omitempty"`
}

func (Request) String() string     { return "NetBird journal request [redacted]" }
func (r Request) GoString() string { return r.String() }

func (r Request) Validate() error {
	if r.SchemaVersion != 1 || r.Domain != Domain || r.Binding.Validate() != nil || !entityid.Valid(r.OperationID) || !digest(r.Nonce) ||
		r.StartedAt.IsZero() || r.StartedAt.Location() != time.UTC || r.FirstDeadline.Location() != time.UTC ||
		!r.FirstDeadline.After(r.StartedAt) || r.FirstDeadline.After(r.StartedAt.Add(30*time.Second)) {
		return ErrAction
	}
	if r.Action == Ready {
		if r.Reservation != nil || r.Completion != nil {
			return ErrAction
		}
		return nil
	}
	if r.Reservation == nil || r.Reservation.Validate() != nil || r.Reservation.Binding != r.Binding ||
		r.Reservation.OperationID != r.OperationID || r.Reservation.Nonce != r.Nonce ||
		!r.Reservation.StartedAt.Equal(r.StartedAt) || !r.Reservation.FirstDeadline.Equal(r.FirstDeadline) {
		return ErrAction
	}
	switch r.Action {
	case Reserve:
		if r.Completion != nil {
			return ErrAction
		}
	case Complete:
		if r.Completion == nil || r.Completion.Validate(*r.Reservation) != nil || r.Completion.CompletedAt.Location() != time.UTC {
			return ErrAction
		}
	default:
		return ErrAction
	}
	return nil
}

// Encode returns the exact bytes to sign and send in the fixed HTTPS request.
func (r Request) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	wire, err := json.Marshal(r, json.Deterministic(true))
	if err != nil || len(wire) > MaxMessageBytes {
		return nil, ErrAction
	}
	return wire, nil
}

func (r Request) Digest() (string, error) {
	if _, err := r.Encode(); err != nil {
		return "", err
	}
	return wireDigest(r)
}

func DecodeRequest(wire []byte) (Request, error) {
	var request Request
	if len(wire) == 0 || len(wire) > MaxMessageBytes || json.Unmarshal(wire, &request, json.RejectUnknownMembers(true)) != nil {
		return Request{}, ErrAction
	}
	canonical, err := request.Encode()
	if err != nil || !bytes.Equal(wire, canonical) {
		return Request{}, ErrAction
	}
	return request, nil
}

// Reply binds a successful authenticated exchange to its exact request. It is
// not a dispatch permit outside the client's private original HTTP transaction.
type Reply struct {
	SchemaVersion            int    `json:"schemaVersion"`
	Domain                   string `json:"domain"`
	Action                   Action `json:"action"`
	RequestSHA256            string `json:"requestSha256"`
	NextCounter              uint64 `json:"nextCounter,omitempty"`
	PreviousCompletionSHA256 string `json:"previousCompletionSha256,omitempty"`
	ReservationSHA256        string `json:"reservationSha256,omitempty"`
	CompletionSHA256         string `json:"completionSha256,omitempty"`
}

func (reply Reply) Validate(request Request) error {
	fingerprint, err := request.Digest()
	if err != nil || reply.SchemaVersion != 1 || reply.Domain != Domain || reply.Action != request.Action || reply.RequestSHA256 != fingerprint {
		return ErrAction
	}
	if request.Action == Ready {
		if reply.NextCounter == 0 || reply.NextCounter == 1 && reply.PreviousCompletionSHA256 != "" ||
			reply.NextCounter > 1 && !digest(reply.PreviousCompletionSHA256) || reply.ReservationSHA256 != "" || reply.CompletionSHA256 != "" {
			return ErrAction
		}
		return nil
	}
	reservation, err := request.Reservation.Digest()
	if err != nil || reply.NextCounter != 0 || reply.PreviousCompletionSHA256 != "" || reply.ReservationSHA256 != reservation {
		return ErrAction
	}
	if request.Action == Reserve {
		if reply.CompletionSHA256 != "" {
			return ErrAction
		}
		return nil
	}
	completion, err := CompletionDigest(*request.Reservation, *request.Completion)
	if err != nil || reply.CompletionSHA256 != completion {
		return ErrAction
	}
	return nil
}

func (reply Reply) Encode(request Request) ([]byte, error) {
	if err := reply.Validate(request); err != nil {
		return nil, err
	}
	return json.Marshal(reply, json.Deterministic(true))
}

func DecodeReply(wire []byte, request Request) (Reply, error) {
	var reply Reply
	if len(wire) == 0 || len(wire) > MaxMessageBytes || json.Unmarshal(wire, &reply, json.RejectUnknownMembers(true)) != nil {
		return Reply{}, ErrAction
	}
	canonical, err := reply.Encode(request)
	if err != nil || !bytes.Equal(wire, canonical) {
		return Reply{}, ErrAction
	}
	return reply, nil
}
