package databaseadmission

import (
	"context"
	"encoding/json/v2"
	"errors"
	"github.com/nats-io/nats.go"
	"io"
	"net/http"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission/subjects"
	"time"
)

const DeletionBeginSubject = subjects.DeletionBegin
const DeletionStatusSubject = subjects.DeletionStatus

type deletionAuthorizationKey struct{}

func WithDeletionAuthorization(ctx context.Context, authorization string) context.Context {
	return context.WithValue(ctx, deletionAuthorizationKey{}, authorization)
}

func DeletionAuthorization(ctx context.Context) string {
	value, _ := ctx.Value(deletionAuthorizationKey{}).(string)
	return value
}

type deletionCommand struct {
	Request       DeleteRequest `json:"request"`
	Authorization string        `json:"authorization"`
}

func validDeletionAuthorization(value string) bool {
	return strings.HasPrefix(value, "Bearer ") && len(value) > 7 && len(value) <= 8192 && !strings.ContainsAny(value, "\r\n")
}

type deletionResponse struct {
	Result *Deletion `json:"result,omitempty"`
	Error  string    `json:"error,omitempty"`
}

func (w *DeletionWorkflow) Status(ctx context.Context, r DeleteRequest) (Deletion, error) {
	if w == nil || w.Journal == nil || w.Policy == nil || !validDeleteRequest(r) {
		return Deletion{}, ErrInvalid
	}
	if _, err := w.Policy.AuthorizeDeletion(ctx, r); err != nil {
		return Deletion{}, err
	}
	ds, err := w.Journal.ListDeletions(ctx)
	if err != nil {
		return Deletion{}, err
	}
	for _, d := range ds {
		if d.Request == r {
			return d, nil
		}
	}
	return Deletion{}, ErrConflict
}
func StartDeletionAuthority(ctx context.Context, nc *nats.Conn, w *DeletionWorkflow) (*Service, error) {
	if ctx == nil || !secureConnection(nc) || w == nil || w.Journal == nil || w.Policy == nil || w.Stopper == nil {
		return nil, ErrInvalid
	}
	var subs []*nats.Subscription
	closeSubs := func() error {
		var errs []error
		for _, sub := range subs {
			errs = append(errs, sub.Unsubscribe())
		}
		return errors.Join(errs...)
	}
	for _, subject := range []string{DeletionBeginSubject, DeletionStatusSubject} {
		sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
			if m.Reply == "" || len(m.Data) > maxMessage {
				return
			}
			var command deletionCommand
			reply := deletionResponse{}
			if json.Unmarshal(m.Data, &command, json.RejectUnknownMembers(true)) != nil || !validDeletionAuthorization(command.Authorization) {
				reply.Error = "invalid"
			} else {
				opctx, cancel := context.WithTimeout(context.WithValue(ctx, deletionAuthorizationKey{}, command.Authorization), 20*time.Second)
				defer cancel()
				var d Deletion
				var err error
				if m.Subject == DeletionBeginSubject {
					d, err = w.Begin(opctx, command.Request)
				} else {
					d, err = w.Status(opctx, command.Request)
				}
				if err != nil {
					reply.Error = lifecycleError(err)
				} else {
					reply.Result = &d
				}
			}
			data, err := json.Marshal(reply)
			if err != nil || len(data) > maxMessage {
				data = []byte(`{"error":"unavailable"}`)
			}
			_ = m.Respond(data)
		})
		if err != nil {
			_ = closeSubs()
			return nil, err
		}
		subs = append(subs, sub)
		if err = sub.SetPendingLimits(128, 8<<20); err != nil {
			_ = closeSubs()
			return nil, err
		}
	}
	if err := nc.FlushTimeout(5 * time.Second); err != nil {
		_ = closeSubs()
		return nil, err
	}
	service := &Service{done: make(chan struct{}), close: closeSubs}
	context.AfterFunc(ctx, func() { _ = service.Close() })
	return service, nil
}
func registerDeletionIngress(mux *http.ServeMux, c IngressConfig) {
	for path, subject := range map[string]string{"/internal/v1/databases/delete/begin": DeletionBeginSubject, "/internal/v1/databases/delete/status": DeletionStatusSubject} {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			uid, ok := r.Context().Value(peerUIDKey{}).(uint32)
			if !ok || uid != c.AllowedUID {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMessage))
			if err != nil {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			var request DeleteRequest
			authorization := r.Header.Get("Authorization")
			if json.Unmarshal(data, &request, json.RejectUnknownMembers(true)) != nil || !validDeletionAuthorization(authorization) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			data, err = json.Marshal(deletionCommand{Request: request, Authorization: authorization})
			if err != nil {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			m, err := c.Connection.RequestWithContext(ctx, subject, data)
			if err != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			var reply deletionResponse
			if len(m.Data) > maxMessage || json.Unmarshal(m.Data, &reply, json.RejectUnknownMembers(true)) != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			if reply.Error != "" {
				http.Error(w, reply.Error, lifecycleStatus(reply.Error))
				return
			}
			if reply.Result == nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			body, err := json.Marshal(reply.Result)
			if err != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		})
	}
}
