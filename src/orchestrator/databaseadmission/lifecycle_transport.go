package databaseadmission

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

const LifecycleEventSubject = "orch.database.lifecycle.event"
const InventoryFreezeSubject = "orch.database.inventory.freeze"
const InventoryResourcesSubject = "orch.database.inventory.resources"

type InventoryFreezeRequest struct {
	OrganizationID string    `json:"organization_id"`
	Start          time.Time `json:"start"`
	End            time.Time `json:"end"`
}
type InventoryResources struct {
	Revision  uint64                       `json:"revision"`
	Resources []databaselifecycle.Resource `json:"resources"`
}
type lifecycleResponse struct {
	Applied   bool                        `json:"applied,omitzero"`
	Snapshot  *databaselifecycle.Snapshot `json:"snapshot,omitempty"`
	Inventory *InventoryResources         `json:"inventory,omitempty"`
	Error     string                      `json:"error,omitempty"`
}

// LifecyclePublisherPermissions are only for trusted backend lifecycle workers.
// Neither customer credentials nor billing credentials may mutate lifecycle.
func LifecyclePublisherPermissions() (publish, subscribe []string) {
	return []string{LifecycleEventSubject}, []string{"_INBOX.>"}
}
func InventoryConsumerPermissions() (publish, subscribe []string) {
	return []string{InventoryFreezeSubject, InventoryResourcesSubject}, []string{"_INBOX.>"}
}
func lifecycleError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalid), errors.Is(err, databaselifecycle.ErrInvalid):
		return "invalid"
	case errors.Is(err, ErrConflict), errors.Is(err, databaselifecycle.ErrConflict):
		return "conflict"
	case errors.Is(err, databaselifecycle.ErrClosed):
		return "closed"
	case errors.Is(err, databaselifecycle.ErrIncomplete):
		return "incomplete"
	case errors.Is(err, ErrForbidden):
		return "forbidden"
	default:
		return "unavailable"
	}
}
func lifecycleStatus(code string) int {
	switch code {
	case "invalid":
		return http.StatusBadRequest
	case "conflict", "closed":
		return http.StatusConflict
	case "forbidden":
		return http.StatusForbidden
	default:
		return http.StatusServiceUnavailable
	}
}
func handleLifecycle(ctx context.Context, journal LifecycleJournal, subject string, data []byte) lifecycleResponse {
	var reply lifecycleResponse
	var err error
	switch subject {
	case LifecycleEventSubject:
		var event databaselifecycle.Event
		if json.Unmarshal(data, &event, json.RejectUnknownMembers(true)) != nil || event.Kind == "create" {
			return lifecycleResponse{Error: "invalid"}
		}
		err = journal.ApplyLifecycle(ctx, event)
		reply.Applied = err == nil
	case InventoryFreezeSubject:
		var request InventoryFreezeRequest
		if json.Unmarshal(data, &request, json.RejectUnknownMembers(true)) != nil {
			return lifecycleResponse{Error: "invalid"}
		}
		var snapshot databaselifecycle.Snapshot
		snapshot, err = journal.FreezeInventory(ctx, request.OrganizationID, request.Start, request.End)
		if err == nil {
			reply.Snapshot = &snapshot
		}
	case InventoryResourcesSubject:
		var request struct{}
		if json.Unmarshal(data, &request, json.RejectUnknownMembers(true)) != nil {
			return lifecycleResponse{Error: "invalid"}
		}
		var inventory InventoryResources
		inventory.Revision, inventory.Resources, err = journal.LifecycleResources(ctx)
		if err == nil {
			reply.Inventory = &inventory
		}
	default:
		return lifecycleResponse{Error: "invalid"}
	}
	reply.Error = lifecycleError(err)
	return reply
}

// StartLifecycleAuthority shares the admission journal and leadership fence.
// The broker must restrict event publication to lifecycle workers and inventory
// requests to the separate billing service NKey.
func StartLifecycleAuthority(ctx context.Context, nc *nats.Conn, journal LifecycleJournal) (*Service, error) {
	if ctx == nil || !secureConnection(nc) || journal == nil {
		return nil, ErrInvalid
	}
	var subscriptions []*nats.Subscription
	closeSubscriptions := func() error {
		var errs []error
		for _, sub := range subscriptions {
			errs = append(errs, sub.Unsubscribe())
		}
		return errors.Join(errs...)
	}
	for _, subject := range []string{LifecycleEventSubject, InventoryFreezeSubject, InventoryResourcesSubject} {
		sub, err := nc.Subscribe(subject, func(message *nats.Msg) {
			if message.Reply == "" || len(message.Data) > maxMessage {
				return
			}
			opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			reply := handleLifecycle(opctx, journal, message.Subject, message.Data)
			data, err := json.Marshal(reply)
			if err != nil || len(data) > maxMessage {
				data = []byte(`{"error":"unavailable"}`)
			}
			_ = message.Respond(data)
		})
		if err != nil {
			_ = closeSubscriptions()
			return nil, err
		}
		subscriptions = append(subscriptions, sub)
		if err := sub.SetPendingLimits(128, 8<<20); err != nil {
			_ = closeSubscriptions()
			return nil, err
		}
	}
	if err := nc.FlushTimeout(5 * time.Second); err != nil {
		_ = closeSubscriptions()
		return nil, err
	}
	service := &Service{done: make(chan struct{}), close: closeSubscriptions}
	context.AfterFunc(ctx, func() { _ = service.Close() })
	return service, nil
}

// LifecycleIngressConfig separates local worker identity and broker credentials
// from billing. A nil connection disables that role's routes.
type LifecycleIngressConfig struct {
	PublisherConnection *nats.Conn
	BillingConnection   *nats.Conn
	PublisherUID        uint32
	BillingUID          uint32
}

func validateLifecycleIngress(c *LifecycleIngressConfig) error {
	if c == nil {
		return nil
	}
	if c.PublisherConnection == nil && c.BillingConnection == nil {
		return ErrInvalid
	}
	if c.PublisherConnection != nil && !secureConnection(c.PublisherConnection) || c.BillingConnection != nil && !secureConnection(c.BillingConnection) {
		return ErrInvalid
	}
	if c.PublisherConnection != nil && c.BillingConnection != nil && (c.PublisherUID == c.BillingUID || c.PublisherConnection == c.BillingConnection || c.PublisherConnection.Opts.Nkey == c.BillingConnection.Opts.Nkey) {
		return ErrInvalid
	}
	return nil
}
func registerLifecycleIngress(mux *http.ServeMux, c *LifecycleIngressConfig) {
	if c == nil {
		return
	}
	for path, subject := range map[string]string{
		"/internal/v1/databases/lifecycle":           LifecycleEventSubject,
		"/internal/v1/databases/inventory/freeze":    InventoryFreezeSubject,
		"/internal/v1/databases/inventory/resources": InventoryResourcesSubject,
	} {
		nc, allowedUID := c.BillingConnection, c.BillingUID
		if subject == LifecycleEventSubject {
			nc, allowedUID = c.PublisherConnection, c.PublisherUID
		}
		if nc == nil {
			continue
		}
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			uid, ok := r.Context().Value(peerUIDKey{}).(uint32)
			if !ok || uid != allowedUID {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMessage))
			if err != nil {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			opctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			message, err := nc.RequestWithContext(opctx, subject, data)
			if err != nil || len(message.Data) > maxMessage {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			var reply lifecycleResponse
			if json.Unmarshal(message.Data, &reply, json.RejectUnknownMembers(true)) != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			if reply.Error != "" {
				http.Error(w, reply.Error, lifecycleStatus(reply.Error))
				return
			}
			var payload any
			switch subject {
			case LifecycleEventSubject:
				if reply.Applied && reply.Snapshot == nil && reply.Inventory == nil {
					payload = struct {
						Applied bool `json:"applied"`
					}{true}
				}
			case InventoryFreezeSubject:
				if !reply.Applied && reply.Snapshot != nil && reply.Inventory == nil {
					payload = reply.Snapshot
				}
			case InventoryResourcesSubject:
				if !reply.Applied && reply.Snapshot == nil && reply.Inventory != nil {
					payload = reply.Inventory
				}
			}
			if payload == nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			body, err := json.Marshal(payload)
			if err != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		})
	}
}
