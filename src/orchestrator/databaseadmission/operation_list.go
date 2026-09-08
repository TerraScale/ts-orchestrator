package databaseadmission

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission/subjects"
)

// OperationPage is a read-only projection of the authoritative admission journal.
// Coverage is explicit: other owners' journals are not silently represented here.
type OperationPage struct {
	Environment  string             `json:"environment"`
	TenantID     string             `json:"tenant_id"`
	ProjectID    string             `json:"project_id"`
	Operations   []OperationSummary `json:"operations"`
	NextCursor   string             `json:"next_cursor,omitempty"`
	CoveredKinds []string           `json:"covered_kinds"`
}
type OperationSummary struct {
	OperationID        string    `json:"operation_id"`
	Kind               string    `json:"kind"`
	DatabaseID         string    `json:"database_id"`
	Name               string    `json:"name"`
	State              string    `json:"state"`
	Stage              string    `json:"stage"`
	CreatedAt          time.Time `json:"created_at"`
	Revision           uint64    `json:"revision"`
	Cancellable        bool      `json:"cancellable"`
	CancellationReason string    `json:"cancellation_reason"`
}
type OperationListRequest struct {
	Environment string `json:"environment"`
	TenantID    string `json:"tenant_id"`
	ProjectID   string `json:"project_id"`
	After       string `json:"after,omitempty"`
	Limit       int    `json:"limit"`
}

func (r OperationListRequest) cursorScope() string {
	data, _ := json.Marshal([]string{r.Environment, r.TenantID, r.ProjectID})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
func (r OperationListRequest) validate() (string, error) {
	if !environmentName.MatchString(r.Environment) || !canonicalID.MatchString(r.TenantID) || !canonicalID.MatchString(r.ProjectID) || r.Limit < 1 || r.Limit > 50 {
		return "", ErrInvalid
	}
	if r.After == "" {
		return "", nil
	}
	if len(r.After) > 256 {
		return "", ErrInvalid
	}
	data, err := base64.RawURLEncoding.DecodeString(r.After)
	if err != nil {
		return "", ErrInvalid
	}
	scope, key, ok := strings.Cut(string(data), ":")
	decoded, err := hex.DecodeString(key)
	if !ok || scope != r.cursorScope() || err != nil || len(decoded) != 32 {
		return "", ErrInvalid
	}
	return key, nil
}
func (p *Pipeline) ListOperations(ctx context.Context, request OperationListRequest) (OperationPage, error) {
	page := OperationPage{Environment: request.Environment, TenantID: request.TenantID, ProjectID: request.ProjectID, Operations: []OperationSummary{}, CoveredKinds: []string{"database_create", "branch_create"}}
	after, err := request.validate()
	if err != nil {
		return page, err
	}
	records, err := p.config.Journal.List(ctx)
	if err != nil {
		return page, err
	}
	// Journal snapshots already have a fixed encoded size ceiling. Retain only
	// matching scope; no global contents enter the response or its cursor.
	records = slices.DeleteFunc(records, func(record Record) bool {
		r := record.Request
		return r.Environment != request.Environment || r.TenantID != request.TenantID || r.ProjectID != request.ProjectID || ScopeKey(r) <= after
	})
	slices.SortFunc(records, func(a, b Record) int { return cmp.Compare(ScopeKey(a.Request), ScopeKey(b.Request)) })
	pageRecords := records
	if len(pageRecords) > request.Limit {
		pageRecords = pageRecords[:request.Limit]
	}
	// Authorize the complete matching snapshot before returning a page. This
	// keeps a forbidden record from being hidden behind a continuation cursor.
	for _, record := range records {
		if err := p.config.Authorize(ctx, record.Request); err != nil {
			return OperationPage{}, err
		}
	}
	for _, record := range pageRecords {
		kind, state := "database_create", "running"
		if record.Request.ParentDatabaseID != "" {
			kind = "branch_create"
		}
		if record.State == "accepted" {
			state = "queued"
		}
		if record.State == "ready" {
			state = "succeeded"
		}
		page.Operations = append(page.Operations, OperationSummary{OperationID: record.Request.OperationID, Kind: kind, DatabaseID: record.DatabaseID, Name: record.Request.Name, State: state, Stage: record.State, CreatedAt: record.CreatedAt, Revision: record.Revision, CancellationReason: "Provisioning has no safe cancellation action"})
	}
	if len(records) > len(pageRecords) {
		last := pageRecords[len(pageRecords)-1]
		page.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(request.cursorScope() + ":" + ScopeKey(last.Request)))
	}
	return page, nil
}

type operationListReply struct {
	Result *OperationPage `json:"result,omitempty"`
	Error  string         `json:"error,omitempty"`
}

func subscribeOperationList(ctx context.Context, nc *nats.Conn, pipeline *Pipeline) (*nats.Subscription, error) {
	return nc.Subscribe(subjects.OperationList, func(message *nats.Msg) {
		if len(message.Data) > 16<<10 || message.Reply == "" {
			return
		}
		opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		var request OperationListRequest
		reply := operationListReply{}
		err := json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true))
		if err == nil {
			var page OperationPage
			page, err = pipeline.ListOperations(opctx, request)
			if err == nil {
				reply.Result = &page
			}
		}
		if err != nil {
			reply.Error = "unavailable"
			if errors.Is(err, ErrInvalid) {
				reply.Error = "invalid"
			}
			if errors.Is(err, ErrForbidden) {
				reply.Error = "forbidden"
			}
		}
		data, _ := json.Marshal(reply)
		_ = message.Respond(data)
	})
}
func registerOperationListIngress(mux *http.ServeMux, c IngressConfig) {
	mux.HandleFunc("POST /internal/v1/operations/list", func(w http.ResponseWriter, r *http.Request) {
		uid, ok := r.Context().Value(peerUIDKey{}).(uint32)
		if !ok || uid != c.AllowedUID {
			http.Error(w, "forbidden", 403)
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
		var request OperationListRequest
		if err != nil || json.Unmarshal(data, &request, json.RejectUnknownMembers(true)) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		if _, err = request.validate(); err != nil {
			http.Error(w, "invalid", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		message, err := c.Connection.RequestWithContext(ctx, subjects.OperationList, data)
		if err != nil || len(message.Data) > maxMessage {
			http.Error(w, "unavailable", 503)
			return
		}
		var reply operationListReply
		if json.Unmarshal(message.Data, &reply) != nil || reply.Result == nil {
			code := 503
			if reply.Error == "invalid" {
				code = 400
			}
			if reply.Error == "forbidden" {
				code = 403
			}
			http.Error(w, "operation discovery unavailable", code)
			return
		}
		body, err := json.Marshal(reply.Result)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
}
