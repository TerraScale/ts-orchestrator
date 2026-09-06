package databaseadmission

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"net/http"
	"slices"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

const InventoryPath = "/internal/v1/databases/admission-inventory"
const InventoryKeyHeader = "x-terrascale-database-admission-key"

type InventoryScope struct {
	Environment string `json:"environment"`
	TenantID    string `json:"tenant_id"`
	ProjectID   string `json:"project_id,omitempty"`
}
type InventoryOperation struct {
	OperationID string `json:"operation_id"`
	ProjectID   string `json:"project_id"`
}
type InventoryResource struct {
	databaselifecycle.Resource
	OperationID    string `json:"operation_id"`
	AdmissionState string `json:"admission_state"`
	Deleting       bool   `json:"deleting"`
	Deleted        bool   `json:"deleted"`
}
type AdmissionInventory struct {
	InventoryScope
	Revision            string               `json:"revision"`
	Complete            bool                 `json:"complete"`
	Operations          []InventoryOperation `json:"operations"`
	RetiredOperationIDs []string             `json:"retired_operation_ids"`
	Resources           []InventoryResource  `json:"resources"`
}
type InventoryJournal interface {
	AdmissionInventory(context.Context, InventoryScope) (AdmissionInventory, error)
}

func validInventoryScope(scope InventoryScope) bool {
	return environmentName.MatchString(scope.Environment) && canonicalID.MatchString(scope.TenantID) && (scope.ProjectID == "" || canonicalID.MatchString(scope.ProjectID))
}
func admissionInventory(state journalState, scope InventoryScope) (AdmissionInventory, error) {
	if !validInventoryScope(scope) {
		return AdmissionInventory{}, ErrInvalid
	}
	out := AdmissionInventory{InventoryScope: scope, Complete: true, Operations: []InventoryOperation{}, RetiredOperationIDs: []string{}, Resources: []InventoryResource{}}
	deleting := map[string]bool{}
	for _, d := range state.Deletions {
		if d.State == "stopping" {
			for _, target := range d.Targets {
				deleting[databaselifecycle.Key(target.Stop.Identity)] = true
			}
		}
	}
	for _, record := range state.Records {
		r := record.Request
		if r.Environment != scope.Environment || r.TenantID != scope.TenantID || scope.ProjectID != "" && scope.ProjectID != r.ProjectID {
			continue
		}
		key := databaselifecycle.Key(admissionLifecycleEvent(record).Identity)
		resource, ok := state.Lifecycle.Resources[key]
		if !ok {
			return AdmissionInventory{}, ErrJournalUnavailable
		}
		deleted := !resource.DeletedAt.IsZero() && resource.AccessRevoked && !resource.UsageStoppedAt.IsZero()
		out.Resources = append(out.Resources, InventoryResource{Resource: resource, OperationID: r.OperationID, AdmissionState: record.State, Deleting: deleting[key], Deleted: deleted})
		if deleted {
			out.RetiredOperationIDs = append(out.RetiredOperationIDs, r.OperationID)
		} else {
			out.Operations = append(out.Operations, InventoryOperation{OperationID: r.OperationID, ProjectID: r.ProjectID})
		}
	}
	slices.SortFunc(out.Resources, func(a, b InventoryResource) int { return cmp.Compare(a.DatabaseID, b.DatabaseID) })
	slices.SortFunc(out.Operations, func(a, b InventoryOperation) int {
		return cmp.Or(cmp.Compare(a.ProjectID, b.ProjectID), cmp.Compare(a.OperationID, b.OperationID))
	})
	slices.Sort(out.RetiredOperationIDs)
	// Digest covers this complete, atomic scoped view, including pending deletions.
	data, err := json.Marshal(out)
	if err != nil {
		return AdmissionInventory{}, err
	}
	digest := sha256.Sum256(data)
	out.Revision = hex.EncodeToString(digest[:])
	return out, nil
}
func (j *NATSJournal) AdmissionInventory(ctx context.Context, scope InventoryScope) (out AdmissionInventory, err error) {
	if j == nil || j.journal == nil {
		return out, ErrJournalUnavailable
	}
	err = j.journal.Transact(ctx, false, func(state *journalState) error { var e error; out, e = admissionInventory(*state, scope); return e })
	if err != nil {
		return AdmissionInventory{}, err
	}
	return out, nil
}
func (j *MemoryJournal) AdmissionInventory(ctx context.Context, scope InventoryScope) (AdmissionInventory, error) {
	state, err := j.snapshot(ctx)
	if err != nil {
		return AdmissionInventory{}, err
	}
	return admissionInventory(state, scope)
}

// NewInventoryHandler exposes only authenticated, environment-bound scoped views.
// The backing NATS journal performs its live GRU lease barrier for every read.
func NewInventoryHandler(journal InventoryJournal, environment, serviceKey string) (http.Handler, error) {
	if journal == nil || !environmentName.MatchString(environment) || len(serviceKey) < 32 {
		return nil, ErrInvalid
	}
	expected := sha256.Sum256([]byte(serviceKey))
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+InventoryPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 {
			http.Error(w, "HTTPS required", http.StatusBadRequest)
			return
		}
		supplied := sha256.Sum256([]byte(r.Header.Get(InventoryKeyHeader)))
		if len(r.Header.Values(InventoryKeyHeader)) != 1 || subtle.ConstantTimeCompare(expected[:], supplied[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		var scope InventoryScope
		if json.Unmarshal(data, &scope, json.RejectUnknownMembers(true)) != nil || !validInventoryScope(scope) || scope.Environment != environment {
			http.Error(w, "invalid scope", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		inventory, err := journal.AdmissionInventory(ctx, scope)
		if err != nil {
			http.Error(w, "inventory unavailable", http.StatusServiceUnavailable)
			return
		}
		body, err := json.Marshal(inventory)
		if err != nil {
			http.Error(w, "inventory unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	return mux, nil
}

// NewInventoryHTTPSServer must be served with ServeTLS/ListenAndServeTLS using
// the configured service certificate, never a plaintext reverse-proxy listener.
func NewInventoryHTTPSServer(address string, handler http.Handler) *http.Server {
	return &http.Server{Addr: address, Handler: handler, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
}
