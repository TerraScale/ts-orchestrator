package databaseadmission

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json/v2"
	"io"
	"net/http"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaselifecycle"
)

const InventoryFreezePath = "/internal/v1/databases/inventory/freeze"

// EnvironmentInventoryJournal checks environment and freezes in one transaction.
type EnvironmentInventoryJournal interface {
	FreezeEnvironmentInventory(context.Context, string, string, time.Time, time.Time) (databaselifecycle.Snapshot, error)
}

// NewFreezeInventoryHandler requires the inventory service credential, separate
// from lifecycle mutation credentials.
func NewFreezeInventoryHandler(journal EnvironmentInventoryJournal, environment, serviceKey string) (http.Handler, error) {
	if journal == nil || !environmentName.MatchString(environment) || len(serviceKey) < 32 {
		return nil, ErrInvalid
	}
	expected := sha256.Sum256([]byte(serviceKey))
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+InventoryFreezePath, func(w http.ResponseWriter, r *http.Request) {
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
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		var request InventoryFreezeRequest
		if json.Unmarshal(data, &request, json.RejectUnknownMembers(true)) != nil || !canonicalID.MatchString(request.OrganizationID) || request.Start.IsZero() || !request.End.After(request.Start) || request.End.After(time.Now()) {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		snapshot, err := journal.FreezeEnvironmentInventory(ctx, environment, request.OrganizationID, request.Start, request.End)
		if err != nil {
			code := lifecycleError(err)
			http.Error(w, code, lifecycleStatus(code))
			return
		}
		if snapshot.Environment != environment || snapshot.OrganizationID != request.OrganizationID || !snapshot.Start.Equal(request.Start) || !snapshot.End.Equal(request.End) || snapshot.Digest == "" || snapshot.Revision == 0 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		for _, resource := range snapshot.Resources {
			if resource.Environment != environment || resource.OrganizationID != request.OrganizationID {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		body, err := json.Marshal(snapshot)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	return mux, nil
}
