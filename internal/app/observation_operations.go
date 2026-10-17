package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

var errOperationObservationUnavailable = errors.New("operation observation unavailable")

// Dependencies are borrowed from the controller; observations never own effects.
type operationObservationSources struct {
	credentials managedmaterial.CredentialService
	hosts       *host.Controller
	backup      *backupOperationRuntime
	netbird     netbirdStateReader
}

type operationObservationAPI struct {
	cell    string
	sources atomic.Pointer[operationObservationSources]
}

type operationCommitObservation struct {
	MutationOperationID string    `json:"mutation_operation_id"`
	Sequence            uint64    `json:"sequence"`
	Epoch               uint64    `json:"epoch"`
	RecordedAt          time.Time `json:"recorded_at"`
}

type credentialOperationObservation struct {
	Cell       string                        `json:"cell"`
	Commit     operationCommitObservation    `json:"commit"`
	Credential materialCredentialStatusReply `json:"credential"`
}

type backupOperationObservation struct {
	Cell        string                     `json:"cell"`
	Commit      operationCommitObservation `json:"commit"`
	DatabaseID  string                     `json:"database_id"`
	PartitionID string                     `json:"partition_id"`
	OperationID string                     `json:"operation_id"`
	State       string                     `json:"state"`
	Ordinal     uint64                     `json:"ordinal"`
	Attempt     uint64                     `json:"attempt"`
}

type netbirdOperationObservation struct {
	Cell              string                     `json:"cell"`
	Commit            operationCommitObservation `json:"commit"`
	OperationID       string                     `json:"operation_id"`
	Node              string                     `json:"node"`
	Phase             string                     `json:"phase"`
	StartedAt         time.Time                  `json:"started_at"`
	Deadline          time.Time                  `json:"deadline"`
	RollbackRequired  *bool                      `json:"rollback_required,omitzero"`
	RecoveryComplete  bool                       `json:"recovery_complete"`
	RecoveryReturning bool                       `json:"recovery_returning"`
}

func operationCommit(entry authority.LogEntry) (operationCommitObservation, error) {
	if !entityid.Valid(entry.OperationID) || entry.Sequence == 0 || entry.Epoch == 0 || entry.CreatedAt.IsZero() {
		return operationCommitObservation{}, errOperationObservationUnavailable
	}
	// RecordedAt is the committed log timestamp, not a stage-transition clock.
	return operationCommitObservation{MutationOperationID: entry.OperationID,
		Sequence: entry.Sequence, Epoch: entry.Epoch, RecordedAt: entry.CreatedAt}, nil
}

func (api *operationObservationAPI) mount(server *observability.Server) {
	server.HandleAuthenticated("GET /v1/operations/credentials/{database}/{partition}",
		http.HandlerFunc(api.credentialsHTTP))
	server.HandleAuthenticated("GET /v1/operations/backups/{database}/{partition}",
		http.HandlerFunc(api.backupHTTP))
	server.HandleAuthenticated("GET /v1/operations/netbird", http.HandlerFunc(api.netbirdHTTP))
}

func operationObservationInput(w http.ResponseWriter, r *http.Request, partitioned bool) bool {
	if r.URL.RawQuery != "" || partitioned &&
		(!entityid.Valid(r.PathValue("database")) || !entityid.Valid(r.PathValue("partition"))) {
		writeOperationObservation(w, nil, http.StatusBadRequest)
		return false
	}
	return true
}

func writeOperationObservation(w http.ResponseWriter, value any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if status != http.StatusOK {
		code := "operation_unavailable"
		if status == http.StatusBadRequest {
			code = "invalid_request"
		} else if status == http.StatusNotFound {
			code = "operation_not_found"
		}
		value = struct {
			Error string `json:"error"`
		}{code}
	}
	wire, err := json.Marshal(value)
	if err != nil {
		status, wire = http.StatusServiceUnavailable, []byte(`{"error":"operation_unavailable"}`)
	}
	w.WriteHeader(status)
	_, _ = w.Write(wire)
}

func operationObservationStatus(err error) int {
	if errors.Is(err, authority.ErrNotFound) {
		return http.StatusNotFound
	}
	if err != nil {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

func (api *operationObservationAPI) credentialsHTTP(w http.ResponseWriter, r *http.Request) {
	if !operationObservationInput(w, r, true) {
		return
	}
	sources := api.sources.Load()
	if sources == nil {
		writeOperationObservation(w, nil, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	value, err := sources.readCredentials(ctx, api.cell, r.PathValue("database"), r.PathValue("partition"))
	writeOperationObservation(w, value, operationObservationStatus(err))
}

func (sources *operationObservationSources) readCredentials(ctx context.Context, cell, database, partition string) (credentialOperationObservation, error) {
	service := sources.credentials
	if service.Store == nil || service.Preparation.Fencer == nil || sources.hosts == nil ||
		service.Preparation.Repository == nil || service.Preparation.Receipts == nil ||
		len(service.Preparation.ControllerKey) != ed25519.PrivateKeySize {
		return credentialOperationObservation{}, errOperationObservationUnavailable
	}
	entry, err := service.Store.ReadClientCredentials(ctx, database, partition)
	if err != nil {
		return credentialOperationObservation{}, err
	}
	commit, err := operationCommit(entry)
	if err != nil || entry.Kind != authority.MutationClientCredentials || entry.SubjectKey != database+"."+partition {
		return credentialOperationObservation{}, errOperationObservationUnavailable
	}
	state, receipt, err := service.Current(ctx, database, partition)
	if err != nil || receipt == nil || state.Generation < 2 {
		return credentialOperationObservation{}, errOperationObservationUnavailable
	}
	wire, err := protocol.EncodeJSON(receipt)
	if err != nil || !bytes.Equal(wire, entry.Payload) {
		return credentialOperationObservation{}, errOperationObservationUnavailable
	}
	request := materialCredentialStatusRequest{DatabaseID: database, PartitionID: partition,
		InitialReceiptSHA: state.InitialReceiptSHA256, Generation: state.Generation, OperationID: entry.OperationID}
	reply, _, _, err := readCurrentMaterialCredentialStatus(ctx, request,
		service.Preparation.Fencer.Current().Epoch, service, sources.hosts)
	if err != nil {
		return credentialOperationObservation{}, errOperationObservationUnavailable
	}
	confirmed, err := service.Store.ReadClientCredentials(ctx, database, partition)
	if err != nil || confirmed.Sequence != entry.Sequence || confirmed.OperationID != entry.OperationID ||
		confirmed.Epoch != entry.Epoch || !confirmed.CreatedAt.Equal(entry.CreatedAt) || !bytes.Equal(confirmed.Payload, entry.Payload) {
		return credentialOperationObservation{}, errOperationObservationUnavailable
	}
	return credentialOperationObservation{Cell: cell, Commit: commit, Credential: reply}, nil
}

func (api *operationObservationAPI) backupHTTP(w http.ResponseWriter, r *http.Request) {
	if !operationObservationInput(w, r, true) {
		return
	}
	sources := api.sources.Load()
	if sources == nil || sources.backup == nil || sources.backup.control == nil {
		writeOperationObservation(w, nil, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	record, entry, err := authority.ReadBackupObservation(ctx, sources.backup.control,
		r.PathValue("database"), r.PathValue("partition"))
	if err != nil {
		writeOperationObservation(w, nil, operationObservationStatus(err))
		return
	}
	commit, err := operationCommit(entry)
	if err == nil {
		err = sources.backup.producer.VerifyCommittedPublication(ctx, record)
	}
	if err != nil {
		writeOperationObservation(w, nil, http.StatusServiceUnavailable)
		return
	}
	reply := backupReplyFor(record, entry.Sequence)
	writeOperationObservation(w, backupOperationObservation{Cell: api.cell, Commit: commit,
		DatabaseID: reply.DatabaseID, PartitionID: reply.PartitionID, OperationID: reply.OperationID,
		State: reply.State, Ordinal: reply.Ordinal, Attempt: reply.Attempt}, http.StatusOK)
}

func (api *operationObservationAPI) netbirdHTTP(w http.ResponseWriter, r *http.Request) {
	if !operationObservationInput(w, r, false) {
		return
	}
	sources := api.sources.Load()
	if sources == nil || sources.netbird == nil {
		writeOperationObservation(w, nil, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	entry, err := sources.netbird.ReadNetBirdState(ctx)
	if err != nil {
		writeOperationObservation(w, nil, operationObservationStatus(err))
		return
	}
	commit, err := operationCommit(entry)
	state, decodeErr := decodeNetBirdState(entry)
	if err != nil || decodeErr != nil || state.Record.ID == "" {
		writeOperationObservation(w, nil, http.StatusServiceUnavailable)
		return
	}
	record := state.Record
	writeOperationObservation(w, netbirdOperationObservation{Cell: api.cell, Commit: commit,
		OperationID: record.ID, Node: record.Node, Phase: record.Phase, StartedAt: record.StartedAt,
		Deadline: record.Deadline, RollbackRequired: record.RollbackRequired,
		RecoveryComplete: record.RecoveryComplete, RecoveryReturning: record.RecoveryReturning}, http.StatusOK)
}
