package cli

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

type observeOperationCommit struct {
	MutationOperationID string    `json:"mutation_operation_id"`
	Sequence            uint64    `json:"sequence"`
	Epoch               uint64    `json:"epoch"`
	RecordedAt          time.Time `json:"recorded_at"`
}

type observeCredentialOperation struct {
	Cell       string                 `json:"cell"`
	Commit     observeOperationCommit `json:"commit"`
	Credential struct {
		DatabaseID        string `json:"database_id"`
		PartitionID       string `json:"partition_id"`
		InitialReceiptSHA string `json:"initial_receipt_sha256"`
		Generation        uint64 `json:"generation"`
		StateSHA256       string `json:"state_sha256"`
		Status            string `json:"status"`
		Members           []struct {
			SeatID     string `json:"seat_id"`
			MemberID   string `json:"member_id"`
			Node       string `json:"node,omitempty"`
			Generation uint64 `json:"generation,omitzero"`
			Applied    bool   `json:"applied"`
		} `json:"members"`
	} `json:"credential"`
}

type observeBackupOperation struct {
	Cell        string                 `json:"cell"`
	Commit      observeOperationCommit `json:"commit"`
	DatabaseID  string                 `json:"database_id"`
	PartitionID string                 `json:"partition_id"`
	OperationID string                 `json:"operation_id"`
	State       string                 `json:"state"`
	Ordinal     uint64                 `json:"ordinal"`
	Attempt     uint64                 `json:"attempt"`
}

type observeNetBirdOperation struct {
	Cell              string                 `json:"cell"`
	Commit            observeOperationCommit `json:"commit"`
	OperationID       string                 `json:"operation_id"`
	Node              string                 `json:"node"`
	Phase             string                 `json:"phase"`
	StartedAt         time.Time              `json:"started_at"`
	Deadline          time.Time              `json:"deadline"`
	RollbackRequired  *bool                  `json:"rollback_required,omitzero"`
	RecoveryComplete  bool                   `json:"recovery_complete"`
	RecoveryReturning bool                   `json:"recovery_returning"`
}

type observeOperationFailure struct {
	SchemaVersion int    `json:"schemaVersion,omitzero"`
	State         string `json:"state,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Error         string `json:"error,omitempty"`
}

func observeOperationPath(view, database, partition string) (string, error) {
	if view == "netbird" {
		return "/v1/operations/netbird", nil
	}
	if !entityid.Valid(database) || !entityid.Valid(partition) {
		return "", errors.New("observe credentials and backups require --database ID and --partition ID as canonical uppercase ULIDs")
	}
	return "/v1/operations/" + view + "/" + database + "/" + partition, nil
}

func observeOperationFailureJSON(view string, data []byte) (observeOperationFailure, bool) {
	var result observeOperationFailure
	if json.Unmarshal(data, &result) != nil {
		return result, false
	}
	if view == "foundation" {
		ok := result.SchemaVersion == 1 && result.State == "unavailable" &&
			(result.Reason == "foundation-record-missing" || result.Reason == "foundation-observation-unavailable")
		return observeOperationFailure{SchemaVersion: result.SchemaVersion, State: result.State, Reason: result.Reason}, ok
	}
	return observeOperationFailure{Error: result.Error}, result.Error == "invalid_request" || result.Error == "operation_not_found" || result.Error == "operation_unavailable"
}

func observeOperationError(path string, status int, data []byte) bool {
	view := ""
	if strings.HasPrefix(path, "/v1/regions/") && strings.HasSuffix(path, "/foundation") && status == http.StatusServiceUnavailable {
		view = "foundation"
	} else if strings.HasPrefix(path, "/v1/operations/") && (status == http.StatusBadRequest || status == http.StatusNotFound || status == http.StatusServiceUnavailable) {
		view = "operation"
	} else {
		return false
	}
	_, ok := observeOperationFailureJSON(view, data)
	return ok
}

func writeObserveOperation(out io.Writer, view, format string, data []byte) (any, bool, error) {
	if failure, ok := observeOperationFailureJSON(view, data); ok {
		if format == "table" {
			fmt.Fprintf(out, "STATE\tunavailable\tREASON\t%s%s\n", failure.Reason, failure.Error)
		}
		return failure, true, nil
	}
	if view == "foundation" {
		var result region.FoundationObservation
		if err := json.Unmarshal(data, &result); err != nil || result.SchemaVersion != 1 || result.Cell == "" || result.OCIRegion == "" ||
			!entityid.Valid(result.OperationID) || result.Generation == 0 || result.Epoch == 0 || result.Stage == "" || result.StartedAt.IsZero() || result.UpdatedAt.IsZero() {
			return nil, false, errors.New("invalid foundation observation JSON")
		}
		if format == "table" {
			fmt.Fprintf(out, "CELL\t%s\tOCI REGION\t%s\tOPERATION\t%s\tGENERATION\t%d\tEPOCH\t%d\nSTAGE\t%s\tREASON\t%s\nSTARTED\t%s\tUPDATED\t%s\tCOMPLETED\t%s\n", result.Cell, result.OCIRegion, result.OperationID, result.Generation, result.Epoch, result.Stage, result.Reason, observeOperationTime(result.StartedAt), observeOperationTime(result.UpdatedAt), observeOperationTime(result.CompletedAt))
			fmt.Fprintln(out, "KIND\tKEY\tRESOURCE\tORIGINAL OPERATION\tGENERATION\tFIRST ATTEMPT")
			for _, checkpoint := range result.Checkpoints {
				generation := "unknown"
				if checkpoint.Generation != 0 {
					generation = fmt.Sprint(checkpoint.Generation)
				}
				fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\n", checkpoint.Kind, checkpoint.Key, checkpoint.ResourceID, checkpoint.OperationID, generation, observeOperationTime(checkpoint.FirstAttemptAt))
			}
		}
		return result, result.Stage == "unknown" || result.Stage == "unavailable", nil
	}
	var header struct {
		Cell   string                 `json:"cell"`
		Commit observeOperationCommit `json:"commit"`
	}
	if err := json.Unmarshal(data, &header); err != nil || header.Cell == "" || !entityid.Valid(header.Commit.MutationOperationID) || header.Commit.Sequence == 0 || header.Commit.Epoch == 0 || header.Commit.RecordedAt.IsZero() {
		return nil, false, errors.New("invalid committed operation observation JSON")
	}
	var result any
	state := ""
	switch view {
	case "credentials":
		var value observeCredentialOperation
		if err := json.Unmarshal(data, &value); err != nil || !entityid.Valid(value.Credential.DatabaseID) || !entityid.Valid(value.Credential.PartitionID) || value.Credential.Generation < 2 || value.Credential.Status == "" || len(value.Credential.Members) != 2 {
			return nil, false, errors.New("invalid credential operation observation JSON")
		}
		result, state = value, value.Credential.Status
		if format == "table" {
			credential := value.Credential
			fmt.Fprintf(out, "DATABASE\t%s\tPARTITION\t%s\tGENERATION\t%d\tSTATUS\t%s\nINITIAL RECEIPT SHA256\t%s\nSTATE SHA256\t%s\n", credential.DatabaseID, credential.PartitionID, credential.Generation, credential.Status, credential.InitialReceiptSHA, credential.StateSHA256)
			fmt.Fprintln(out, "SEAT\tMEMBER\tNODE\tGENERATION\tAPPLIED")
			for _, member := range credential.Members {
				generation := "unknown"
				if member.Generation != 0 {
					generation = fmt.Sprint(member.Generation)
				}
				fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%t\n", member.SeatID, member.MemberID, member.Node, generation, member.Applied)
			}
		}
	case "backups":
		var value observeBackupOperation
		if err := json.Unmarshal(data, &value); err != nil || !entityid.Valid(value.DatabaseID) || !entityid.Valid(value.PartitionID) || !entityid.Valid(value.OperationID) || value.State == "" {
			return nil, false, errors.New("invalid backup operation observation JSON")
		}
		result, state = value, value.State
		if format == "table" {
			fmt.Fprintf(out, "DATABASE\t%s\tPARTITION\t%s\tOPERATION\t%s\tSTATE\t%s\tORDINAL\t%d\tATTEMPT\t%d\n", value.DatabaseID, value.PartitionID, value.OperationID, value.State, value.Ordinal, value.Attempt)
		}
	case "netbird":
		var value observeNetBirdOperation
		if err := json.Unmarshal(data, &value); err != nil || !entityid.Valid(value.OperationID) || value.Phase == "" {
			return nil, false, errors.New("invalid NetBird operation observation JSON")
		}
		result, state = value, value.Phase
		if format == "table" {
			rollback := "unknown"
			if value.RollbackRequired != nil {
				rollback = fmt.Sprint(*value.RollbackRequired)
			}
			fmt.Fprintf(out, "OPERATION\t%s\tNODE\t%s\tPHASE\t%s\nSTARTED\t%s\tDEADLINE\t%s\nROLLBACK REQUIRED\t%s\tRECOVERY COMPLETE\t%t\tRECOVERY RETURNING\t%t\n", value.OperationID, value.Node, value.Phase, observeOperationTime(value.StartedAt), observeOperationTime(value.Deadline), rollback, value.RecoveryComplete, value.RecoveryReturning)
		}
	}
	if format == "table" {
		fmt.Fprintf(out, "CELL\t%s\tMUTATION OPERATION\t%s\tSEQUENCE\t%d\tEPOCH\t%d\nLOG RECORDED AT\t%s (commit time)\n", header.Cell, header.Commit.MutationOperationID, header.Commit.Sequence, header.Commit.Epoch, observeOperationTime(header.Commit.RecordedAt))
	}
	return result, state == "unknown" || state == "unavailable", nil
}

func observeOperationTime(value time.Time) string {
	if value.IsZero() {
		return "unknown"
	}
	return value.Format(time.RFC3339Nano)
}
