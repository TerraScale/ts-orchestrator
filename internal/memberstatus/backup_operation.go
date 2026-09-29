package memberstatus

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const maxBackupOperationBytes = 64 << 10

// Rust may spend two sequential 60-second stages draining and publishing a
// final Cut. Abort can wait behind that same member operation gate.
const backupOperationTimeout = 150 * time.Second

var ErrBackupOperationNotFound = errors.New("member backup operation is not retained")

type BackupFrontierRow struct {
	Origin          string `json:"origin"`
	AppliedSequence uint64 `json:"applied_sequence"`
}

// BackupOperationStatus is process-bound member evidence. The controller must
// still compare it to its committed R3 allocation and roster acknowledgments.
type BackupOperationStatus struct {
	Version               uint64              `json:"version"`
	OperationID           string              `json:"operation_id"`
	Nonce                 string              `json:"nonce"`
	State                 string              `json:"state"`
	BackupSet             string              `json:"backup_set"`
	Ordinal               uint64              `json:"ordinal"`
	Attempt               uint64              `json:"attempt"`
	SourceScopeDigest     string              `json:"source_scope_digest"`
	SourceAuthoritySHA256 string              `json:"source_authority_sha256"`
	SourceTargetDigest    string              `json:"source_target_digest"`
	BackupTargetDigest    string              `json:"backup_target_digest"`
	SourceCutAtMS         uint64              `json:"source_cut_at_ms"`
	CompletedAtMS         uint64              `json:"completed_at_ms"`
	PointSHA256           string              `json:"point_sha256"`
	ClosureSHA256         string              `json:"closure_sha256"`
	CatalogHeadSHA256     string              `json:"catalog_head_sha256"`
	SelectedFrontier      []BackupFrontierRow `json:"selected_frontier"`
	ErrorCode             string              `json:"error_code"`
}

// BackupPrepare returns the exact leaf-signed Cut produced by the bound
// native process. Signature and roster verification belongs to the controller.
func (c *Client) BackupPrepare(ctx context.Context, envelope []byte) ([]byte, error) {
	if len(envelope) == 0 || len(envelope) > maxBackupOperationBytes {
		return nil, errors.New("backup Prepare envelope exceeds bound")
	}
	code, body, _, err := c.exchangeBounded(ctx, http.MethodPost, "/v1/backup/prepare",
		envelope, maxBackupOperationBytes, backupOperationTimeout)
	if err != nil {
		return nil, errors.Join(ErrOutcomeUnknown, err)
	}
	if code == http.StatusConflict {
		return nil, ErrOperationConflict
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("member backup Prepare HTTP %d", code)
	}
	var signed struct {
		Version   uint64 `json:"version"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &signed, json.RejectUnknownMembers(true)); err != nil ||
		signed.Version != 1 || signed.Payload == "" || signed.Signature == "" {
		return nil, errors.New("member backup Cut envelope is invalid")
	}
	return body, nil
}

// BackupAbort sends only an R3-committed signed Release. The caller supplies
// that exact envelope and reconciles a timeout through per-operation status.
func (c *Client) BackupAbort(ctx context.Context, envelope []byte) error {
	if len(envelope) == 0 || len(envelope) > maxBackupOperationBytes {
		return errors.New("backup Abort envelope exceeds bound")
	}
	code, body, _, err := c.exchangeBounded(ctx, http.MethodPost, "/v1/backup/release",
		envelope, 4096, backupOperationTimeout)
	if err != nil {
		return errors.Join(ErrOutcomeUnknown, err)
	}
	if code == http.StatusConflict {
		return ErrOperationConflict
	}
	if code != http.StatusOK {
		return fmt.Errorf("member backup Abort HTTP %d", code)
	}
	var released struct {
		Version uint64 `json:"version"`
		State   string `json:"state"`
	}
	if err := json.Unmarshal(body, &released, json.RejectUnknownMembers(true)); err != nil ||
		released.Version != 1 || released.State != "released" {
		return errors.New("member backup Abort acknowledgment is invalid")
	}
	canonical, err := json.Marshal(released)
	if err != nil || !bytes.Equal(canonical, body) {
		return errors.New("member backup Abort acknowledgment is not canonical")
	}
	return nil
}

func (c *Client) BackupOperationStatus(ctx context.Context, operationID string) (BackupOperationStatus, error) {
	if !canonicalUUID(operationID) {
		return BackupOperationStatus{}, errors.New("backup operation ID is invalid")
	}
	code, body, _, err := c.exchangeBounded(ctx, http.MethodGet,
		"/v1/backup/operations/"+operationID, nil, maxBackupOperationBytes, 5*time.Second)
	if err != nil {
		return BackupOperationStatus{}, err
	}
	if code == http.StatusNotFound {
		return BackupOperationStatus{}, ErrBackupOperationNotFound
	}
	if code != http.StatusOK {
		return BackupOperationStatus{}, fmt.Errorf("member backup status HTTP %d", code)
	}
	var status BackupOperationStatus
	if err := json.Unmarshal(body, &status, json.RejectUnknownMembers(true)); err != nil ||
		status.Version != 1 || status.OperationID != operationID ||
		(status.State != "pending" && status.State != "complete" &&
			status.State != "failed" && status.State != "uncertain") ||
		status.Ordinal == 0 || status.Attempt == 0 {
		return BackupOperationStatus{}, errors.New("member backup status is invalid")
	}
	return status, nil
}
