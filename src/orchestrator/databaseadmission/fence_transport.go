package databaseadmission

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"
)

type hostFenceCommand struct { Fence hostFenceRequest `json:"fence"` }
type hostFenceRequest struct {
	Record NativeAdmissionRecord `json:"record"`
	DeletionOperationID string `json:"deletion_operation_id"`
	ProjectFenceRevision uint64 `json:"project_fence_revision"`
}
type HostFenceReceipt struct {
	Record NativeAdmissionRecord `json:"record"`
	DeletionOperationID string `json:"deletion_operation_id"`
	ProjectFenceRevision uint64 `json:"project_fence_revision"`
	Outcome string `json:"outcome"`
}
type ProjectAdmissionFencer interface {
	FenceProjectAdmission(context.Context, ProjectDeletion, ProjectAdmissionTarget) (HostFenceReceipt, error)
}
type remoteProjectAdmissionFencer struct{ connection *nats.Conn }
func RemoteProjectAdmissionFencer(nc *nats.Conn) ProjectAdmissionFencer { return &remoteProjectAdmissionFencer{connection:nc} }

func (f *remoteProjectAdmissionFencer) FenceProjectAdmission(ctx context.Context, project ProjectDeletion, target ProjectAdmissionTarget) (HostFenceReceipt, error) {
	if f == nil || !secureConnection(f.connection) || !validProjectDeletionRequest(project.Request) || project.Revision == 0 || target.Record.Environment != project.Request.Environment || target.Record.TenantID != project.Request.TenantID || target.Record.ProjectID != project.Request.ProjectID { return HostFenceReceipt{}, ErrInvalid }
	payload, err := json.Marshal(hostFenceCommand{Fence:hostFenceRequest{Record:target.Record, DeletionOperationID:project.Request.OperationID, ProjectFenceRevision:project.Revision}}); if err != nil { return HostFenceReceipt{}, err }
	subject, err := HostSubject(target.ServerIdentity); if err != nil { return HostFenceReceipt{}, err }
	opctx, cancel := context.WithTimeout(ctx, 20*time.Second); defer cancel()
	message, err := f.connection.RequestWithContext(opctx, subject, payload); if err != nil { return HostFenceReceipt{}, err }
	var receipt HostFenceReceipt
	if len(message.Data) > maxMessage || json.Unmarshal(message.Data, &receipt, json.RejectUnknownMembers(true)) != nil || !sameNativeRecord(receipt.Record, target.Record) || receipt.DeletionOperationID != project.Request.OperationID || receipt.ProjectFenceRevision != project.Revision || (receipt.Outcome != "no_install" && receipt.Outcome != "stop_required") { return HostFenceReceipt{}, ErrInvalid }
	return receipt, nil
}

func hostFenceLock(path string) (func(), error) {
	f, err := os.OpenFile(path+".admission-fence.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600); if err != nil { return nil, err }
	if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil { f.Close(); return nil, errors.New("admission fence lock held") }
	return func(){ unix.Flock(int(f.Fd()), unix.LOCK_UN); f.Close() }, nil
}
func fencePath(catalog string, record NativeAdmissionRecord) string { return filepath.Join(filepath.Dir(catalog), "admission-fences", record.DatabaseID+".json") }
func hasLocalFence(catalog string, record nativeAdmissionRecord) bool { data, err := os.ReadFile(fencePath(catalog, NativeAdmissionRecord(record))); if err != nil { return false }; var receipt HostFenceReceipt; return json.Unmarshal(data, &receipt, json.RejectUnknownMembers(true)) == nil && sameNativeRecord(receipt.Record, NativeAdmissionRecord(record)) }
func persistHostFence(catalog string, receipt HostFenceReceipt) error {
	dir := filepath.Dir(fencePath(catalog, receipt.Record)); if err := os.MkdirAll(dir, 0700); err != nil { return err }
	body, err := json.Marshal(receipt); if err != nil { return err }
	f, err := os.CreateTemp(dir, ".fence-*"); if err != nil { return err }; name := f.Name(); defer os.Remove(name)
	if _, err = f.Write(body); err == nil { err = f.Sync() }; if closeErr := f.Close(); err == nil { err = closeErr }; if err != nil { return err }
	if err = os.Rename(name, fencePath(catalog, receipt.Record)); err != nil { return err }
	d, err := os.Open(dir); if err == nil { err = d.Sync(); d.Close() }; return err
}
func handleHostFence(ctx context.Context, c HostConfig, client *http.Client, message *nats.Msg) bool {
	var command hostFenceCommand
	if json.Unmarshal(message.Data, &command, json.RejectUnknownMembers(true)) != nil || command.Fence.DeletionOperationID == "" || command.Fence.ProjectFenceRevision == 0 { return false }
	unlock, err := hostFenceLock(c.CatalogPath); if err != nil { _ = message.Respond([]byte("unavailable")); return true }; defer unlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/internal/v1/databases/fence", bytes.NewReader(mustJSON(command.Fence))); if err != nil { _ = message.Respond([]byte("unavailable")); return true }; request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request); if err != nil { _ = message.Respond([]byte("unavailable")); return true }; defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMessage+1)); var receipt HostFenceReceipt
	if err != nil || response.StatusCode != http.StatusOK || len(body) > maxMessage || json.Unmarshal(body, &receipt, json.RejectUnknownMembers(true)) != nil || receipt.Record != command.Fence.Record || receipt.DeletionOperationID != command.Fence.DeletionOperationID || receipt.ProjectFenceRevision != command.Fence.ProjectFenceRevision || (receipt.Outcome != "no_install" && receipt.Outcome != "stop_required") || persistHostFence(c.CatalogPath, receipt) != nil { _ = message.Respond([]byte("unavailable")); return true }
	_ = message.Respond(body); return true
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
