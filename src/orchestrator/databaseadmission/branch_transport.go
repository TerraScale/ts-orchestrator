package databaseadmission

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

// BranchRestoreRequest names the immutable admission and an authority challenge.
// The engine must persist its selected source snapshot under AuthorityOperationID
// before copying, and replay that same source after an unknown effect outcome.
type BranchRestoreRequest struct {
	Capture              bool          `json:"capture,omitzero"`
	Source               *BranchSource `json:"source,omitempty"`
	Admission            Admission     `json:"admission"`
	AuthorityOperationID string        `json:"authority_operation_id"`
	Nonce                string        `json:"nonce"`
}

func BranchRestoreSubject(identity string) (string, error) {
	subject, err := HostSubject(identity)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(subject, ".install") + ".branch_restore", nil
}

// RemoteBranchRestore collects signed durable restore evidence from every
// admitted child replica. The pipeline verifies signatures and cross-replica
// snapshot agreement before it authorizes serving placement.
func RemoteBranchRestore(nc *nats.Conn) func(context.Context, Record, string) ([]SignedReadiness, error) {
	return func(ctx context.Context, record Record, nonce string) ([]SignedReadiness, error) {
		if !secureConnection(nc) || ValidateRecord(record) != nil || record.Request.ParentDatabaseID == "" || !validDigest(nonce) {
			return nil, ErrInvalid
		}
		receipts := make([]SignedReadiness, 0, len(record.Targets))
		for _, target := range record.Targets {
			subject, err := BranchRestoreSubject(target.ServerIdentity)
			if err != nil {
				return nil, err
			}
			data, err := json.Marshal(BranchRestoreRequest{Source: record.BranchSource, Admission: Admission{CreatedAt: record.CreatedAt, Request: record.Request, DatabaseID: record.DatabaseID, KeyVersion: record.KeyVersion, Region: target.Region, MemberID: target.MemberID}, AuthorityOperationID: PlacementOperationID(record.Request), Nonce: nonce})
			if err != nil || len(data) > maxMessage {
				return nil, ErrInvalid
			}
			opctx, cancel := context.WithTimeout(ctx, 55*time.Second)
			reply, err := nc.RequestWithContext(opctx, subject, data)
			cancel()
			if err != nil {
				return nil, err
			}
			if len(reply.Data) > maxMessage {
				return nil, ErrInvalid
			}
			var receipt SignedReadiness
			if json.Unmarshal(reply.Data, &receipt, json.RejectUnknownMembers(true)) != nil || len(receipt.Payload) == 0 {
				return nil, errors.New("database branch: restore unresolved")
			}
			receipts = append(receipts, receipt)
		}
		return receipts, nil
	}
}

func validateBranchRestoreRequest(c HostConfig, request BranchRestoreRequest) error {
	a := request.Admission
	if a.CreatedAt.IsZero() || ValidateRequest(a.Request) != nil || a.ParentDatabaseID == "" || a.ParentDatabaseID == a.DatabaseID || a.Environment != c.Environment || a.Region != c.Region || a.MemberID != c.MemberID || !canonicalID.MatchString(a.DatabaseID) || !canonicalID.MatchString(a.KeyVersion) || !slices.Contains(a.Regions, a.Region) || request.AuthorityOperationID != PlacementOperationID(a.Request) || !validDigest(request.Nonce) {
		return ErrInvalid
	}
	if request.Capture {
		if request.Source != nil {
			return ErrInvalid
		}
	} else {
		if _, err := validateBranchSource(Record{Request: a.Request, DatabaseID: a.DatabaseID, KeyVersion: a.KeyVersion}, request.Source, nil, time.Time{}); err != nil {
			return err
		}
	}
	return nil
}

// StartBranchRestoreHost proxies only this admitted host's authority subject to
// its UID-pinned engine socket. It never substitutes a transport acknowledgment
// for the engine's signed restored-snapshot evidence.
func StartBranchRestoreHost(ctx context.Context, c HostConfig) (*Service, error) {
	if ctx == nil || !secureConnection(c.Connection) || !filepath.IsAbs(c.EngineSocket) {
		return nil, ErrInvalid
	}
	subject, err := BranchRestoreSubject(c.ServerIdentity)
	if err != nil {
		return nil, err
	}
	identity := strings.Split(strings.TrimPrefix(c.ServerIdentity, "spiffe://terrascale.tech/"), "/")
	if identity[0] != c.Environment || identity[3] != c.MemberID {
		return nil, ErrInvalid
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, "unix", c.EngineSocket)
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(connection)
		if err != nil || uid != c.EngineUID {
			_ = connection.Close()
			return nil, ErrForbidden
		}
		return connection, nil
	}}
	client := &http.Client{Transport: transport, Timeout: 50 * time.Second}
	sub, err := c.Connection.Subscribe(subject, func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) > maxMessage {
			return
		}
		var request BranchRestoreRequest
		if json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)) != nil || validateBranchRestoreRequest(c, request) != nil {
			_ = message.Respond([]byte(`{"error":"invalid"}`))
			return
		}
		opctx, cancel := context.WithTimeout(ctx, 50*time.Second)
		defer cancel()
		endpoint := "http://unix/internal/v1/databases/branch-restore"
		if request.Capture {
			endpoint = "http://unix/internal/v1/databases/branch-source"
		}
		req, err := http.NewRequestWithContext(opctx, http.MethodPost, endpoint, bytes.NewReader(message.Data))
		if err != nil {
			_ = message.Respond([]byte(`{"error":"unavailable"}`))
			return
		}
		req.Header.Set("Content-Type", "application/json")
		reply, err := client.Do(req)
		if err != nil {
			_ = message.Respond([]byte(`{"error":"unavailable"}`))
			return
		}
		defer reply.Body.Close()
		data, err := io.ReadAll(io.LimitReader(reply.Body, maxMessage+1))
		var receipt SignedReadiness
		if err != nil || reply.StatusCode != http.StatusOK || len(data) > maxMessage || json.Unmarshal(data, &receipt, json.RejectUnknownMembers(true)) != nil || len(receipt.Payload) == 0 {
			_ = message.Respond([]byte(`{"error":"unavailable"}`))
			return
		}
		_ = message.Respond(data)
	})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	if err = sub.SetPendingLimits(16, 4<<20); err != nil {
		_ = sub.Unsubscribe()
		transport.CloseIdleConnections()
		return nil, err
	}
	if err = c.Connection.FlushTimeout(5 * time.Second); err != nil {
		_ = sub.Unsubscribe()
		transport.CloseIdleConnections()
		return nil, err
	}
	service := &Service{done: make(chan struct{}), close: func() error { transport.CloseIdleConnections(); return sub.Unsubscribe() }}
	context.AfterFunc(ctx, func() { _ = service.Close() })
	return service, nil
}

func RemoteBranchSource(nc *nats.Conn) func(context.Context, Record, Record, string) (SignedReadiness, error) {
	return func(ctx context.Context, child, parent Record, nonce string) (SignedReadiness, error) {
		if !secureConnection(nc) || child.Request.ParentDatabaseID != parent.DatabaseID || len(parent.Targets) == 0 || !validDigest(nonce) {
			return SignedReadiness{}, ErrInvalid
		}
		target := parent.Targets[0]
		subject, err := BranchRestoreSubject(target.ServerIdentity)
		if err != nil {
			return SignedReadiness{}, err
		}
		request := BranchRestoreRequest{Capture: true, Admission: Admission{CreatedAt: child.CreatedAt, Request: child.Request, DatabaseID: child.DatabaseID, KeyVersion: child.KeyVersion, Region: target.Region, MemberID: target.MemberID}, AuthorityOperationID: PlacementOperationID(child.Request), Nonce: nonce}
		data, err := json.Marshal(request)
		if err != nil || len(data) > maxMessage {
			return SignedReadiness{}, ErrInvalid
		}
		opctx, cancel := context.WithTimeout(ctx, 55*time.Second)
		defer cancel()
		reply, err := nc.RequestWithContext(opctx, subject, data)
		if err != nil {
			return SignedReadiness{}, err
		}
		var receipt SignedReadiness
		if len(reply.Data) > maxMessage || json.Unmarshal(reply.Data, &receipt, json.RejectUnknownMembers(true)) != nil || len(receipt.Payload) == 0 {
			return SignedReadiness{}, ErrInvalid
		}
		return receipt, nil
	}
}
