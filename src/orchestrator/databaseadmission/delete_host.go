package databaseadmission

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"github.com/nats-io/nats.go"
	"io"
	"net/http"
	"time"
)

type hostDeletionRequest struct {
	Stop     DeletionStop `json:"stop"`
	MemberID string       `json:"member_id"`
}
type hostDeletionReceipt struct {
	DeletionReceipt
	MemberID string `json:"member_id"`
}
type remoteDeletionStopper struct {
	connection *nats.Conn
	journal    Journal
}

func RemoteDeletionStopper(nc *nats.Conn, j Journal) DeletionStopper {
	return &remoteDeletionStopper{nc, j}
}
func (s *remoteDeletionStopper) StopDeletion(ctx context.Context, stop DeletionStop) (DeletionReceipt, error) {
	if !secureConnection(s.connection) || s.journal == nil {
		return DeletionReceipt{}, ErrInvalid
	}
	records, err := s.journal.List(ctx)
	if err != nil {
		return DeletionReceipt{}, err
	}
	for _, r := range records {
		if r.Request.Environment != stop.Environment || r.Request.TenantID != stop.OrganizationID || r.Request.ProjectID != stop.ProjectID || r.DatabaseID != stop.DatabaseID {
			continue
		}
		count := 0
		seen := map[string]bool{}
		for _, target := range r.Targets {
			if target.Region != stop.Region {
				continue
			}
			if seen[target.MemberID] {
				return DeletionReceipt{}, ErrInvalid
			}
			seen[target.MemberID] = true
			subject, err := HostSubject(target.ServerIdentity)
			if err != nil {
				return DeletionReceipt{}, err
			}
			data, err := json.Marshal(hostDeletionRequest{stop, target.MemberID})
			if err != nil {
				return DeletionReceipt{}, err
			}
			opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			message, err := s.connection.RequestWithContext(opctx, subject, data)
			cancel()
			if err != nil {
				return DeletionReceipt{}, err
			}
			var receipt hostDeletionReceipt
			if len(message.Data) > maxMessage || json.Unmarshal(message.Data, &receipt, json.RejectUnknownMembers(true)) != nil || receipt.MemberID != target.MemberID || !validStopReceipt(stop, receipt.DeletionReceipt) {
				return DeletionReceipt{}, ErrInvalid
			}
			count++
		}
		if count != 2 {
			return DeletionReceipt{}, ErrConflict
		}
		return DeletionReceipt{DeletionStop: stop, AccessRevoked: true, UsageStopped: true}, nil
	}
	return DeletionReceipt{}, ErrConflict
}
func handleHostDeletion(ctx context.Context, c HostConfig, client *http.Client, message *nats.Msg) bool {
	var envelope map[string]any
	if json.Unmarshal(message.Data, &envelope) != nil || envelope["stop"] == nil {
		return false
	}
	var r hostDeletionRequest
	if json.Unmarshal(message.Data, &r, json.RejectUnknownMembers(true)) != nil || r.MemberID != c.MemberID || r.Stop.Environment != c.Environment || r.Stop.Region != c.Region || !canonicalID.MatchString(r.Stop.DatabaseID) || !canonicalID.MatchString(r.Stop.OrganizationID) || !canonicalID.MatchString(r.Stop.ProjectID) || r.Stop.OperationID == "" || r.Stop.Cutoff.IsZero() || r.Stop.Cutoff.Nanosecond()%int(time.Millisecond) != 0 || r.Stop.RetainUntil.Before(r.Stop.Cutoff) {
		_ = message.Respond([]byte("invalid"))
		return true
	}
	body, _ := json.Marshal(struct {
		DeletionStop
		MemberID string `json:"member_id"`
	}{r.Stop, r.MemberID})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/internal/v1/databases/stop", bytes.NewReader(body))
	if err != nil {
		_ = message.Respond([]byte("unavailable"))
		return true
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		_ = message.Respond([]byte("unavailable"))
		return true
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxMessage+1))
	var receipt hostDeletionReceipt
	if err != nil || response.StatusCode != http.StatusOK || len(data) > maxMessage || json.Unmarshal(data, &receipt, json.RejectUnknownMembers(true)) != nil || receipt.MemberID != r.MemberID || !validStopReceipt(r.Stop, receipt.DeletionReceipt) {
		_ = message.Respond([]byte("unavailable"))
		return true
	}
	_ = message.Respond(data)
	return true
}
