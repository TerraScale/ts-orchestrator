package databaseadmission

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission/subjects"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

const poolMessageLimit = 64 << 10

// PoolWork is persisted by the member before its host sends any control message.
type PoolWork struct {
	Request      writebudget.PoolRefillRequest `json:"request"`
	Consumptions []writebudget.PoolConsumption `json:"consumptions"`
}

const PoolRefillAuthoritySubject = subjects.PoolRefillAuthority

type PoolAuthorityRequest struct {
	ServerIdentity string   `json:"server_identity"`
	MemberID       string   `json:"member_id"`
	Work           PoolWork `json:"work"`
}
type PoolWorkReply struct {
	RefillOperationID string `json:"refill_operation_id"`
	State             string `json:"state"`
}

func PoolSubject(identity string) (string, error) {
	subject, err := HostSubject(identity)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(subject, ".install") + ".budget_refill", nil
}

// pollPool performs one bounded off-path exchange. Unknown replies deliberately
// leave the member outbox unchanged, including across host/member restart.
func pollPool(ctx context.Context, c HostConfig, client *http.Client, after string) (string, error) {
	body, _ := json.Marshal(struct {
		After string `json:"after_database"`
	}{after})
	response, err := poolLocalRequest(ctx, client, "/work", body)
	if err != nil {
		return after, err
	}
	var page struct {
		Next string    `json:"next_database"`
		Work *PoolWork `json:"work"`
	}
	if json.Unmarshal(response, &page, json.RejectUnknownMembers(true)) != nil {
		return after, ErrInvalid
	}
	if page.Work == nil {
		return page.Next, nil
	}
	request := page.Work.Request
	if request.HolderID != c.MemberID || request.Region != strings.ToLower(c.Region) || len(page.Work.Consumptions) > 64 {
		return after, ErrInvalid
	}
	subject, err := PoolSubject(c.ServerIdentity)
	if err != nil {
		return after, err
	}
	body, err = json.Marshal(page.Work)
	if err != nil || len(body) > poolMessageLimit {
		return after, ErrInvalid
	}
	reply, err := c.Connection.RequestWithContext(ctx, subject, body)
	if err != nil {
		return after, err
	}
	var ack PoolWorkReply
	if len(reply.Data) > 1024 || json.Unmarshal(reply.Data, &ack, json.RejectUnknownMembers(true)) != nil || ack.RefillOperationID != request.RefillOperationID || (ack.State != "installed" && ack.State != "reported" && ack.State != "expired") {
		return after, errors.New("pool refill outcome unknown")
	}
	body, _ = json.Marshal(struct {
		Database  string `json:"database_id"`
		Operation string `json:"refill_operation_id"`
	}{request.DatabaseID, request.RefillOperationID})
	_, err = poolLocalRequest(ctx, client, "/ack", body)
	if err != nil {
		return after, err
	}
	return page.Next, nil
}
func poolLocalRequest(ctx context.Context, client *http.Client, path string, body []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/internal/v1/databases/usage/pool"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	reply, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer reply.Body.Close()
	data, err := io.ReadAll(io.LimitReader(reply.Body, poolMessageLimit+1))
	if err != nil || len(data) > poolMessageLimit || reply.StatusCode != http.StatusOK {
		return nil, errors.New("member pool journal unavailable")
	}
	return data, nil
}
func runPoolRefills(ctx context.Context, c HostConfig, client *http.Client, done chan<- struct{}) {
	defer close(done)
	after := ""
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		// Do not probe the engine as part of host startup. Apart from adding
		// needless work, an immediate probe can race the first admission and
		// make the pool endpoint compete with the request's engine route.
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		operation, cancel := context.WithTimeout(ctx, 20*time.Second)
		next, _ := pollPool(operation, c, client, after)
		cancel()
		after = next
	}
}
