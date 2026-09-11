package databaseadmission

import (
	"strings"
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"slices"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

// BudgetAllocationDelivery distinguishes signed budget installation from the
// other commands on the existing host-scoped, GRU-only installation subject.
// The engine verifies the signed bytes against its admitted placement and key.
type BudgetAllocationDelivery struct {
	Allocation writebudget.SignedAllocation `json:"write_budget_allocation"`
}

// BudgetPoolRefillDelivery carries the schema-2 refill document over the
// existing host-scoped authenticated NATS subject. The host identity and
// accepted writer checks remain transport and placement authority; the Rust
// member verifies the detached signature before persisting the refill.
type BudgetPoolRefillDelivery struct {
	Allocation writebudget.SignedPoolAllocation `json:"write_budget_pool_refill"`
}

func handleHostBudgetPoolRefill(ctx context.Context, c HostConfig, client *http.Client, message *nats.Msg) bool {
	if len(message.Data) > usageMessageLimit {
		return false
	}
	var delivery BudgetPoolRefillDelivery
	if json.Unmarshal(message.Data, &delivery, json.RejectUnknownMembers(true)) != nil || len(delivery.Allocation.Payload) == 0 {
		return false
	}
	var envelope writebudget.AllocationEnvelopeV2
	grant := &envelope.Grant
	localRegion := strings.ToLower(c.Region)
	if delivery.Allocation.KeyID == "" || len(delivery.Allocation.Signature) == 0 || json.Unmarshal(delivery.Allocation.Payload, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.SchemaVersion != 2 || grant.SchemaVersion != 2 || grant.Kind != "regional_write_pool_refill" || grant.HolderID != c.MemberID || grant.Region != localRegion || !slices.Contains(grant.Regions, localRegion) {
		_ = message.Respond([]byte("invalid"))
		return true
	}
	data, err := json.Marshal(delivery.Allocation)
	if err != nil || len(data) > usageMessageLimit {
		_ = message.Respond([]byte("invalid"))
		return true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/internal/v1/databases/usage/allocation", bytes.NewReader(data))
	if err != nil {
		_ = message.Respond([]byte("unavailable"))
		return true
	}
	req.Header.Set("Content-Type", "application/json")
	reply, err := client.Do(req)
	if err != nil {
		_ = message.Respond([]byte("unavailable"))
		return true
	}
	defer reply.Body.Close()
	body, err := io.ReadAll(io.LimitReader(reply.Body, usageMessageLimit+1))
	if err != nil || reply.StatusCode != http.StatusOK || len(body) != 0 {
		_ = message.Respond([]byte("unavailable"))
		return true
	}
	_ = message.Respond([]byte("installed"))
	return true
}

func handleHostBudgetAllocation(ctx context.Context, c HostConfig, client *http.Client, message *nats.Msg) bool {
	if len(message.Data) > usageMessageLimit {
		return false
	}
	var delivery BudgetAllocationDelivery
	if json.Unmarshal(message.Data, &delivery, json.RejectUnknownMembers(true)) != nil || len(delivery.Allocation.Payload) == 0 {
		return false
	}
	var envelope writebudget.AllocationEnvelope
	if delivery.Allocation.KeyID == "" || len(delivery.Allocation.Signature) == 0 || json.Unmarshal(delivery.Allocation.Payload, &envelope, json.RejectUnknownMembers(true)) != nil || envelope.SchemaVersion != 1 || envelope.Grant.HolderID != c.MemberID || !slices.Contains(envelope.Grant.Regions, c.Region) {
		_ = message.Respond([]byte("invalid"))
		return true
	}
	data, err := json.Marshal(delivery.Allocation)
	if err != nil || len(data) > usageMessageLimit {
		_ = message.Respond([]byte("invalid"))
		return true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/internal/v1/databases/usage/allocation", bytes.NewReader(data))
	if err != nil {
		_ = message.Respond([]byte("unavailable"))
		return true
	}
	req.Header.Set("Content-Type", "application/json")
	reply, err := client.Do(req)
	if err != nil {
		_ = message.Respond([]byte("unavailable"))
		return true
	}
	defer reply.Body.Close()
	body, err := io.ReadAll(io.LimitReader(reply.Body, usageMessageLimit+1))
	if err != nil || reply.StatusCode != http.StatusOK || len(body) != 0 {
		_ = message.Respond([]byte("unavailable"))
		return true
	}
	_ = message.Respond([]byte("installed"))
	return true
}
