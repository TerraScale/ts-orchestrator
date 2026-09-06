package databaseadmission

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/nats-io/nats.go"
)

const usageMessageLimit = 16 << 10

// UsageRegistration is the immutable lifecycle-approved billing stream tuple
// delivered to the receiving Terrabase member.
type UsageRegistration struct {
	SchemaVersion        uint32   `json:"schema_version"`
	Environment          string   `json:"environment"`
	TenantID             string   `json:"tenant_id"`
	ProjectID            string   `json:"project_id"`
	DatabaseID           string   `json:"database_id"`
	MemberID             string   `json:"member_id"`
	Region               string   `json:"region"`
	SelectedRegions      []string `json:"selected_regions"`
	Residency            string   `json:"residency"`
	Partition            string   `json:"partition"`
	StreamEpoch          uint64   `json:"stream_epoch"`
	PlacementProofDigest string   `json:"placement_proof_digest"`
	OperationID          string   `json:"operation_id"`
}

type usageEnvelope struct {
	Registration UsageRegistration `json:"usage_registration"`
}

type usageReceipt struct {
	UsageRegistration
	State string `json:"state"`
}

// ValidateUsageRegistration checks the protocol bounds shared with the
// Terrabase usage admission receiver.
func ValidateUsageRegistration(r UsageRegistration) error {
	if r.SchemaVersion != 1 || !environmentName.MatchString(r.Environment) || !canonicalID.MatchString(r.TenantID) || !canonicalID.MatchString(r.ProjectID) || !canonicalID.MatchString(r.DatabaseID) || !canonicalID.MatchString(r.MemberID) || !slices.Contains([]string{"GRU", "SFO", "FRA"}, r.Region) || len(r.SelectedRegions) == 0 || len(r.SelectedRegions) > 20 || r.Residency == "" || len(r.Residency) > 128 || r.Partition == "" || len(r.Partition) > 255 || r.StreamEpoch == 0 || len(r.PlacementProofDigest) != 64 || !validDigest(r.PlacementProofDigest) || r.OperationID == "" || len(r.OperationID) > 256 {
		return ErrInvalid
	}
	if !slices.IsSorted(r.SelectedRegions) || slices.Contains(r.SelectedRegions[1:], r.SelectedRegions[0]) {
		return ErrInvalid
	}
	for i, region := range r.SelectedRegions {
		if !slices.Contains([]string{"FRA", "GRU", "SFO"}, region) || (i > 0 && region == r.SelectedRegions[i-1]) {
			return ErrInvalid
		}
	}
	if !slices.Contains(r.SelectedRegions, r.Region) || strings.IndexFunc(r.Partition, unicode.IsControl) >= 0 {
		return ErrInvalid
	}
	return nil
}

// RemoteUsageRegistration delivers one immutable registration to its target host.
func RemoteUsageRegistration(nc *nats.Conn) func(context.Context, Target, UsageRegistration) error {
	return func(ctx context.Context, target Target, registration UsageRegistration) error {
		if !secureConnection(nc) || ValidateUsageRegistration(registration) != nil {
			return ErrInvalid
		}
		subject, err := HostSubject(target.ServerIdentity)
		if err != nil {
			return err
		}
		data, err := json.Marshal(usageEnvelope{Registration: registration})
		if err != nil || len(data) > usageMessageLimit {
			return ErrInvalid
		}
		opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		reply, err := nc.RequestWithContext(opctx, subject, data)
		if err != nil || len(reply.Data) > usageMessageLimit {
			return errors.New("database admission: usage registration unavailable")
		}
		var receipt usageReceipt
		if json.Unmarshal(reply.Data, &receipt, json.RejectUnknownMembers(true)) != nil || receipt.State != "registered" || !sameUsageRegistration(receipt.UsageRegistration, registration) {
			return errors.New("database admission: usage registration unresolved")
		}
		return nil
	}
}

func handleHostUsage(ctx context.Context, c HostConfig, client *http.Client, message *nats.Msg) bool {
	if len(message.Data) > usageMessageLimit {
		return false
	}
	var envelope usageEnvelope
	if json.Unmarshal(message.Data, &envelope, json.RejectUnknownMembers(true)) != nil || validateHostUsage(c, envelope.Registration) != nil {
		return false
	}
	registrationData, err := json.Marshal(envelope.Registration)
	if err != nil || len(registrationData) > usageMessageLimit {
		_ = message.Respond([]byte("invalid"))
		return true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/internal/v1/databases/usage/admit", bytes.NewReader(registrationData))
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
	var receipt usageReceipt
	if err != nil || reply.StatusCode != http.StatusOK || len(body) > usageMessageLimit || json.Unmarshal(body, &receipt, json.RejectUnknownMembers(true)) != nil || receipt.State != "registered" || !sameUsageRegistration(receipt.UsageRegistration, envelope.Registration) {
		_ = message.Respond([]byte("unavailable"))
		return true
	}
	_ = message.Respond(body)
	return true
}

func validateHostUsage(c HostConfig, r UsageRegistration) error {
	if ValidateUsageRegistration(r) != nil || r.Environment != c.Environment || r.Region != c.Region || r.MemberID != c.MemberID {
		return ErrInvalid
	}
	return nil
}

func sameUsageRegistration(a, b UsageRegistration) bool {
	return a.SchemaVersion == b.SchemaVersion && a.Environment == b.Environment && a.TenantID == b.TenantID && a.ProjectID == b.ProjectID && a.DatabaseID == b.DatabaseID && a.MemberID == b.MemberID && a.Region == b.Region && slices.Equal(a.SelectedRegions, b.SelectedRegions) && a.Residency == b.Residency && a.Partition == b.Partition && a.StreamEpoch == b.StreamEpoch && a.PlacementProofDigest == b.PlacementProofDigest && a.OperationID == b.OperationID
}
