package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

type databaseDeletionClaimConfig struct {
	Endpoint       string `json:"endpoint"`
	ServiceKeyFile string `json:"serviceKeyFile"`
}

type automaticDeletionClaimRequest struct {
	SchemaVersion  uint8  `json:"schemaVersion"`
	Environment    string `json:"environment"`
	TenantID       string `json:"tenant_id"`
	ProjectID      string `json:"project_id"`
	DatabaseID     string `json:"database_id"`
	OperationID    string `json:"operation_id"`
	PolicyRevision string `json:"policy_revision"`
	GraceCondition string `json:"grace_condition"`
}

type automaticDeletionClaimClient func(context.Context, automaticDeletionClaimRequest) (databaseadmission.DeletionClaimReceipt, error)

func newDatabaseDeletionClaimClient(config databaseDeletionClaimConfig) (automaticDeletionClaimClient, error) {
	client, key, err := databaseAuthorizationClient(databaseAuthorizationFile{Endpoint: config.Endpoint, ServiceKeyFile: config.ServiceKeyFile})
	if err != nil {
		return nil, err
	}
	return databaseDeletionClaimHTTPClient(client, config.Endpoint, key), nil
}

func databaseDeletionClaimHTTPClient(client *http.Client, endpoint, key string) automaticDeletionClaimClient {
	return func(ctx context.Context, request automaticDeletionClaimRequest) (databaseadmission.DeletionClaimReceipt, error) {
		var empty databaseadmission.DeletionClaimReceipt
		if request.SchemaVersion != 1 || !claimToken(request.Environment) || !claimToken(request.TenantID) || !claimToken(request.ProjectID) || !claimToken(request.DatabaseID) || !claimToken(request.OperationID) || !claimToken(request.PolicyRevision) || !claimToken(request.GraceCondition) {
			return empty, databaseadmission.ErrInvalid
		}
		body, err := json.Marshal(request)
		if err != nil {
			return empty, err
		}
		call, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return empty, err
		}
		call.Header.Set("Content-Type", "application/json")
		call.Header.Set("x-terrascale-lifecycle-service-key", key)
		response, err := client.Do(call)
		if err != nil {
			return empty, errors.New("database deletion claim: producer unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusConflict {
			return empty, databaseadmission.ErrConflict
		}
		if response.StatusCode != http.StatusOK {
			return empty, errors.New("database deletion claim: producer unavailable")
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
		if err != nil || len(data) > 8192 {
			return empty, errors.New("database deletion claim: invalid response")
		}
		var receipt databaseadmission.DeletionClaimReceipt
		if err := json.Unmarshal(data, &receipt, json.RejectUnknownMembers(true)); err != nil || receipt.SchemaVersion != 1 || receipt.Environment != request.Environment || receipt.TenantID != request.TenantID || receipt.ProjectID != request.ProjectID || receipt.DatabaseID != request.DatabaseID || receipt.OperationID != request.OperationID || !claimToken(receipt.PolicyRevision) || !claimToken(receipt.PolicyFingerprint) || receipt.GraceCondition != request.GraceCondition || receipt.Deadline.IsZero() || receipt.AcceptedAt.IsZero() || !claimToken(receipt.AuthorityEpoch) {
			return empty, errors.New("database deletion claim: invalid receipt")
		}
		return receipt, nil
	}
}

func claimToken(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\t")
}
