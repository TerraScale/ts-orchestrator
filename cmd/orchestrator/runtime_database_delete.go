package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

type databaseDeletionPolicy func(context.Context, databaseadmission.DeleteRequest) (databaseadmission.DeletionPolicyDecision, error)

func (p databaseDeletionPolicy) AuthorizeDeletion(ctx context.Context, request databaseadmission.DeleteRequest) (databaseadmission.DeletionPolicyDecision, error) {
	return p(ctx, request)
}

func newDatabaseDeletionAuthorizer(config databaseAuthorizationFile) (databaseadmission.DeletionPolicy, error) {
	client, key, err := databaseAuthorizationClient(config)
	if err != nil {
		return nil, err
	}
	return databaseDeletionAuthorizer(client, config.Endpoint, key), nil
}

func databaseDeletionAuthorizer(client *http.Client, endpoint, key string) databaseDeletionPolicy {
	return func(ctx context.Context, request databaseadmission.DeleteRequest) (databaseadmission.DeletionPolicyDecision, error) {
		var result databaseadmission.DeletionPolicyDecision
		data, err := json.Marshal(request)
		if err != nil {
			return result, err
		}
		call, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
		if err != nil {
			return result, err
		}
		call.Header.Set("Content-Type", "application/json")
		call.Header.Set("x-terrascale-database-admission-key", key)
		response, err := client.Do(call)
		if err != nil {
			return result, errors.New("database deletion authorization: producer unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusForbidden {
			return result, databaseadmission.ErrForbidden
		}
		if response.StatusCode != http.StatusOK {
			return result, errors.New("database deletion authorization: producer unavailable")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
		if err != nil || len(body) > 8192 {
			return result, errors.New("database deletion authorization: invalid response")
		}
		var decision struct {
			Allowed     bool   `json:"allowed"`
			Protected   *bool  `json:"protected"`
			Environment string `json:"environment"`
			TenantID    string `json:"tenant_id"`
			ProjectID   string `json:"project_id"`
			DatabaseID  string `json:"database_id"`
			OperationID string `json:"operation_id"`
			ExpiresAt   int64  `json:"expires_at"`
			RetainUntil int64  `json:"retain_until"`
		}
		now := time.Now()
		if json.Unmarshal(body, &decision, json.RejectUnknownMembers(true)) != nil || decision.Environment != request.Environment || decision.TenantID != request.TenantID || decision.ProjectID != request.ProjectID || decision.DatabaseID != request.DatabaseID || decision.OperationID != request.OperationID || decision.ExpiresAt <= now.Unix() || decision.ExpiresAt > now.Add(time.Minute).Unix() || decision.RetainUntil <= now.UnixMilli() {
			return result, errors.New("database deletion authorization: response scope or freshness mismatch")
		}
		if !decision.Allowed || decision.Protected == nil || *decision.Protected {
			return result, databaseadmission.ErrForbidden
		}
		result.RetainUntil = time.UnixMilli(decision.RetainUntil).UTC()
		return result, nil
	}
}
