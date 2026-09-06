package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

type databaseDeletionPolicy func(context.Context, databaseadmission.DeleteRequest) (databaseadmission.DeletionPolicyDecision, error)

func (p databaseDeletionPolicy) AuthorizeDeletion(ctx context.Context, request databaseadmission.DeleteRequest) (databaseadmission.DeletionPolicyDecision, error) {
	return p(ctx, request)
}

func newDatabaseDeletionAuthorizer(config databaseAuthorizationFile) (func(context.Context, databaseadmission.DeleteRequest) error, error) {
	client, key, err := databaseAuthorizationClient(config)
	if err != nil {
		return nil, err
	}
	return databaseDeletionAuthorizer(client, config.Endpoint, key), nil
}

func databaseDeletionAuthorizer(client *http.Client, endpoint, key string) func(context.Context, databaseadmission.DeleteRequest) error {
	return func(ctx context.Context, request databaseadmission.DeleteRequest) error {
		authorization := databaseadmission.DeletionAuthorization(ctx)
		token, ok := strings.CutPrefix(authorization, "Bearer ")
		if !ok || token == "" || strings.ContainsAny(token, " \t\r\n") {
			return databaseadmission.ErrForbidden
		}
		data, err := json.Marshal(request)
		if err != nil {
			return err
		}
		call, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
		if err != nil {
			return err
		}
		call.Header.Set("Content-Type", "application/json")
		call.Header.Set("Authorization", authorization)
		call.Header.Set("x-terrascale-database-admission-key", key)
		response, err := client.Do(call)
		if err != nil {
			return errors.New("database deletion authorization: producer unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusForbidden {
			return databaseadmission.ErrForbidden
		}
		if response.StatusCode != http.StatusOK {
			return errors.New("database deletion authorization: producer unavailable")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
		if err != nil || len(body) > 8192 {
			return errors.New("database deletion authorization: invalid response")
		}
		var decision struct {
			Allowed     bool   `json:"allowed"`
			Action      string `json:"action"`
			Subject     string `json:"subject"`
			Actor       string `json:"actor"`
			IssuedAt    int64  `json:"issued_at"`
			Environment string `json:"environment"`
			TenantID    string `json:"tenant_id"`
			ProjectID   string `json:"project_id"`
			DatabaseID  string `json:"database_id"`
			OperationID string `json:"operation_id"`
			ExpiresAt   int64  `json:"expires_at"`
		}
		now := time.Now()
		if json.Unmarshal(body, &decision, json.RejectUnknownMembers(true)) != nil || decision.Environment != request.Environment || decision.TenantID != request.TenantID || decision.ProjectID != request.ProjectID || decision.DatabaseID != request.DatabaseID || decision.OperationID != request.OperationID || decision.ExpiresAt <= now.Unix() || decision.ExpiresAt > now.Add(30*time.Second).Unix() || decision.Action != "delete" || decision.Subject == "" || decision.Actor == "" || decision.IssuedAt > now.Unix() || decision.IssuedAt < now.Add(-30*time.Second).Unix() || decision.ExpiresAt <= decision.IssuedAt {
			return errors.New("database deletion authorization: response scope or freshness mismatch")
		}
		if !decision.Allowed {
			return databaseadmission.ErrForbidden
		}
		return nil
	}
}
