package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
)

type databaseDeletionPolicy func(context.Context, databaseadmission.DeleteRequest) (databaseadmission.DeletionPolicyDecision, error)

func (p databaseDeletionPolicy) AuthorizeDeletion(ctx context.Context, request databaseadmission.DeleteRequest) (databaseadmission.DeletionPolicyDecision, error) {
	return p(ctx, request)
}

func newDatabaseDeletionAuthorizer(config databaseAuthorizationFile) (func(context.Context, databaseadmission.DeleteRequest) (databaseadmission.DeletionClaimReceipt, error), error) {
	client, key, err := databaseAuthorizationClient(config)
	if err != nil {
		return nil, err
	}
	claimEndpoint := config.Endpoint
	if parsed, parseErr := url.Parse(claimEndpoint); parseErr == nil {
		parsed.Path = "/api/internal/lifecycle/claim-delete"
		claimEndpoint = parsed.String()
	}
	return databaseDeletionAuthorizer(client, claimEndpoint, key), nil
}

func databaseDeletionAuthorizer(client *http.Client, endpoint, key string) func(context.Context, databaseadmission.DeleteRequest) (databaseadmission.DeletionClaimReceipt, error) {
	return func(ctx context.Context, request databaseadmission.DeleteRequest) (databaseadmission.DeletionClaimReceipt, error) {
		var empty databaseadmission.DeletionClaimReceipt
		authorization := databaseadmission.DeletionAuthorization(ctx)
		token, ok := strings.CutPrefix(authorization, "Bearer ")
		if !ok || token == "" || strings.ContainsAny(token, " \t\r\n") {
			return empty, databaseadmission.ErrForbidden
		}
		data, err := json.Marshal(request)
		if err != nil {
			return empty, err
		}
		call, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
		if err != nil {
			return empty, err
		}
		call.Header.Set("Content-Type", "application/json")
		call.Header.Set("Authorization", authorization)
		call.Header.Set("x-terrascale-database-admission-key", key)
		response, err := client.Do(call)
		if err != nil {
			return empty, errors.New("database deletion authorization: producer unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusForbidden {
			return empty, databaseadmission.ErrForbidden
		}
		if response.StatusCode != http.StatusOK {
			return empty, errors.New("database deletion authorization: producer unavailable")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
		if err != nil || len(body) > 8192 {
			return empty, errors.New("database deletion authorization: invalid response")
		}
		var receipt databaseadmission.DeletionClaimReceipt
		if json.Unmarshal(body, &receipt) != nil || receipt.SchemaVersion != 1 || receipt.Environment != request.Environment || receipt.TenantID != request.TenantID || receipt.ProjectID != request.ProjectID || receipt.DatabaseID != request.DatabaseID || receipt.OperationID != request.OperationID || receipt.PolicyRevision == "" || receipt.AuthorityEpoch == "" || receipt.Deadline.IsZero() {
			return empty, errors.New("database deletion claim: invalid receipt")
		}
		return receipt, nil
	}
}
