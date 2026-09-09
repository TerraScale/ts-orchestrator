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

// byokPolicyFileConfig identifies the authenticated dashboard policy producer.
// It carries no customer credential material; the producer owns credential
// exchange with the customer broker.
type byokPolicyFileConfig struct {
	Endpoint       string `json:"endpoint"`
	ServiceKeyFile string `json:"serviceKeyFile"`
}

type byokPolicyDecision struct {
	Allowed     bool                             `json:"allowed"`
	Status      string                           `json:"status"`
	Environment string                           `json:"environment"`
	TenantID    string                           `json:"tenant_id"`
	ProjectID   string                           `json:"project_id"`
	OperationID string                           `json:"operation_id"`
	BYOK        *databaseadmission.BYOKReference `json:"byok,omitempty"`
	ExpiresAt   int64                            `json:"expires_at"`
	ErrorCode   string                           `json:"error_code,omitempty"`
}

func newBYOKPolicyAuthorizer(config byokPolicyFileConfig) (func(context.Context, databaseadmission.Request) error, error) {
	if err := validateBYOKPolicyEndpoint(config.Endpoint); err != nil {
		return nil, err
	}
	client, key, err := databaseAuthorizationClient(databaseAuthorizationFile{Endpoint: config.Endpoint, ServiceKeyFile: config.ServiceKeyFile})
	if err != nil {
		return nil, err
	}
	return byokPolicyAuthorizer(client, config.Endpoint, key), nil
}

func byokPolicyAuthorizer(client *http.Client, endpoint, key string) func(context.Context, databaseadmission.Request) error {
	return func(ctx context.Context, request databaseadmission.Request) error {
		if request.BYOK == nil || databaseadmission.ValidateBYOKReference(request.BYOK) != nil {
			return databaseadmission.ErrInvalid
		}
		body, err := json.Marshal(request)
		if err != nil {
			return err
		}
		call, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		call.Header.Set("Content-Type", "application/json")
		call.Header.Set("x-terrascale-byok-service-key", key)
		response, err := client.Do(call)
		if err != nil {
			return errors.New("BYOK policy producer unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusForbidden {
			return databaseadmission.ErrForbidden
		}
		if response.StatusCode != http.StatusOK {
			return errors.New("BYOK policy producer unavailable")
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
		if err != nil || len(data) > 8192 {
			return errors.New("BYOK policy producer returned an invalid response")
		}
		var decision byokPolicyDecision
		if err := json.Unmarshal(data, &decision, json.RejectUnknownMembers(true)); err != nil {
			return errors.New("BYOK policy producer returned an invalid response")
		}
		if decision.Environment != request.Environment || decision.TenantID != request.TenantID || decision.ProjectID != request.ProjectID || decision.OperationID != request.OperationID || decision.ExpiresAt <= time.Now().Unix() || decision.ExpiresAt > time.Now().Add(time.Minute).Unix() || decision.Status != "verified" || !decision.Allowed || decision.BYOK == nil || !sameBYOK(decision.BYOK, request.BYOK) {
			if decision.Status == "error" && decision.Environment == request.Environment && decision.TenantID == request.TenantID && decision.ProjectID == request.ProjectID && decision.OperationID == request.OperationID {
				return databaseadmission.ErrForbidden
			}
			return errors.New("BYOK policy producer returned a scope or freshness mismatch")
		}
		return nil
	}
}

func sameBYOK(left, right *databaseadmission.BYOKReference) bool {
	return left != nil && right != nil && left.BackupEndpoint == right.BackupEndpoint && left.BackupBucket == right.BackupBucket && left.BackupRegion == right.BackupRegion && left.BackupRoleARN == right.BackupRoleARN && left.BackupExternalID == right.BackupExternalID && left.KeyProvider == right.KeyProvider && left.KeyID == right.KeyID && left.KeyRegion == right.KeyRegion && left.KeyEndpoint == right.KeyEndpoint
}

// validateBYOKPolicyEndpoint is kept separate for tests and to make the
// endpoint boundary explicit: no redirects, plaintext, query credentials, or
// non-canonical paths are admitted.
func validateBYOKPolicyEndpoint(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("BYOK policy requires an explicit HTTPS endpoint")
	}
	return nil
}
