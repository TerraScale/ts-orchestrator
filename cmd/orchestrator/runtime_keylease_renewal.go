package main

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

type renewalPolicyChecker struct {
	endpoint, serviceKey string
	client               *http.Client
}

func (c renewalPolicyChecker) Check(ctx context.Context, request keylease.RenewalRequest) (time.Time, error) {
	if ctx == nil || request.AdmissionOperationID == "" {
		return time.Time{}, errors.New("renewal admission metadata unavailable")
	}
	b := request.BYOK
	if b == nil {
		return time.Time{}, errors.New("renewal BYOK catalog metadata unavailable")
	}
	purpose := "key-unseal"
	if request.Workload != nil {
		purpose = "workload-credentials"
	}
	environment, tenant, project, database := request.Binding.Environment, request.Binding.TenantID, request.Binding.ProjectID, request.Binding.DatabaseID
	if request.Workload != nil {
		environment, tenant, project, database = request.Workload.Environment, request.Workload.TenantID, request.Workload.ProjectID, request.Workload.DatabaseID
	}
	body := struct {
		Environment          string                 `json:"environment"`
		TenantID             string                 `json:"tenant_id"`
		ProjectID            string                 `json:"project_id"`
		DatabaseID           string                 `json:"database_id"`
		AdmissionOperationID string                 `json:"admission_operation_id"`
		Purpose              string                 `json:"purpose"`
		BYOK                 *keylease.BYOKMetadata `json:"byok"`
		KeyPurpose           string                 `json:"key_purpose,omitempty"`
		KeyRegion            string                 `json:"key_region,omitempty"`
		KeyVersion           string                 `json:"key_version,omitempty"`
		S3                   any                    `json:"s3,omitempty"`
	}{environment, tenant, project, database, request.AdmissionOperationID, purpose, b, request.Binding.Purpose, request.Binding.Region, request.Binding.KeyVersion, nil}
	if request.Workload != nil {
		body.S3 = map[string]any{"endpoint": request.Workload.Endpoint, "bucket": request.Workload.Bucket, "region": request.Workload.Region, "role": request.Workload.Role, "placement_revision": request.Workload.PlacementRevision}
		if request.Workload.ExternalID != nil && *request.Workload.ExternalID != "" {
			body.S3.(map[string]any)["external_id"] = *request.Workload.ExternalID
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return time.Time{}, err
	}
	if len(data) > 8192 {
		return time.Time{}, errors.New("renewal policy request exceeds bound")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(data))
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-terrascale-byok-service-key", c.serviceKey)
	res, err := c.client.Do(req)
	if err != nil {
		return time.Time{}, errors.New("renewal policy unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return time.Time{}, errors.New("renewal policy denied")
	}
	var reply struct {
		Allowed              bool                   `json:"allowed"`
		Status               string                 `json:"status"`
		Purpose              string                 `json:"purpose"`
		ExpiresAt            int64                  `json:"expires_at"`
		AdmissionOperationID string                 `json:"admission_operation_id"`
		DatabaseID           string                 `json:"database_id"`
		Environment          string                 `json:"environment"`
		TenantID             string                 `json:"tenant_id"`
		ProjectID            string                 `json:"project_id"`
		BYOK                 *keylease.BYOKMetadata `json:"byok"`
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(res.Body, 8193))
	if readErr != nil || len(responseBody) > 8192 || json.Unmarshal(responseBody, &reply, json.RejectUnknownMembers(true)) != nil || !reply.Allowed || (reply.Status != "pending" && reply.Status != "verified") || reply.Purpose != body.Purpose || !sameRenewalBYOK(reply.BYOK, b) || reply.AdmissionOperationID != request.AdmissionOperationID || reply.DatabaseID != body.DatabaseID || reply.Environment != body.Environment || reply.TenantID != body.TenantID || reply.ProjectID != body.ProjectID || reply.ExpiresAt <= time.Now().Unix() || reply.ExpiresAt > time.Now().Add(30*time.Second).Unix() {
		return time.Time{}, errors.New("renewal policy denied")
	}
	return time.Unix(reply.ExpiresAt, 0), nil
}
func sameRenewalBYOK(a, b *keylease.BYOKMetadata) bool {
	return a != nil && b != nil && *a == *b
}
func newRenewalPolicyChecker(endpoint, key string) (keylease.RenewalPolicyChecker, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || key == "" {
		return nil, errors.New("renewal policy configuration unavailable")
	}
	return renewalPolicyChecker{endpoint: endpoint, serviceKey: key, client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
