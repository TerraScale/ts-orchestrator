package cloudflare

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"time"
)

var ErrIdentityService = errors.New("cloudflare: identity service secret update unavailable")

// SetIdentityServiceKeys atomically changes only the dashboard identity secrets.
// The supported scripts/secrets-bulk API uses JSON Merge Patch, including null
// for deletion; it does not accept a bindings array. Provider contract:
// https://github.com/cloudflare/cloudflare-go/blob/main/workers/scriptsecret.go
func (c *Client) SetIdentityServiceKeys(ctx context.Context, script string, active, previous []byte, expires time.Time) error {
	if script == "" || c.AccountID == "" || len(active) < 32 || (len(previous) == 0) != expires.IsZero() || len(previous) > 0 && (len(previous) < 32 || !expires.After(time.Now()) || expires.After(time.Now().Add(300*time.Second))) {
		return ErrIdentityService
	}
	for _, key := range [][]byte{active, previous} {
		if len(key) != 0 && len(key) != 43 {
			return ErrIdentityService
		}
		for _, v := range key {
			if !(v >= 'a' && v <= 'z' || v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' || v == '_' || v == '-') {
				return ErrIdentityService
			}
		}
	}
	buffer, err := hostsecrets.NewSecretBuffer(2048)
	if err != nil {
		return ErrIdentityService
	}
	defer buffer.Close()
	payload := buffer.Bytes()[:0]
	payload = append(payload, `{"secrets":{"TERRASCALE_IDENTITY_SERVICE_KEY":{"name":"TERRASCALE_IDENTITY_SERVICE_KEY","type":"secret_text","text":"`...)
	payload = append(payload, active...)
	payload = append(payload, `"},"TERRASCALE_IDENTITY_SERVICE_PREVIOUS_KEY":`...)
	if len(previous) == 0 {
		payload = append(payload, `null,"TERRASCALE_IDENTITY_SERVICE_PREVIOUS_KEY_EXPIRES_AT":null}}`...)
	} else {
		payload = append(payload, `{"name":"TERRASCALE_IDENTITY_SERVICE_PREVIOUS_KEY","type":"secret_text","text":"`...)
		payload = append(payload, previous...)
		payload = append(payload, `"},"TERRASCALE_IDENTITY_SERVICE_PREVIOUS_KEY_EXPIRES_AT":{"name":"TERRASCALE_IDENTITY_SERVICE_PREVIOUS_KEY_EXPIRES_AT","type":"secret_text","text":"`...)
		payload = strconv.AppendInt(payload, expires.Unix(), 10)
		payload = append(payload, `"}}}`...)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.BaseURL+c.accountPath("/workers/scripts/"+url.PathEscape(script)+"/secrets-bulk"), bytes.NewReader(payload))
	if err != nil {
		return ErrIdentityService
	}
	request.Header.Set("Authorization", "Bearer "+c.Token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	transport := c.HTTP
	if transport == nil {
		transport = http.DefaultTransport
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return ErrIdentityService
	}
	defer response.Body.Close()
	status := response.StatusCode
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	if len(raw) > 8192 {
		clear(raw)
		return ErrIdentityService
	}
	defer clear(raw)
	// Never expose provider error bodies, which could contain submitted secrets.
	if err != nil || status < 200 || status >= 300 {
		return ErrIdentityService
	}
	var envelope struct {
		Success bool `json:"success"`
	}
	if json.Unmarshal(raw, &envelope) != nil || !envelope.Success {
		return ErrIdentityService
	}
	return nil
}
