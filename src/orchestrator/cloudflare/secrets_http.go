package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// ErrSecretMutationOutcomeUnknown requires observation before another mutation.
// Secrets Store does not document an idempotency key or conditional update API.
var ErrSecretMutationOutcomeUnknown = errors.New("cloudflare: secret mutation outcome unknown")

// secretsRequest deliberately makes one HTTP attempt. It never copies provider
// response messages or transport diagnostics into errors containing secret values.
func (c *Client) secretsRequest(ctx context.Context, op, method, path string, input, out any) (*resultInfo, error) {
	if ctx == nil {
		return nil, errors.New("cloudflare: context required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.HTTP == nil {
		return nil, errors.New("cloudflare: secret transport unavailable")
	}
	mutation := method != http.MethodGet
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, errors.New("cloudflare: invalid secret request")
	}
	defer clear(payload)
	var body io.Reader
	if input != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, errors.New("cloudflare: invalid secret endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.HTTP.RoundTrip(req)
	if err != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if mutation {
			return nil, ErrSecretMutationOutcomeUnknown
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("cloudflare: secret transport failed")
	}
	if response == nil || response.Body == nil {
		if mutation {
			return nil, ErrSecretMutationOutcomeUnknown
		}
		return nil, errors.New("cloudflare: empty secret response")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	defer clear(raw)
	malformed := func() error {
		if mutation {
			return ErrSecretMutationOutcomeUnknown
		}
		return &APIError{Op: op, Status: response.StatusCode, Message: "invalid secret response"}
	}
	if err != nil || len(raw) > maxBodyBytes {
		return nil, malformed()
	}
	var env struct {
		Success *bool `json:"success"`
		Errors  []struct {
			Code int `json:"code"`
		} `json:"errors"`
		Result     json.RawMessage `json:"result"`
		ResultInfo *resultInfo     `json:"result_info"`
	}
	if json.Unmarshal(raw, &env) != nil {
		return nil, malformed()
	}
	defer clear(env.Result)
	if env.Success == nil || len(env.Result) == 0 && response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil, malformed()
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !*env.Success {
		if mutation && response.StatusCode >= 500 {
			return nil, ErrSecretMutationOutcomeUnknown
		}
		failure := &APIError{Op: op, Status: response.StatusCode, Message: "request rejected"}
		if len(env.Errors) > 0 {
			failure.Code = env.Errors[0].Code
		}
		return nil, failure
	}
	if out != nil {
		if len(env.Result) == 0 || bytes.Equal(bytes.TrimSpace(env.Result), []byte("null")) || json.Unmarshal(env.Result, out) != nil {
			return nil, malformed()
		}
	}
	return env.ResultInfo, nil
}

func readSecretsPages[T any](ctx context.Context, c *Client, op, path string, identity func(T) (string, string, bool)) ([]T, error) {
	result := make([]T, 0)
	ids, names := map[string]bool{}, map[string]bool{}
	expectedPages := -1
	for page := 1; page <= 128; page++ {
		query := url.Values{"page": {strconv.Itoa(page)}, "per_page": {"100"}}
		var items []T
		info, err := c.secretsRequest(ctx, op, http.MethodGet, path+"?"+query.Encode(), nil, &items)
		if err != nil {
			return nil, err
		}
		if items == nil || len(items) > 100 || len(result)+len(items) > 10000 || info == nil || info.Page != page || info.TotalPages < 0 || info.TotalPages > 128 || info.TotalPages == 0 && (page != 1 || len(items) != 0) || info.TotalPages > 0 && info.TotalPages < page {
			return nil, errors.New("cloudflare: invalid secrets pagination")
		}
		if expectedPages >= 0 && expectedPages != info.TotalPages {
			return nil, errors.New("cloudflare: secrets collection changed during pagination")
		}
		expectedPages = info.TotalPages
		for _, item := range items {
			id, name, valid := identity(item)
			if !valid || ids[id] || names[name] {
				return nil, errors.New("cloudflare: invalid or duplicate secrets metadata")
			}
			ids[id], names[name] = true, true
			result = append(result, item)
		}
		if page >= info.TotalPages {
			return result, nil
		}
		if len(items) == 0 {
			return nil, errors.New("cloudflare: missing secrets page")
		}
	}
	return nil, errors.New("cloudflare: secrets pagination limit")
}
