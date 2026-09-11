// Package byokstatus publishes provider admission outcomes to the dashboard.
package byokstatus

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

var ErrUnavailable = errors.New("byokstatus: dashboard unavailable")

type Config struct {
	Endpoint   string
	ServiceKey string
	HTTP       *http.Client
}

// Status is the durable outcome that the dashboard accepts from the
// orchestrator. Provider-install failures remain pending and are retried; they
// are not project-wide durable states.
type Status string

const StatusVerified Status = "verified"

type Update struct {
	ProjectID              string `json:"projectId"`
	Status                 Status `json:"status"`
	ConfigurationUpdatedAt string `json:"configurationUpdatedAt"`
}

type Client struct {
	endpoint string
	key      string
	http     *http.Client
}

func New(config Config) (*Client, error) {
	if strings.TrimSpace(config.ServiceKey) == "" {
		return nil, ErrUnavailable
	}
	u, err := url.Parse(strings.TrimSpace(config.Endpoint))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrUnavailable
	}
	httpClient := config.HTTP
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	return &Client{endpoint: strings.TrimRight(u.String(), "/"), key: config.ServiceKey, http: httpClient}, nil
}

func (c *Client) Publish(ctx context.Context, update Update) error {
	if c == nil || ctx == nil || ctx.Err() != nil || update.ProjectID == "" || update.Status != StatusVerified || update.ConfigurationUpdatedAt == "" {
		return ErrUnavailable
	}
	body, err := json.Marshal(update)
	if err != nil {
		return ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-terrascale-byok-status-key", c.key)
	response, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrUnavailable
	}
	return nil
}
