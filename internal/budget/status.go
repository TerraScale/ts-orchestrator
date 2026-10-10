package budget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"

	json "encoding/json/v2"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// StatusOperatorURL is ts-status's operator API.
const StatusOperatorURL = "https://status.terrascale.tech/api/operator"

const (
	maxStatusReplyBytes   = 64 << 10
	warningTitle          = "Capacity growth may be limited"
	openWarningMessage    = "TerraScale's capacity budget for this month is nearly used. New capacity may be added more slowly until it is reviewed."
	resolveWarningMessage = "Capacity growth is back to normal."
)

// ErrNoStatusToken means the ts-status operator token is not in Vault.
var ErrNoStatusToken = errors.New("no ts-status operator token")

// incidentID matches the UUIDs ts-status issues; it is also a URL path segment.
var incidentID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// StatusPage opens and resolves the budget warning on ts-status.
type StatusPage struct {
	URL   string                                    // StatusOperatorURL in production, a test server in tests
	Token func(ctx context.Context) (string, error) // read on every call, never logged
	HTTP  *http.Client                              // 10 s timeout
}

type incidentRequest struct {
	Kind       string   `json:"kind"`
	Title      string   `json:"title"`
	Impact     string   `json:"impact"`
	Components []string `json:"components"`
	Message    string   `json:"message"`
}

type updateRequest struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// OpenWarning publishes the budget warning and returns its incident id.
func (p StatusPage) OpenWarning(ctx context.Context) (string, error) {
	var created struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	request := incidentRequest{Kind: "warning", Title: warningTitle, Impact: "none", Components: []string{},
		Message: openWarningMessage}
	if err := p.post(ctx, "/incidents", request, &created); err != nil {
		return "", err
	}
	if !incidentID.MatchString(created.ID) {
		return "", errors.New("ts-status returned an invalid incident id")
	}
	return created.ID, nil
}

// ResolveWarning adds a resolved update to the warning incident id.
func (p StatusPage) ResolveWarning(ctx context.Context, id string) error {
	if !incidentID.MatchString(id) {
		return errors.New("invalid ts-status incident id")
	}
	request := updateRequest{Status: "resolved", Message: resolveWarningMessage}
	return p.post(ctx, "/incidents/"+id+"/updates", request, nil)
}

// post sends one bearer-authenticated JSON request and decodes the reply into out when out is set.
func (p StatusPage) post(ctx context.Context, path string, request, out any) error {
	token, err := p.Token(ctx)
	if err != nil {
		return fmt.Errorf("read ts-status operator token: %w", err)
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode ts-status request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.URL+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build ts-status request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("ts-status request: %w", err)
	}
	defer resp.Body.Close()
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusReplyBytes+1))
	if err != nil {
		return fmt.Errorf("read ts-status reply: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ts-status %s returned HTTP %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := protocol.DecodeStrict(reply, out, maxStatusReplyBytes); err != nil {
		return fmt.Errorf("decode ts-status reply: %w", err)
	}
	return nil
}
