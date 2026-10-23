// Package alertdelivery delivers loopback Alertmanager notifications through
// Cloudflare Email Sending. Credentials remain in Vault and process memory.
package alertdelivery

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

type notification struct {
	Status string `json:"status"`
	Alerts []struct {
		Status string            `json:"status"`
		Labels map[string]string `json:"labels"`
	} `json:"alerts"`
}

type credentials struct{ account, token string }

type relay struct {
	client   *http.Client
	endpoint string
	read     func(context.Context) (credentials, error)
}

// Run serves only loopback; Alertmanager owns retry, grouping and deduplication.
func Run(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("usage: ts-orch alert-delivery")
	}
	r := relay{client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, endpoint: "https://api.cloudflare.com/client/v4/accounts/", read: readCredentials}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /alerts", r.deliver)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	listener, err := net.Listen("tcp", "127.0.0.1:9094")
	if err != nil {
		return err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 55 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func readCredentials(ctx context.Context) (credentials, error) {
	refs := map[string]vaultsecret.Ref{
		"CLOUDFLARE_ACCOUNT_ID_FILE":  {Vault: vaultsecret.SharedVault, Name: "gru-1-cloudflare-account-id"},
		"CLOUDFLARE_EMAIL_TOKEN_FILE": {Vault: vaultsecret.SharedVault, Name: "gru-1-cloudflare-email-token"},
	}
	// Preserve service authorization. Sharing these two existing refs with
	// ts-alerts requires explicit security approval before activation.
	values, err := vaultsecret.ReadInstanceSecrets(ctx, "ts-alerts", refs)
	if err != nil {
		return credentials{}, errors.New("alert delivery Vault credentials unavailable")
	}
	account, token := strings.TrimSpace(values["CLOUDFLARE_ACCOUNT_ID_FILE"]), strings.TrimSpace(values["CLOUDFLARE_EMAIL_TOKEN_FILE"])
	if !regexp.MustCompile(`^[a-fA-F0-9]{32}$`).MatchString(account) || token == "" || strings.ContainsAny(token, "\r\n") {
		return credentials{}, errors.New("alert delivery Vault credentials invalid")
	}
	return credentials{account, token}, nil
}

func (r relay) deliver(w http.ResponseWriter, request *http.Request) {
	var notice notification
	body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, 64<<10))
	if err != nil || json.Unmarshal(body, &notice) != nil || len(notice.Alerts) == 0 || len(notice.Alerts) > 64 || (notice.Status != "firing" && notice.Status != "resolved") {
		http.Error(w, "invalid alert notification", http.StatusBadRequest)
		return
	}
	var lines []string
	for _, alert := range notice.Alerts {
		name := alert.Labels["alertname"]
		if name == "" || len(name) > 128 || (alert.Status != "firing" && alert.Status != "resolved") {
			http.Error(w, "invalid alert notification", http.StatusBadRequest)
			return
		}
		// Never forward tenant labels, annotations, raw paths or credentials.
		lines = append(lines, fmt.Sprintf("%s: %s; service=%s; region=%s; severity=%s", alert.Status, name, alert.Labels["service"], alert.Labels["region"], alert.Labels["severity"]))
	}
	ctx, cancel := context.WithTimeout(request.Context(), 50*time.Second)
	defer cancel()
	secrets, err := r.read(ctx)
	if err != nil {
		http.Error(w, "alert delivery credentials unavailable", http.StatusServiceUnavailable)
		return
	}
	payload, err := json.Marshal(map[string]any{
		"from": map[string]string{"address": "no-reply@terrascale.tech", "name": "TerraScale production alerts"},
		"to":   "mariogk@terrascale.tech", "subject": "TerraScale production alert: " + notice.Status,
		"text": strings.Join(lines, "\n"),
	})
	if err != nil {
		http.Error(w, "alert delivery encoding failed", http.StatusInternalServerError)
		return
	}
	outgoing, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint+secrets.account+"/email/sending/send", bytes.NewReader(payload))
	if err != nil {
		http.Error(w, "alert delivery request failed", http.StatusBadGateway)
		return
	}
	outgoing.Header.Set("Authorization", "Bearer "+secrets.token)
	outgoing.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(outgoing)
	if err != nil {
		http.Error(w, "alert delivery transport failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	var result struct {
		Success bool `json:"success"`
		Result  struct {
			PermanentBounces []jsontext.Value `json:"permanent_bounces"`
		} `json:"result"`
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if response.StatusCode < 200 || response.StatusCode >= 300 || err != nil || len(data) > 64<<10 || json.Unmarshal(data, &result) != nil || !result.Success || len(result.Result.PermanentBounces) > 0 {
		http.Error(w, "alert delivery rejected by provider", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	slog.InfoContext(ctx, "production alert email accepted", "status", notice.Status, "alerts", len(notice.Alerts))
}
