// Package alertdelivery delivers loopback Alertmanager notifications through
// Cloudflare Email Sending and generic push. Credentials remain in Vault and process memory.
package alertdelivery

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

type notification struct {
	TruncatedAlerts uint64 `json:"truncatedAlerts"`
	Status          string `json:"status"`
	GroupKey        string `json:"groupKey"`
	Alerts          []struct {
		Status      string            `json:"status"`
		Fingerprint string            `json:"fingerprint"`
		Labels      map[string]string `json:"labels"`
	} `json:"alerts"`
}

type credentials struct{ account, token string }

type relay struct {
	client       *http.Client
	endpoint     string
	pushEndpoint string
	ledgerPath   string
	read         func(context.Context) (credentials, error)
	readTopic    func(context.Context) (string, error)
}

const recipient = "mariogk@terrascale.tech"

// Run serves only loopback; the relay independently bounds email quota usage.
func Run(ctx context.Context, args []string) error {
	if len(args) != 0 && (len(args) != 1 || args[0] != "subscribe") {
		return errors.New("usage: ts-orch alert-delivery")
	}
	r := relay{ledgerPath: "/var/lib/ts-alerts/email-ledger.json", client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, endpoint: "https://api.cloudflare.com/client/v4/accounts/", pushEndpoint: "https://ntfy.sh/", read: readCredentials, readTopic: readPushTopic}
	if len(args) == 1 {
		return r.subscribe(ctx)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", readinessMetrics(newReadinessClient()))
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
	// Only the two refs approved for alert delivery are shared with this service.
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
	if notice.TruncatedAlerts > 0 {
		lines = append(lines, fmt.Sprintf("%d additional alerts in this group; inspect Prometheus for every affected host", notice.TruncatedAlerts))
	}
	ctx, cancel := context.WithTimeout(request.Context(), 50*time.Second)
	defer cancel()
	var emailErr, pushErr error
	var deliveries sync.WaitGroup
	deliveries.Go(func() {
		if reason := r.reserveEmail(ctx, notice.emailKey(), time.Now()); reason != "" {
			slog.WarnContext(ctx, "production alert email suppressed", "reason", reason)
			return
		}
		emailErr = r.email(ctx, notice.Status, lines)
	})
	deliveries.Go(func() { pushErr = r.push(ctx, notice.Status) })
	deliveries.Wait()
	if pushErr != nil {
		// Push is independent: never retry an accepted email because push failed.
		slog.WarnContext(ctx, "production alert push failed", "status", notice.Status)
	}
	if emailErr != nil {
		slog.WarnContext(ctx, "production alert channel rejected", "email_accepted", emailErr == nil, "push_accepted", pushErr == nil)
		http.Error(w, "alert delivery incomplete", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	slog.InfoContext(ctx, "production alert notification handled", "status", notice.Status, "alerts", len(notice.Alerts))
}

func (r relay) email(ctx context.Context, status string, lines []string) error {
	secrets, err := r.read(ctx)
	if err != nil {
		return errors.New("alert delivery credentials unavailable")
	}
	sendBy, err := r.admit(ctx, secrets.token)
	if err != nil {
		// Suppression is handled, just like the local cap; push remains independent.
		slog.WarnContext(ctx, "production alert email suppressed", "reason", "admission unavailable")
		return nil
	}
	ctx, cancel := context.WithDeadline(ctx, sendBy)
	defer cancel()
	payload, err := json.Marshal(map[string]any{
		"from": map[string]string{"address": "no-reply@terrascale.tech", "name": "TerraScale production alerts"},
		"to":   recipient, "subject": "TerraScale production alert: " + status,
		"text": strings.Join(lines, "\n"),
	})
	if err != nil {
		return errors.New("alert delivery encoding failed")
	}
	outgoing, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint+secrets.account+"/email/sending/send", bytes.NewReader(payload))
	if err != nil {
		return errors.New("alert delivery request failed")
	}
	outgoing.Header.Set("Authorization", "Bearer "+secrets.token)
	outgoing.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(outgoing)
	if err != nil {
		return errors.New("alert delivery transport failed")
	}
	defer response.Body.Close()
	var result struct {
		Success bool `json:"success"`
		Result  struct {
			PermanentBounces []string `json:"permanent_bounces"`
			Suppressed       []string `json:"suppressed_recipients"`
			Delivered        []string `json:"delivered"`
			Queued           []string `json:"queued"`
		} `json:"result"`
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10+1))
	if response.StatusCode < 200 || response.StatusCode >= 300 || err != nil || len(data) > 64<<10 || json.Unmarshal(data, &result) != nil || !result.Success || len(result.Result.PermanentBounces) > 0 || len(result.Result.Suppressed) > 0 || (!slices.Contains(result.Result.Delivered, recipient) && !slices.Contains(result.Result.Queued, recipient)) {
		return errors.New("alert delivery rejected by provider")
	}
	return nil
}

func (r relay) push(ctx context.Context, status string) error {
	topic, err := r.readTopic(ctx)
	if err != nil || !validPushTopic(topic) {
		return errors.New("push Vault topic unavailable or invalid")
	}
	// Topic knowledge grants publish and subscribe access. Send generic details only.
	push, err := http.NewRequestWithContext(ctx, http.MethodPost, r.pushEndpoint+topic, strings.NewReader("TerraScale production alert: "+status+". Check production monitoring."))
	if err != nil {
		return errors.New("push request failed")
	}
	push.Header.Set("Title", "TerraScale production alert")
	push.Header.Set("Priority", "urgent")
	pushResponse, err := r.client.Do(push)
	if err != nil {
		return errors.New("push transport failed")
	}
	defer pushResponse.Body.Close()
	var published struct {
		ID    string `json:"id"`
		Event string `json:"event"`
		Topic string `json:"topic"`
	}
	pushData, err := io.ReadAll(io.LimitReader(pushResponse.Body, 64<<10+1))
	if pushResponse.StatusCode != http.StatusOK || err != nil || len(pushData) > 64<<10 || json.Unmarshal(pushData, &published) != nil || published.ID == "" || published.Event != "message" || published.Topic != topic {
		return errors.New("push rejected by provider")
	}
	return nil
}
