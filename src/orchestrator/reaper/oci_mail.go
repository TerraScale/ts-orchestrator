package reaper

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

var ErrOCIEmail = errors.New("reaper: OCI email submission unavailable or unacknowledged")

// OCIMailConfig supplies explicit host credentials and effect authority. Transport
// is an optional qualification seam; production uses the default HTTP transport.
type OCIMailConfig struct {
	Endpoint, CompartmentID, Sender, KeyID string
	PrivateKey                             *rsa.PrivateKey
	Transport                              http.RoundTripper
	CheckEffectAuthority                   func(context.Context) error
}

type OCIMailAdapter struct {
	endpoint, compartment, sender string
	signer                        *provider.InstancePrincipalSigner
	client                        *http.Client
	check                         func(context.Context) error
}

// OCIEmailMessage is a metadata-only operational notice. OCI SubmitEmail has no
// idempotency token contract: OperationKey is local bookkeeping, and a retry
// after an ambiguous response can submit a duplicate notice.
type OCIEmailMessage struct{ To, Subject, Body, OperationKey string }

func NewOCIMailAdapter(c OCIMailConfig) (*OCIMailAdapter, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || !regexp.MustCompile(`^cell0\.submit\.email\.[a-z0-9-]+\.oci\.oraclecloud\.com$`).MatchString(u.Host) || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || !ociMailbox(c.Sender) || strings.TrimSpace(c.CompartmentID) == "" || strings.TrimSpace(c.CompartmentID) != c.CompartmentID || len(c.CompartmentID) > 255 || strings.ContainsAny(c.CompartmentID, "\r\n\t") || len(c.KeyID) > 2048 || strings.ContainsAny(c.KeyID, "\r\n\"\\") || c.CheckEffectAuthority == nil {
		return nil, ErrOCIEmail
	}
	signer, err := provider.NewInstancePrincipalSigner(c.KeyID, c.PrivateKey)
	if err != nil {
		return nil, ErrOCIEmail
	}
	if err := c.PrivateKey.Validate(); err != nil {
		return nil, ErrOCIEmail
	}
	return &OCIMailAdapter{endpoint: "https://" + u.Host + "/20220926/actions/submitEmail", compartment: c.CompartmentID, sender: c.Sender, signer: signer, check: c.CheckEffectAuthority, client: &http.Client{Transport: c.Transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func ociMailbox(value string) bool {
	a, err := mail.ParseAddress(value)
	return err == nil && a.Address == value && a.Name == "" && len(value) <= 320 && !strings.ContainsAny(value, "\r\n")
}

func (m *OCIMailAdapter) Send(ctx context.Context, email Email) error {
	if !validDatabaseID(email.DatabaseID) {
		return ErrOCIEmail
	}
	var subject, body string
	switch email.Template {
	case "free-tier-paused":
		subject = "Your Free database has been paused"
		body = "Your Free database " + email.DatabaseID + " has been paused due to inactivity. Its retained snapshot is available for reactivation. Make a request before deletion begins to reactivate it."
	case "free-tier-reminder-1":
		subject = "Your paused Free database is approaching deletion"
		body = "Your Free database " + email.DatabaseID + " remains paused due to inactivity. Make a request before deletion begins to reactivate it. Continued inactivity leads to permanent deletion."
	case "free-tier-final":
		subject = "Final notice: your Free database is scheduled for deletion"
		body = "Your Free database " + email.DatabaseID + " is scheduled for permanent deletion due to inactivity. Once deletion begins, it cannot be reactivated or recovered."
	default:
		return ErrOCIEmail
	}
	return m.SendMessage(ctx, OCIEmailMessage{To: email.To, Subject: subject, Body: body, OperationKey: email.OperationKey})
}

// SendMessage acknowledges provider acceptance, not delivery to a recipient.
// Rejections, suppressed recipients and malformed acknowledgements fail closed.
func (m *OCIMailAdapter) SendMessage(ctx context.Context, message OCIEmailMessage) error {
	if m == nil || m.signer == nil || m.client == nil || m.check == nil || ctx == nil || !ociMailbox(message.To) || strings.TrimSpace(message.OperationKey) == "" || len(message.OperationKey) > 1024 || strings.TrimSpace(message.Subject) == "" || len(message.Subject) > 998 || strings.ContainsAny(message.Subject, "\r\n") || strings.TrimSpace(message.Body) == "" || len(message.Body) > 64<<10 {
		return ErrOCIEmail
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, err := json.Marshal(map[string]any{"sender": map[string]any{"compartmentId": m.compartment, "senderAddress": map[string]string{"email": m.sender}}, "recipients": map[string]any{"to": []map[string]string{{"email": message.To}}}, "subject": message.Subject, "bodyText": message.Body})
	if err != nil {
		return ErrOCIEmail
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrOCIEmail
	}
	req.Header.Set("Content-Type", "application/json")
	// OCI supports request correlation, but does not deduplicate on this ID.
	operationID := sha256.Sum256([]byte(message.OperationKey))
	req.Header.Set("opc-request-id", fmt.Sprintf("%x", operationID))
	if err := m.signer.Sign(req); err != nil {
		return ErrOCIEmail
	}
	if err := checkReaperEffect(ctx, m.check); err != nil {
		return err
	}
	response, err := m.client.Do(req)
	if err != nil {
		return ErrOCIEmail
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%w (HTTP %d)", ErrOCIEmail, response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return ErrOCIEmail
	}
	var result struct {
		MessageID  string             `json:"messageId"`
		EnvelopeID string             `json:"envelopeId"`
		Suppressed []jsonRawRecipient `json:"suppressedRecipients"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || strings.TrimSpace(result.MessageID) == "" || strings.TrimSpace(result.EnvelopeID) == "" || len(result.Suppressed) != 0 {
		return ErrOCIEmail
	}
	return nil
}

type jsonRawRecipient map[string]any

var _ MailAdapter = (*OCIMailAdapter)(nil)
