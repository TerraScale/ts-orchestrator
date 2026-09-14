package delivery

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"terrascale.tech/orchestrator/src/orchestrator/protocol"
)

func TestSourceNotFoundErrorMatchesOnlyItsSentinel(t *testing.T) {
	err := SourceNotFoundError{}
	if !errors.Is(err, ErrSourceNotFound) {
		t.Fatal("source-not-found error must match its sentinel")
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("source-not-found error must not match unrelated errors")
	}
}

func signedPush(t *testing.T, after, ref, delivery string) []byte {
	t.Helper()
	return []byte(`{"ref":"` + ref + `","before":"affe000000000000000000000000000000000001","after":"` + after + `","repository":{"full_name":"acme/repo"}}`)
}
func signature(payload, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}
func TestWebhookVerificationChecksSignatureBeforeJSON(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	bad := []byte("not json")
	v := VerifyWebhook(bad, secret, "acme/repo", "application/json", strings.Repeat("0", 64), "f6266f16-1bf3-46a5-9ea4-602e06ead473", "push")
	if v.Error != WebhookInvalidSignature {
		t.Fatalf("error=%v", v.Error)
	}
}
func TestWebhookVerificationRejectsDuplicatePropertiesAndAcceptsDeletion(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	payload := []byte(`{"ref":"refs/heads/main","before":"affe000000000000000000000000000000000001","after":"0000000000000000000000000000000000000000","repository":{"full_name":"acme/repo"}}`)
	v := VerifyWebhook(payload, secret, "acme/repo", "application/json", signature(payload, secret), "f6266f16-1bf3-46a5-9ea4-602e06ead473", "push")
	if !v.Accepted() || !v.Envelope.IsDeletion {
		t.Fatalf("deletion rejected: %#v", v)
	}
	dup := []byte(`{"ref":"refs/heads/main","ref":"refs/heads/main","before":"affe000000000000000000000000000000000001","after":"bffeb74224043ba2feb48d137756c8a9331c449a","repository":{"full_name":"acme/repo"}}`)
	if VerifyWebhook(dup, secret, "acme/repo", "application/json", signature(dup, secret), "f6266f16-1bf3-46a5-9ea4-602e06ead473", "push").Error != WebhookMalformedPayload {
		t.Fatal("duplicate property accepted")
	}
}
func TestWebhookJournalPublishesBeforeAcceptanceAndConverges(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	p := signedPush(t, "bffeb74224043ba2feb48d137756c8a9331c449a", "refs/heads/develop", "f6266f16-1bf3-46a5-9ea4-602e06ead473")
	e := VerifyWebhook(p, secret, "acme/repo", "application/json", signature(p, secret), "f6266f16-1bf3-46a5-9ea4-602e06ead473", "push").Envelope
	l := NewMemoryLedger()
	pub := &recordingPublisher{}
	j := NewWebhookJournal(l, pub)
	one, err := j.Accept(context.Background(), e)
	if err != nil || !one.CanAcknowledge() {
		t.Fatalf("first=%v %v", one, err)
	}
	two, err := j.Accept(context.Background(), e)
	if err != nil || two.Disposition != JournalDuplicate || len(pub.events) != 1 {
		t.Fatalf("duplicate=%v err=%v events=%d", two, err, len(pub.events))
	}
}

func TestNatsEventPublisherEmitsOnlyTheBoundV2ForgejoEnvelope(t *testing.T) {
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	t.Cleanup(func() { instance.Shutdown(); instance.WaitForShutdown() })
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("test NATS server did not become ready")
	}
	client, err := nats.Connect(instance.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	js, err := jetstream.New(client)
	if err != nil {
		t.Fatal(err)
	}
	subject := protocol.NatsSubjectTaxonomy.CiForgejoTriggerSubject()
	if _, err := js.CreateStream(context.Background(), jetstream.StreamConfig{
		Name: "GLOBAL_CI", Subjects: []string{subject}, Storage: jetstream.MemoryStorage,
	}); err != nil {
		t.Fatal(err)
	}
	subscription, err := client.SubscribeSync(subject)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = subscription.Unsubscribe() })
	if err := client.Flush(); err != nil {
		t.Fatal(err)
	}

	secret := []byte(strings.Repeat("s", 32))
	payload := signedPush(t, "bffeb74224043ba2feb48d137756c8a9331c449a", "refs/heads/develop", "f6266f16-1bf3-46a5-9ea4-602e06ead473")
	event := VerifyWebhook(payload, secret, "acme/repo", "application/json", signature(payload, secret), "f6266f16-1bf3-46a5-9ea4-602e06ead473", "push").Envelope
	publisher := NatsEventPublisher{JS: js}
	if err := publisher.Publish(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	message, err := subscription.NextMsg(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	envelope, encodedPayload, err := protocol.UnmarshalMessagingEnvelope(
		message.Data, subject, map[string]struct{}{"forgejo-webhook": {}})
	if err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != protocol.MessagingSchemaVersionCurrent || envelope.MessageId.Value != event.DeliveryID {
		t.Fatalf("Forgejo envelope = %#v", envelope)
	}
	var document eventDocument
	if err := json.Unmarshal(encodedPayload, &document); err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != protocol.ProtocolVersion.Current() || document.DeliveryID != event.DeliveryID {
		t.Fatalf("Forgejo payload = %#v", document)
	}
	if err := (NatsEventPublisher{JS: js, Subject: subject + ".alternate"}).Publish(context.Background(), event); err == nil {
		t.Fatal("alternate Forgejo subject was accepted")
	}
}

type recordingPublisher struct{ events []*WebhookEnvelope }

func (p *recordingPublisher) Publish(_ context.Context, e *WebhookEnvelope) error {
	p.events = append(p.events, e)
	return nil
}
func TestWebhookHandlerBoundsBody(t *testing.T) {
	secretFile := t.TempDir() + "/secret"
	if err := os.WriteFile(secretFile, []byte(strings.Repeat("s", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := WebhookConfig{ListenAddress: "http://127.0.0.1:1", Path: "/forgejo", Repository: "acme/repo", SecretFile: secretFile}
	h, err := NewWebhookHandler(cfg, NewWebhookJournal(NewMemoryLedger(), nil))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	r := httptest.NewRequest(http.MethodPost, "http://x/forgejo", strings.NewReader(strings.Repeat("x", MaximumWebhookBody+1)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d", w.Code)
	}
}
