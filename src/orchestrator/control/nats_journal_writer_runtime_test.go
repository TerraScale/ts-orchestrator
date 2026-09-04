package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
)

func TestNatsJournalWriterRuntimeRequiresIsolatedWriterRole(t *testing.T) {
	ctx := context.Background()
	if _, err := NatsJournalWriterRuntimeStartAsync(ctx, nil); err == nil {
		t.Fatal("nil options should be rejected")
	}

	options := &OrchestratorOptions{Command: OrchestratorCommandCheck}
	if _, err := NatsJournalWriterRuntimeStartAsync(ctx, options); err == nil {
		t.Fatal("non-writer command should be rejected")
	}
}

func TestNatsJournalWriterRuntimeCancellationFailsClosed(t *testing.T) {
	seed := "this-seed-must-not-appear-in-errors"
	options := &OrchestratorOptions{
		Command: OrchestratorCommandJournalWriter,
		NatsURL: "nats://127.0.0.1:1",
		AuthoritativeJournal: &NatsAuthoritativeJournalConfiguration{
			NKeyFile: seed,
			Tls: &NatsTlsFiles{
				CaFile:          "ca.pem",
				CertificateFile: "certificate.pem",
				KeyFile:         "key.pem",
			},
			AuthorityPublicKey:           []byte("authority"),
			ReplySigningKeyFile:          "reply.pem",
			EligibleControllerIdentities: map[string]struct{}{"Uexample": {}},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NatsJournalWriterRuntimeStartAsync(ctx, options)
	if err == nil || err != context.Canceled {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if strings.Contains(err.Error(), seed) {
		t.Fatalf("startup error exposed credential material: %q", err)
	}
}

func TestNatsJournalWriterRuntimeCloseIsIdempotent(t *testing.T) {
	serverOptions := &server.Options{Host: "127.0.0.1", Port: -1}
	instance, err := server.NewServer(serverOptions)
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	t.Cleanup(func() {
		instance.Shutdown()
		instance.WaitForShutdown()
	})
	if !instance.ReadyForConnections(5 * time.Second) {
		t.Fatal("test NATS server did not become ready")
	}

	client, err := nats.Connect(instance.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replies := NewNatsOperationJournalMutationReplySignerForKey(key)
	lifetimeCtx, lifetime := context.WithCancel(context.Background())
	service := shared.NewNatsSvcServer(client, shared.NatsSvcConfig{Name: "test-journal-writer"})
	mutations := NewNatsOperationJournalMutationService(service, replies, lifetime)
	runtime := &NatsJournalWriterRuntime{
		client:     client,
		mutations:  mutations,
		completion: make(chan struct{}),
	}

	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := runtime.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}()
	}
	wait.Wait()
	select {
	case <-runtime.Completion():
	case <-time.After(time.Second):
		t.Fatal("completion did not close")
	}
	if !client.IsClosed() {
		t.Fatal("close did not close the owned NATS connection")
	}
	if err := runtime.Dispose(); err != nil {
		t.Fatalf("second dispose: %v", err)
	}
	if err := runtime.Dispose(); err != nil {
		t.Fatalf("third dispose: %v", err)
	}
	select {
	case <-lifetimeCtx.Done():
	default:
		t.Fatal("close did not stop the mutation service lifetime")
	}
}

func TestValidateJournalAuthorityPublicKeyRejectsNonECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateJournalAuthorityPublicKey(der); err != nil {
		t.Fatalf("valid authority key rejected: %v", err)
	}
	if err := validateJournalAuthorityPublicKey([]byte("not-a-key")); err == nil {
		t.Fatal("invalid authority key accepted")
	}
}

func TestNatsOperationJournalMutationClientRejectsNilDependencies(t *testing.T) {
	var client *NatsOperationJournalMutationClient
	if _, err := client.CreateAsync(context.Background(), "operation.key", "value"); err == nil {
		t.Fatal("nil mutation client was accepted")
	}

	client = &NatsOperationJournalMutationClient{}
	if _, err := client.ReadRuntimeLifecycleAsync(context.Background(), "cell", "key"); err == nil {
		t.Fatal("mutation client with nil dependencies was accepted")
	}
}

func TestNatsOperationJournalReplySignerLoadRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.pem")
	if err := os.WriteFile(target, []byte("not-a-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NatsOperationJournalMutationReplySignerLoad(link); err == nil {
		t.Fatal("symlink reply signing key was accepted")
	}
}
