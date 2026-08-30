package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// Keep initial connection establishment bounded even when NATS is configured
	// to retry an unavailable server. Reconnects after startup remain enabled so
	// a transient regional outage does not stop the writer.
	natsJournalWriterConnectTimeout = 15 * time.Second
	natsJournalWriterReconnectWait  = 2 * time.Second
)

// NatsJournalWriterRuntime owns the isolated journal-writer connection and its
// private mutation service. The regional controller deliberately has no path
// to either of these credentials or handles.
type NatsJournalWriterRuntime struct {
	client    *nats.Conn
	mutations *NatsOperationJournalMutationService

	completion chan struct{}
	closeOnce  sync.Once
}

// NatsJournalWriterRuntimeStartAsync starts the isolated journal-writer role.
// The role must have been parsed as journal-writer; accepting another command
// here would weaken credential and authority separation at the composition
// boundary.
func NatsJournalWriterRuntimeStartAsync(
	ctx context.Context,
	options *OrchestratorOptions,
) (*NatsJournalWriterRuntime, error) {
	if ctx == nil {
		return nil, errors.New("The journal-writer startup context is required.")
	}
	if options == nil || options.Command != OrchestratorCommandJournalWriter ||
		!journalWriterConfigurationComplete(options.AuthoritativeJournal) {
		return nil, errors.New("The isolated journal-writer role requires complete writer credentials.")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	journal := options.AuthoritativeJournal
	if err := validateJournalAuthorityPublicKey(journal.AuthorityPublicKey); err != nil {
		return nil, err
	}

	client, err := connectJournalWriter(ctx, options.NatsURL, journal)
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			client.Close()
		}
	}()

	js, err := jetstream.New(client)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	topology := NewNatsTopology(options.Cell, options.Replicas, options.Instance)
	// OpenAsync is intentionally used for both stores. In addition to opening
	// the bucket, it validates the exact immutable stream configuration and the
	// journal's disabled batch-publish policy; no controller-side provisioning
	// or reconfiguration is permitted here.
	operations, err := NatsOperationJournalStore.OpenAsync(
		ctx, js, topology.Operations(), client)
	if err != nil {
		return nil, err
	}
	proofConsumptions, err := NatsOperationJournalStore.OpenAsync(
		ctx, js, topology.OperationProofConsumptions(), client)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	verifier := NewNatsOperationJournalMutationAuthorityVerifier(journal.AuthorityPublicKey)
	replies, err := NatsOperationJournalMutationReplySignerLoad(journal.ReplySigningKeyFile)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		replies.Dispose()
		return nil, err
	}

	controllerIdentities := make(map[string]struct{}, len(journal.EligibleControllerIdentities))
	for identity := range journal.EligibleControllerIdentities {
		controllerIdentities[identity] = struct{}{}
	}
	mutations, err := NatsOperationJournalMutationServiceStartAsync(
		ctx,
		client,
		operations,
		proofConsumptions,
		topology,
		verifier,
		controllerIdentities,
		replies,
		true,
	)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		mutations.Dispose()
		return nil, err
	}

	runtime := &NatsJournalWriterRuntime{
		client:     client,
		mutations:  mutations,
		completion: make(chan struct{}),
	}
	cleanup = false

	// Cancellation of the startup context is the process lifecycle signal. A
	// watcher makes that signal close the owned resources as well as the public
	// completion channel, while Close remains safe if both happen concurrently.
	go func() {
		select {
		case <-ctx.Done():
			_ = runtime.Close()
		case <-runtime.completion:
		}
	}()

	return runtime, nil
}

// StartNatsJournalWriterRuntime is a readable alias for callers that do not
// use the migration's *StartAsync naming convention.
func StartNatsJournalWriterRuntime(
	ctx context.Context,
	options *OrchestratorOptions,
) (*NatsJournalWriterRuntime, error) {
	return NatsJournalWriterRuntimeStartAsync(ctx, options)
}

// Completion closes when the runtime has been disposed or its startup
// context is canceled.
func (r *NatsJournalWriterRuntime) Completion() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.completion
}

// Close deterministically tears down the mutation service before closing its
// NATS connection. It is safe to call concurrently and repeatedly.
func (r *NatsJournalWriterRuntime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.mutations != nil {
			r.mutations.Dispose()
		}
		if r.client != nil {
			r.client.Close()
		}
		if r.completion != nil {
			close(r.completion)
		}
	})
	return nil
}

// Dispose is the synchronous Go lifecycle spelling of the C# DisposeAsync
// boundary. Resource teardown itself is synchronous and idempotent.
func (r *NatsJournalWriterRuntime) Dispose() error { return r.Close() }

// DisposeAsync is retained as a migration-friendly spelling for callers that
// model disposable runtimes after the source C# API.
func (r *NatsJournalWriterRuntime) DisposeAsync() error { return r.Close() }

func journalWriterConfigurationComplete(journal *NatsAuthoritativeJournalConfiguration) bool {
	if journal == nil || strings.TrimSpace(journal.NKeyFile) == "" || journal.Tls == nil ||
		strings.TrimSpace(journal.Tls.CaFile) == "" ||
		strings.TrimSpace(journal.Tls.CertificateFile) == "" ||
		strings.TrimSpace(journal.Tls.KeyFile) == "" || len(journal.AuthorityPublicKey) == 0 ||
		strings.TrimSpace(journal.ReplySigningKeyFile) == "" ||
		len(journal.EligibleControllerIdentities) == 0 {
		return false
	}
	for identity := range journal.EligibleControllerIdentities {
		if strings.TrimSpace(identity) == "" {
			return false
		}
	}
	return true
}

func validateJournalAuthorityPublicKey(publicKey []byte) error {
	parsed, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return errors.New("The journal authority public key is invalid.")
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve == nil || key.Curve.Params().Name != elliptic.P256().Params().Name {
		return errors.New("The journal authority public key must be a NIST P-256 ECDSA key.")
	}
	return nil
}

type journalWriterConnectResult struct {
	client *nats.Conn
	err    error
}

func connectJournalWriter(
	ctx context.Context,
	url string,
	journal *NatsAuthoritativeJournalConfiguration,
) (*nats.Conn, error) {
	options := append([]nats.Option{
		nats.Timeout(natsJournalWriterConnectTimeout),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(natsJournalWriterReconnectWait),
		natsNkeyOption(journal.NKeyFile),
	}, journal.Tls.Options()...)

	result := make(chan journalWriterConnectResult, 1)
	go func() {
		client, err := nats.Connect(url, options...)
		result <- journalWriterConnectResult{client: client, err: err}
	}()

	var connected *nats.Conn
	select {
	case outcome := <-result:
		if outcome.err != nil {
			if outcome.client != nil {
				outcome.client.Close()
			}
			return nil, outcome.err
		}
		connected = outcome.client
	case <-ctx.Done():
		// nats.Connect is bounded by its own timeout but has no context API.
		// Ensure a late result is closed rather than leaking a connection after
		// cancellation wins this select.
		go func() {
			outcome := <-result
			if outcome.client != nil {
				outcome.client.Close()
			}
		}()
		return nil, ctx.Err()
	}
	if connected == nil {
		return nil, errors.New("The journal-writer NATS connection was not created.")
	}

	timer := time.NewTimer(natsJournalWriterConnectTimeout)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if connected.IsConnected() {
			if err := ctx.Err(); err != nil {
				connected.Close()
				return nil, err
			}
			return connected, nil
		}
		if connected.IsClosed() {
			connected.Close()
			return nil, errors.New("The journal-writer NATS connection closed before startup completed.")
		}
		select {
		case <-ctx.Done():
			connected.Close()
			return nil, ctx.Err()
		case <-timer.C:
			connected.Close()
			return nil, context.DeadlineExceeded
		case <-ticker.C:
		}
	}
}
