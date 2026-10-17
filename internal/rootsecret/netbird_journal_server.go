package rootsecret

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/journal"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/nats-io/jwt/v2"
)

// NetBirdJournalServer keeps publication, writer TLS and protected CAS private.
// Only the original admitted root process may open its fixed private listener.
type NetBirdJournalServer struct {
	mu          sync.Mutex
	gate        sync.Mutex
	closed      bool
	requests    sync.WaitGroup
	closeOnce   sync.Once
	serving     atomic.Bool
	publication *netBirdJournalPublication
	writer      *netBirdJournalWriterTLS
	ctx         context.Context
	cancel      context.CancelFunc
	expires     time.Time
	listener    net.Listener
	http        *http.Server
}

func (*NetBirdJournalServer) String() string          { return "NetBird journal server [redacted]" }
func (server *NetBirdJournalServer) GoString() string { return server.String() }

func OpenNetBirdJournalServer(ctx context.Context, custody *NetBirdStartupCustody) (*NetBirdJournalServer, error) {
	if ctx == nil || custody == nil || custody.Guard(ctx) != nil {
		return nil, ErrDelivery
	}
	publication, err := openNetBirdJournalPublication(ctx, custody)
	if err != nil {
		if errors.Is(err, ErrNetBirdJournalBirthUnproven) {
			return nil, ErrNetBirdJournalBirthUnproven
		}
		return nil, ErrDelivery
	}
	retained := false
	defer func() {
		if !retained {
			publication.close()
		}
	}()
	writer, err := openNetBirdJournalWriterTLS(ctx, publication.source)
	if err != nil {
		return nil, ErrDelivery
	}
	current, err := publication.currentDeadline(ctx)
	if err != nil {
		return nil, ErrDelivery
	}
	deadline := minDeadline(writer.expires, minDeadline(publication.expires, current))
	lifetime, cancel := context.WithDeadline(publication.ctx, deadline)
	server := &NetBirdJournalServer{publication: publication, writer: writer, ctx: lifetime, cancel: cancel, expires: deadline}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	server.http = &http.Server{Handler: http.HandlerFunc(server.serveHTTP), TLSConfig: writer.config, Protocols: protocols,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10,
		BaseContext: func(net.Listener) context.Context { return lifetime }}
	ctx, stop := netBirdStartupReadContext(ctx, lifetime, deadline)
	defer stop()
	listen := net.ListenConfig{}
	server.listener, err = listen.Listen(ctx, "tcp", net.JoinHostPort(publication.source.Underlay().WriterPrivateIP(), "443"))
	if err != nil || server.Guard(ctx) != nil {
		server.Close()
		return nil, ErrDelivery
	}
	retained = true
	context.AfterFunc(lifetime, func() { server.Close() })
	return server, nil
}

func (server *NetBirdJournalServer) Context() context.Context {
	if server == nil {
		return nil
	}
	return server.ctx
}

func (server *NetBirdJournalServer) ExpiresAt() time.Time {
	if server == nil {
		return time.Time{}
	}
	return server.expires
}

func (server *NetBirdJournalServer) Close() error {
	if server == nil {
		return nil
	}
	server.closeOnce.Do(func() {
		server.gate.Lock()
		server.closed = true
		server.gate.Unlock()
		server.cancel()
		server.http.Close()
		if server.listener != nil {
			server.listener.Close()
		}
		server.requests.Wait()
		server.mu.Lock()
		server.publication.close()
		server.mu.Unlock()
	})
	return nil
}

// Serve uses only the retained TLS configuration and original listener once.
func (server *NetBirdJournalServer) Serve() error {
	if server == nil || !server.serving.CompareAndSwap(false, true) || server.Guard(server.ctx) != nil {
		return ErrDelivery
	}
	defer server.Close()
	return server.http.ServeTLS(server.listener, "", "")
}

func (server *NetBirdJournalServer) Guard(ctx context.Context) error {
	if server == nil {
		return ErrDelivery
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	_, err := server.currentDeadline(ctx)
	return err
}

func (server *NetBirdJournalServer) currentDeadline(ctx context.Context) (time.Time, error) {
	if ctx == nil || server.ctx == nil || server.ctx.Err() != nil || server.publication == nil || server.writer == nil || !time.Now().Before(server.expires) {
		return time.Time{}, ErrDelivery
	}
	ctx, stop := netBirdStartupReadContext(ctx, server.ctx, server.expires)
	defer stop()
	tlsDeadline, err := server.writer.currentDeadline(ctx)
	if err != nil {
		return time.Time{}, ErrDelivery
	}
	ctx, stopTLS := context.WithDeadline(ctx, minDeadline(server.expires, tlsDeadline))
	defer stopTLS()
	current, err := server.publication.currentDeadline(ctx)
	deadline := minDeadline(server.expires, minDeadline(tlsDeadline, current))
	if err != nil || server.ctx.Err() != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		return time.Time{}, ErrDelivery
	}
	return deadline, nil
}

func (server *NetBirdJournalServer) serveHTTP(w http.ResponseWriter, request *http.Request) {
	server.gate.Lock()
	if server.closed {
		server.gate.Unlock()
		http.Error(w, "NetBird journal unavailable", http.StatusServiceUnavailable)
		return
	}
	server.requests.Add(1)
	server.gate.Unlock()
	defer server.requests.Done()
	if server.handle(w, request) != nil {
		http.Error(w, "NetBird journal unavailable", http.StatusServiceUnavailable)
	}
}

func (server *NetBirdJournalServer) handle(w http.ResponseWriter, request *http.Request) error {
	if request == nil || request.Method != http.MethodPost || request.ProtoMajor != 1 || request.URL == nil ||
		request.RequestURI != journal.Endpoint || request.URL.Path != journal.Endpoint || request.URL.RawPath != "" ||
		request.URL.RawQuery != "" || request.URL.ForceQuery || request.ContentLength <= 0 || request.ContentLength > journal.MaxMessageBytes ||
		len(request.TransferEncoding) != 0 || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Content-Encoding") != "" ||
		len(request.Header.Values(journal.SignatureHeader)) != 1 {
		return ErrDelivery
	}
	ctx, stop := netBirdStartupReadContext(request.Context(), server.ctx, minDeadline(server.expires, time.Now().Add(30*time.Second)))
	defer stop()
	raw, err := io.ReadAll(http.MaxBytesReader(w, request.Body, journal.MaxMessageBytes))
	closeErr := request.Body.Close()
	if err != nil || closeErr != nil || int64(len(raw)) != request.ContentLength {
		return ErrDelivery
	}
	action, err := journal.DecodeRequest(raw)
	if err != nil || action.Binding.AccountOperationDomain != journal.BootstrapAccountDomain || action.StartedAt.After(time.Now()) ||
		!time.Now().Before(action.FirstDeadline) {
		return ErrDelivery
	}
	ctx, stopAction := context.WithDeadline(ctx, action.FirstDeadline)
	defer stopAction()
	if http.NewResponseController(w).SetWriteDeadline(action.FirstDeadline) != nil {
		return ErrDelivery
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	deadline, err := server.currentDeadline(ctx)
	if err != nil || ctx.Err() != nil || !time.Now().Before(minDeadline(action.FirstDeadline, deadline)) {
		return ErrDelivery
	}
	ctx, stopCurrent := context.WithDeadline(ctx, deadline)
	defer stopCurrent()
	if server.authenticate(ctx, request, action, raw) != nil {
		return ErrDelivery
	}
	boundary := func(check context.Context) error {
		until, err := server.currentDeadline(check)
		if err != nil || ociclient.LimitAdmission(check, minDeadline(action.FirstDeadline, until)) != nil || server.ctx.Err() != nil {
			return ErrDelivery
		}
		return check.Err()
	}
	ctx = ociclient.WithRequestGuard(ctx, boundary)
	store := server.publication.source.Source().Resolver().Store
	if store == nil {
		return ErrDelivery
	}
	record, etag, err := store.Load(ctx, "GRU")
	if err != nil || record.Cell != "GRU" || record.Stage != "reconciled" || record.LeaseID != "" || record.NetBirdManager == nil ||
		record.NetBirdManager.InstanceID != action.Binding.ManagerInstanceID || record.NetBirdManager.RecipeSHA256 != action.Binding.ManagerLaunchRecipeSHA256 {
		return ErrDelivery
	}
	reply := journal.Reply{SchemaVersion: 1, Domain: journal.Domain, Action: action.Action}
	reply.RequestSHA256, err = action.Digest()
	if err != nil {
		return ErrDelivery
	}
	effect := record.NetBirdManager.AccountEffect
	switch action.Action {
	case journal.Ready:
		if effect == nil {
			reply.NextCounter = 1
		} else {
			if effect.Completion == nil || effect.Reservation.Counter == math.MaxUint64 {
				return ErrDelivery
			}
			reply.NextCounter = effect.Reservation.Counter + 1
			reply.PreviousCompletionSHA256, err = journal.CompletionDigest(effect.Reservation, *effect.Completion)
			if err != nil {
				return ErrDelivery
			}
		}
	case journal.Reserve:
		reservation := action.Reservation.Clone()
		if effect == nil {
			if reservation.Counter != 1 || reservation.PreviousCompletionSHA256 != "" {
				return ErrDelivery
			}
		} else if effect.Completion == nil || reservation.Follows(effect.Reservation, *effect.Completion) != nil {
			// An identical pending reservation never yields another permit.
			return ErrDelivery
		}
		next := region.NetBirdAccountEffect{Reservation: reservation}
		if server.commit(ctx, store, record, etag, next) != nil {
			return ErrDelivery
		}
		reply.ReservationSHA256, err = reservation.Digest()
	case journal.Complete:
		if effect == nil || effect.Completion != nil || action.Completion.CompletedAt.After(time.Now()) {
			return ErrDelivery
		}
		actual, actualErr := effect.Reservation.Digest()
		wanted, wantedErr := action.Reservation.Digest()
		if actualErr != nil || wantedErr != nil || actual != wanted {
			return ErrDelivery
		}
		completion := *action.Completion
		next := region.NetBirdAccountEffect{Reservation: effect.Reservation.Clone(), Completion: &completion}
		if server.commit(ctx, store, record, etag, next) != nil {
			return ErrDelivery
		}
		reply.ReservationSHA256 = wanted
		reply.CompletionSHA256, err = journal.CompletionDigest(next.Reservation, completion)
	default:
		return ErrDelivery
	}
	if err != nil {
		return ErrDelivery
	}
	wire, err := reply.Encode(action)
	if err != nil || boundary(ctx) != nil {
		return ErrDelivery
	}
	deadline, err = server.currentDeadline(ctx)
	if err != nil || ctx.Err() != nil || http.NewResponseController(w).SetWriteDeadline(minDeadline(action.FirstDeadline, deadline)) != nil ||
		server.ctx.Err() != nil || !time.Now().Before(minDeadline(action.FirstDeadline, deadline)) {
		return ErrDelivery
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(wire)
	return err
}

func (server *NetBirdJournalServer) authenticate(ctx context.Context, request *http.Request, action journal.Request, raw []byte) error {
	publication := server.publication
	source := publication.source
	if request.Host != net.JoinHostPort(source.Underlay().WriterPrivateIP(), "443") ||
		CheckNetBirdJournalManagerPeer(request.TLS, request.RemoteAddr, publication.material, source, time.Now().UTC()) != nil {
		return ErrDelivery
	}
	expected, err := source.Recipient().JournalExpectation(ctx)
	if err != nil {
		return ErrDelivery
	}
	binding := action.Binding
	credential := publication.credential
	if binding.AccountOperationDomain != journal.BootstrapAccountDomain || binding.ManagerAccountIntentSHA256 != "" ||
		binding.PurposeSHA256 != source.Purpose().Digest() || binding.SourceSHA256 != source.Source().Startup().SourceSHA256() ||
		binding.GrantSHA256 != source.Purpose().GrantDigest() || binding.TemplateSHA256 != source.Purpose().TemplateDigest() ||
		binding.CredentialID != credential.ID || binding.CredentialSubject != credential.Subject || binding.CredentialSHA256 != credential.SHA256 ||
		binding.CurrentID != publication.currentID || binding.CurrentVersion != publication.currentVersion || binding.CurrentSHA256 != publication.currentSHA256 ||
		binding.ManagerInstanceID != source.Underlay().ManagerInstanceID() || binding.ManagerVNICID != source.Underlay().ManagerVNICID() ||
		binding.WriterInstanceID != source.Underlay().WriterInstanceID() || binding.WriterVNICID != source.Underlay().WriterVNICID() ||
		binding.UnderlaySHA256 != source.Underlay().Digest() || binding.ManagerAdmissionSHA256 != expected.AdmissionSHA256 ||
		binding.ManagerLaunchRecipeSHA256 != expected.LaunchRecipeSHA256 || binding.ManagerBinarySHA256 != expected.BinarySHA256 {
		return ErrDelivery
	}
	if action.Reservation != nil {
		mutation := action.Reservation.Mutation
		if mutation.Method != http.MethodPut || len(mutation.Path) <= len("/api/accounts/") || mutation.Path[:len("/api/accounts/")] != "/api/accounts/" {
			return ErrDelivery
		}
	}
	header := request.Header.Get(journal.SignatureHeader)
	signature, err := base64.StdEncoding.Strict().DecodeString(header)
	if err != nil || len(signature) != 64 || base64.StdEncoding.EncodeToString(signature) != header {
		return ErrDelivery
	}
	jwtWire, err := jwt.ParseDecoratedJWT(publication.material.JournalCredentials)
	if err != nil {
		return ErrDelivery
	}
	purpose := source.Purpose().Purpose()
	credentialBinding := bootstrapmaterial.NetBirdJournalCredentialBinding{PurposeSHA256: source.Purpose().Digest(), GrantSHA256: source.Purpose().GrantDigest(),
		TemplateSHA256: source.Purpose().TemplateDigest(), SourceSHA256: source.Source().Startup().SourceSHA256(),
		ManagerSlotID: purpose.Manager.SlotID, WriterSlotID: purpose.Writer.SlotID}
	deadline, err := server.currentDeadline(ctx)
	if err != nil || ctx.Err() != nil || !time.Now().Before(minDeadline(action.FirstDeadline, deadline)) {
		return ErrDelivery
	}
	verified, err := bootstrapmaterial.VerifyNetBirdJournalRequest(jwtWire, source.Source().record.Public.CellAccountNKey,
		source.Source().record.Public.ControllerAccountSignerNKey, credentialBinding, credential.ExpiresAt, time.Now().UTC(), raw, signature)
	if err != nil || verified.ID != credential.ID || verified.Subject != credential.Subject || verified.SHA256 != credential.SHA256 ||
		!verified.IssuedAt.Equal(credential.IssuedAt) || !verified.ExpiresAt.Equal(credential.ExpiresAt) {
		return ErrDelivery
	}
	return nil
}

func (server *NetBirdJournalServer) commit(ctx context.Context, store region.FoundationStore, record region.FoundationRecord, etag string, effect region.NetBirdAccountEffect) error {
	if etag == "" || record.NetBirdManager == nil || server.ctx.Err() != nil {
		return ErrDelivery
	}
	manager := *record.NetBirdManager
	manager.AccountEffect = new(effect.Clone())
	record.NetBirdManager, record.UpdatedAt = &manager, time.Now().UTC()
	deadline, err := server.currentDeadline(ctx)
	if err != nil {
		return ErrDelivery
	}
	ctx, stop := context.WithDeadline(ctx, deadline)
	defer stop()
	// A failed or unknown CAS never becomes success through a later read.
	if _, err := store.CompareAndSwap(ctx, record, etag); err != nil {
		return ErrDelivery
	}
	actual, _, err := store.Load(ctx, "GRU")
	if err != nil || actual.NetBirdManager == nil || actual.NetBirdManager.AccountEffect == nil {
		return ErrDelivery
	}
	wantedDigest, err := effect.Reservation.Digest()
	actualEffect := actual.NetBirdManager.AccountEffect
	actualDigest, actualErr := actualEffect.Reservation.Digest()
	if err != nil || actualErr != nil || wantedDigest != actualDigest || (effect.Completion == nil) != (actualEffect.Completion == nil) {
		return ErrDelivery
	}
	if effect.Completion != nil {
		wanted, err := journal.CompletionDigest(effect.Reservation, *effect.Completion)
		observed, observedErr := journal.CompletionDigest(actualEffect.Reservation, *actualEffect.Completion)
		if err != nil || observedErr != nil || wanted != observed {
			return ErrDelivery
		}
	}
	deadline, err = server.currentDeadline(ctx)
	if err != nil || ctx.Err() != nil || server.ctx.Err() != nil || !time.Now().Before(deadline) {
		return ErrDelivery
	}
	return nil
}
