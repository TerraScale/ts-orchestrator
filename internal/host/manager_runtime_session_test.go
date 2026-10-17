package host

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// The real host session path below transports a real native signature but does
// not claim that this ordinary test host is an admitted native manager.
func TestManagerRuntimeSessionCarrierPinsOriginalAndAllowsFutureObservation(t *testing.T) {
	c, _, _, mutations, _ := testController(t)
	key := registerTestHost(t, c)
	reader := &Reader{controller: c}
	sessionID := entityid.New()
	acquire := signedHostRequest(t, key, "session", sessionID, 0, sessionOperation{Kind: "acquire"})
	result, err := c.handleSession(t.Context(), acquire)
	if err != nil {
		t.Fatal(err)
	}
	current := result.(session)
	original, err := reader.ReadManagerRuntimeSession(t.Context(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	signed, cert, ca, nativeKey := managerBindingFixture(t)
	r := original.Registration()
	signed.Binding.HostID, signed.Binding.HostNode = r.ID, r.Node
	signed.Binding.HostPublicKey, signed.Binding.NATSUserPublicKey = r.PublicKey, r.NATSUserPublicKey
	signed.Binding.HostSessionID, signed.Binding.HostSessionEpoch = sessionID, current.Epoch
	signed.Binding.RegistrationGeneration, signed.Binding.RegistrationRevision = r.Generation, original.RegistrationRevision()
	signed.Binding.SourceRevision = original.SourceRevision()
	signManagerBindingFixture(t, &signed, nativeKey)
	install := signedHostRequest(t, key, "session", sessionID, current.Epoch, sessionOperation{Kind: "renew", ManagerRuntimeBinding: &signed})
	if _, err := c.handleSession(t.Context(), install); err != nil {
		t.Fatal(err)
	}
	if original.Revalidate(t.Context()) == nil {
		t.Fatal("pre-install source followed a changed carrier")
	}
	if err := VerifySignedManagerRuntimeBinding(signed, cert, ca, signed.Binding.SwarmClusterID, time.Now()); err != nil {
		t.Fatal(err)
	}
	held, err := reader.ReadManagerRuntimeSession(t.Context(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	installed, ok := held.SignedBinding()
	if !ok || !sameManagerCarrier(&installed, &signed) {
		t.Fatal("actual host readback lost the native-signed carrier")
	}
	if err := VerifySignedManagerRuntimeBinding(installed, cert, ca, installed.Binding.SwarmClusterID, time.Now()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*SignedManagerRuntimeBinding){
		"candidate":  func(s *SignedManagerRuntimeBinding) { s.Binding.RuntimeCandidateID = entityid.New() },
		"binary":     func(s *SignedManagerRuntimeBinding) { s.Binding.BinarySHA256 = strings.Repeat("b", 64) },
		"session":    func(s *SignedManagerRuntimeBinding) { s.Binding.HostSessionID = entityid.New() },
		"expiry":     func(s *SignedManagerRuntimeBinding) { s.Binding.ExpiresAt = s.Binding.ExpiresAt.Add(time.Second) },
		"signature":  func(s *SignedManagerRuntimeBinding) { s.Signature[0] ^= 1 },
		"cluster CA": func(s *SignedManagerRuntimeBinding) { s.Binding.ClusterCASHA256 = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := installed.Clone()
			change(&changed)
			if VerifySignedManagerRuntimeBinding(changed, cert, ca, installed.Binding.SwarmClusterID, time.Now()) == nil {
				t.Fatal("accepted replaced signed host carrier")
			}
		})
	}
	if VerifySignedManagerRuntimeBinding(installed, cert, ca, installed.Binding.SwarmClusterID, installed.Binding.ExpiresAt) == nil {
		t.Fatal("revived original expired binding")
	}
	_, otherCert, _, _ := managerBindingFixture(t)
	if VerifySignedManagerRuntimeBinding(installed, otherCert, ca, installed.Binding.SwarmClusterID, time.Now()) == nil {
		t.Fatal("accepted replacement current certificate")
	}
	for _, digest := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		binding := installed.Binding
		binding.BinarySHA256 = digest
		if _, err := ManagerRuntimeSigningBytes(binding); err == nil {
			t.Fatalf("accepted invalid executable digest %q", digest)
		}
	}
	var acquired session
	if err := applyManagerRuntimeCarrier(&acquired, held.current, Registration{}, request{}, sessionOperation{Kind: "acquire", ManagerRuntimeBinding: &installed}, 1, 1, time.Now()); err == nil {
		t.Fatal("acquire adopted previous session manager binding")
	}
	if acquired.ManagerRuntimeBinding != nil {
		t.Fatal("new session inherited old signed manager")
	}
	digest := held.BindingSHA256()
	if digest == "" {
		t.Fatal("no exact carrier digest")
	}
	// Exact request replay is idempotent; a signed same-nonce different payload is not.
	if _, err := c.handleSession(t.Context(), install); err != nil {
		t.Fatal(err)
	}
	changedReplay := install
	changedReplay.Payload, err = json.Marshal(sessionOperation{Kind: "renew"})
	if err != nil {
		t.Fatal(err)
	}
	if err := signRequest(&changedReplay, key, "gru"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.handleSession(t.Context(), changedReplay); err == nil {
		t.Fatal("same nonce erased the signed carrier")
	}
	renew := signedHostRequest(t, key, "session", sessionID, current.Epoch, sessionOperation{Kind: "renew"})
	if _, err := c.handleSession(t.Context(), renew); err != nil {
		t.Fatal(err)
	}
	if err := held.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	fresh, err := reader.ReadManagerRuntimeSession(t.Context(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.BindingSHA256() != digest {
		t.Fatal("ordinary renewal changed original signed source")
	}
	stale := signed.Clone()
	stale.Binding.RuntimeCandidateID = entityid.New()
	signManagerBindingFixture(t, &stale, nativeKey)
	staleRequest := signedHostRequest(t, key, "session", sessionID, current.Epoch, sessionOperation{Kind: "renew", ManagerRuntimeBinding: &stale})
	if _, err := c.handleSession(t.Context(), staleRequest); err == nil {
		t.Fatal("stale predecessor replaced manager observation")
	}
	// A separately signed, genuinely fresh observation is future-only.
	replacement := signed.Clone()
	replacement.Binding.SourceRevision = fresh.SourceRevision()
	replacement.Binding.IssuedAt = time.Now().UTC()
	replacement.Binding.ExpiresAt = replacement.Binding.IssuedAt.Add(20 * time.Second)
	replacement.Binding.RuntimeCandidateID = entityid.New()
	signManagerBindingFixture(t, &replacement, nativeKey)
	next := signedHostRequest(t, key, "session", sessionID, current.Epoch, sessionOperation{Kind: "renew", ManagerRuntimeBinding: &replacement})
	if _, err := c.handleSession(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	if held.Revalidate(context.Background()) == nil {
		t.Fatal("old held proof followed a new observation")
	}
	latest, err := reader.ReadManagerRuntimeSession(t.Context(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.FindManagerRuntimeSession(t.Context(), replacement.Binding.NodeID); err != nil {
		t.Fatal(err)
	}
	if latest.BindingSHA256() == digest {
		t.Fatal("fresh signed source kept old digest")
	}
	wire, ok := latest.SignedBinding()
	if !ok || !sameManagerCarrier(&wire, &replacement) {
		t.Fatal("fresh source lost exact original envelope")
	}
	// Reads return copies, and cancellation cannot be replaced by Background.
	wire.Signature[0] ^= 1
	if err := latest.Revalidate(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancelled, err := reader.ReadManagerRuntimeSession(ctx, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if cancelled.Revalidate(context.Background()) == nil {
		t.Fatal("Background revived original cancelled source")
	}
	expiringCtx, expire := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer expire()
	expiring, err := reader.ReadManagerRuntimeSession(expiringCtx, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	<-expiringCtx.Done()
	if expiring.Revalidate(context.Background()) == nil {
		t.Fatal("Background revived original expired observation")
	}
	if _, err := reader.ReadManagerRuntimeSession(t.Context(), "node-a"); err != nil {
		t.Fatal("expired held observation blocked independent new observation:", err)
	}
	// An unreadable inventory member cannot hide a duplicate native identity.
	if _, err := mutations.CommitHostMutation(t.Context(), 1, authority.MutationRegistration, "gru.node-b", entityid.New(), 0, []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.FindManagerRuntimeSession(t.Context(), replacement.Binding.NodeID); err == nil {
		t.Fatal("ignored unreadable origin inventory member")
	}
}

func TestExpiredManagerCarrierDoesNotExpireActualHostSession(t *testing.T) {
	c, _, _, _, _ := testController(t)
	key := registerTestHost(t, c)
	id := entityid.New()
	acquire := signedHostRequest(t, key, "session", id, 0, sessionOperation{Kind: "acquire"})
	if _, err := c.handleSession(t.Context(), acquire); err != nil {
		t.Fatal(err)
	}
	current, rev, _, err := c.sessionSnapshot(t.Context(), sessionKey("gru", "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	signed, _, _, nativeKey := managerBindingFixture(t)
	signed.Binding.IssuedAt = time.Now().Add(-25 * time.Second)
	signed.Binding.ExpiresAt = time.Now().Add(-time.Second)
	signManagerBindingFixture(t, &signed, nativeKey)
	current.ManagerRuntimeBinding = &signed
	if _, err := c.cas(t.Context(), sessionKey("gru", "node-a"), current, rev); err != nil {
		t.Fatal(err)
	}
	reader := &Reader{controller: c}
	if _, err := reader.ReadManagerRuntimeSession(t.Context(), "node-a"); err != nil {
		t.Fatal("inert expired envelope blocked genuine future source observation:", err)
	}
	renew := signedHostRequest(t, key, "session", id, current.Epoch, sessionOperation{Kind: "renew"})
	if _, err := c.handleSession(t.Context(), renew); err != nil {
		t.Fatal("inert expired envelope blocked ordinary renewal:", err)
	}
}

func TestManagerRuntimeSessionRejectsShortenedCurrentExpiry(t *testing.T) {
	c, _, _, _, _ := testController(t)
	key := registerTestHost(t, c)
	acquire := signedHostRequest(t, key, "session", entityid.New(), 0, sessionOperation{Kind: "acquire"})
	if _, err := c.handleSession(t.Context(), acquire); err != nil {
		t.Fatal(err)
	}
	reader := &Reader{controller: c}
	held, err := reader.ReadManagerRuntimeSession(t.Context(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	current, revision, _, err := c.sessionSnapshot(t.Context(), sessionKey("gru", "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	current.ExpiresAt = time.Now().Add(10 * time.Second)
	if _, err := c.cas(t.Context(), sessionKey("gru", "node-a"), current, revision); err != nil {
		t.Fatal(err)
	}
	if held.Revalidate(context.Background()) == nil {
		t.Fatal("held observation outlived shortened current session")
	}
	if _, err := reader.ReadManagerRuntimeSession(t.Context(), "node-a"); err != nil {
		t.Fatal("shorter current source cannot be freshly observed:", err)
	}
}

func TestManagerRuntimeSessionSourceExpiryIsIndependentOfOperationDeadline(t *testing.T) {
	c, _, _, _, _ := testController(t)
	key := registerTestHost(t, c)
	id := entityid.New()
	acquire := signedHostRequest(t, key, "session", id, 0, sessionOperation{Kind: "acquire"})
	if _, err := c.handleSession(t.Context(), acquire); err != nil {
		t.Fatal(err)
	}
	original, _, _, err := c.sessionSnapshot(t.Context(), sessionKey("gru", "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	operationDeadline, _ := ctx.Deadline()
	reader := &Reader{controller: c}
	held, err := reader.ReadManagerRuntimeSession(ctx, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if !held.ExpiresAt().Equal(operationDeadline) || !held.SessionSourceExpiresAt().Equal(original.ExpiresAt) ||
		!held.ExpiresAt().Before(held.SessionSourceExpiresAt()) {
		t.Fatal("source expiry followed the shorter operation deadline")
	}
	renew := signedHostRequest(t, key, "session", id, original.Epoch, sessionOperation{Kind: "renew"})
	if _, err := c.handleSession(ctx, renew); err != nil {
		t.Fatal(err)
	}
	if err := held.Revalidate(ctx); err != nil {
		t.Fatal(err)
	}
	if !held.SessionSourceExpiresAt().Equal(original.ExpiresAt) || !held.ExpiresAt().Equal(operationDeadline) {
		t.Fatal("held source adopted a later session renewal")
	}
	current, revision, _, err := c.sessionSnapshot(ctx, sessionKey("gru", "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	if !current.ExpiresAt.After(held.SessionSourceExpiresAt()) {
		t.Fatal("renewal did not advance actual stored expiry")
	}
	current.ExpiresAt = operationDeadline.Add(5 * time.Second)
	if !current.ExpiresAt.After(held.ExpiresAt()) || !current.ExpiresAt.Before(held.SessionSourceExpiresAt()) {
		t.Fatal("fixture did not shorten the source above the operation deadline")
	}
	if _, err := c.cas(ctx, sessionKey("gru", "node-a"), current, revision); err != nil {
		t.Fatal(err)
	}
	if held.Revalidate(context.Background()) == nil {
		t.Fatal("held raw source survived shortening above operation cap")
	}
	fresh, err := reader.ReadManagerRuntimeSession(ctx, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.SessionSourceExpiresAt().Equal(current.ExpiresAt) || !fresh.ExpiresAt().Equal(operationDeadline) {
		t.Fatal("fresh source did not retain its own exact stored expiry")
	}
	cancel()
	if fresh.Revalidate(context.Background()) == nil {
		t.Fatal("raw source getter revived cancelled original observation")
	}
	var zero ManagerRuntimeSession
	if !zero.SessionSourceExpiresAt().IsZero() || zero.Revalidate(context.Background()) == nil {
		t.Fatal("zero source snapshot qualified")
	}
}
