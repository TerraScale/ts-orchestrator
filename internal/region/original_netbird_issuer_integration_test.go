package region

import (
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func TestOriginalNetBirdOCIRRequiresAuthenticOperatorSession(t *testing.T) {
	if _, err := NewOriginalNetBirdOCIRSession(t.Context(), nil, nil, RetainedFoundation{}); err == nil {
		t.Fatal("absent original operator admitted")
	}
	var session *OriginalNetBirdOCIRSession
	if session.Scopes()[0].IsVerified() || session.Guard(t.Context(), VerifiedOCIRIssuer{}) == nil {
		t.Fatal("absent session supplied issuer authority")
	}
	if _, err := session.Journal(t.Context(), VerifiedOCIRIssuer{}); err == nil {
		t.Fatal("manager proof or empty scope acquired original journal")
	}
	if _, release, err := session.HomeWrite(t.Context()); err == nil || release != nil {
		t.Fatal("absent original operator acquired home IAM")
	}
	var journal *OriginalNetBirdIssuerJournal
	if _, _, err := journal.Load(t.Context(), "missing"); err == nil {
		t.Fatal("absent protected store became a missing issuance key")
	}
	if _, err := journal.CompareAndSwap(t.Context(), "missing", OCIRIssuanceState{}, 0); err == nil {
		t.Fatal("absent protected store accepted an issuance")
	}
	if _, err := journal.BeginEffect(nil); err == nil {
		t.Fatal("absent original journal admitted a physical effect")
	}
}

func originalNetBirdIssuerHistoryFixture(t *testing.T) (*OriginalFoundationNetBirdManager, *OriginalNetBirdIssuerJournal, string) {
	t.Helper()
	now := time.Now().UTC()
	installation := entityid.Derive("original-netbird-issuer-test")
	tenancy := "ocid1.tenancy.oc1..original"
	digest := strings.Repeat("a", 64)
	target := vaultsecret.Target{CompartmentID: "ocid1.compartment.oc1..escrow", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.escrow", KeyID: "ocid1.key.oc1.sa-saopaulo-1.escrow"}
	manager := &OriginalFoundationNetBirdManager{GrantSHA256: digest, Intent: NetBirdManagerIntent{
		Material:   new(NetBirdMaterialAuthority{Context: netBirdMaterialContext{InstallationID: installation, TenancyID: tenancy}}),
		Components: new([3]NetBirdComponentAuthorityIntent{}),
	}}
	var first VerifiedOCIRIssuer
	for index, role := range netBirdComponentRoles() {
		principal, email, secret, err := OCIRServiceIdentity(installation, "gru.ocir.io/ns/"+role)
		if err != nil {
			t.Fatal(err)
		}
		intent := OCIRIssuerIntent{OCIRegion: foundationHomeRegion, RegistryHost: "gru.ocir.io", RegistryNamespace: "ns", RepositoryName: role,
			RepositoryCompartmentID: target.CompartmentID, VaultTarget: target, PrincipalName: principal, PrincipalEmail: email, SecretName: secret}
		manager.Intent.Components[index].Issuer = intent
		if index == 0 {
			first = VerifiedOCIRIssuer{intent: intent, tenancyID: tenancy, installationID: installation, generation: 1, grantDigest: digest, expires: now.Add(time.Minute)}
		}
	}
	key, err := first.JournalKey()
	if err != nil {
		t.Fatal(err)
	}
	foundation := entityid.Derive("regional-foundation", tenancy, "GRU", "1")
	journal := &OriginalNetBirdIssuerJournal{session: &OriginalNetBirdOCIRSession{original: FoundationRecord{OperationID: foundation, Epoch: 1}, deadline: first.ExpiresAt()}, scope: first}
	entry := OCIRIssuanceEntry{Revision: 1,
		Origin: OCIRIssuanceOrigin{GrantSHA256: digest, Generation: 1, FoundationOperation: foundation, Epoch: 1, ExpiresAt: first.ExpiresAt()},
		State: OCIRIssuanceState{ScopeHash: strings.TrimPrefix(key, "ocir-issuer."), Generation: 1, GrantDigest: digest,
			OperationID: "6b965eed-713f-4ff9-b5e0-42cd4a11cfa1", Stage: "vault-pending", UserID: "ocid1.user.oc1..pull",
			TokenOperation: "7ae432c4-8174-4208-bc07-cf9f9d2ac2a5", TokenStarted: now, TokenExpires: now.Add(30 * time.Second), TokenID: "ocid1.credential.oc1..uncertain", PendingHash: strings.Repeat("b", 64)},
		Attempts: map[string]OCIRCredentialAttempt{},
		Requests: map[string]OCIRIssuerRequest{strings.Repeat("c", 64): {Method: "POST", URL: "https://identity.sa-saopaulo-1.oci.oraclecloud.com/20160918/users/pull/authTokens",
			BodySHA256: strings.Repeat("d", 64), FirstAttemptAt: now, Deadline: now.Add(30 * time.Second), GrantSHA256: digest, Epoch: 1,
			Dispatches: []OCIRIssuerDispatch{{StartedAt: now}}}},
	}
	if err := journal.retainAttempt(&entry, OCIRIssuanceEntry{}); err != nil {
		t.Fatal(err)
	}
	manager.OCIRIssuances = map[string]OCIRIssuanceEntry{key: entry}
	if err := validateOriginalNetBirdOCIRJournal(manager); err != nil {
		t.Fatalf("valid nested uncertain history: %v", err)
	}
	return manager, journal, key
}

func cloneOriginalNetBirdIssuerHistory(t *testing.T, manager *OriginalFoundationNetBirdManager) *OriginalFoundationNetBirdManager {
	t.Helper()
	wire, err := json.Marshal(manager)
	if err != nil {
		t.Fatal(err)
	}
	var copy OriginalFoundationNetBirdManager
	if err := json.Unmarshal(wire, &copy); err != nil {
		t.Fatal(err)
	}
	return &copy
}

func TestOriginalNetBirdOCIRNestedHistoryCannotBeResetOrExtended(t *testing.T) {
	manager, _, key := originalNetBirdIssuerHistoryFixture(t)
	if err := retainOriginalNetBirdOCIRJournal(manager, cloneOriginalNetBirdIssuerHistory(t, manager)); err != nil {
		t.Fatal(err)
	}
	if err := retainOriginalNetBirdOCIRJournal(nil, manager); err == nil {
		t.Fatal("new manager child adopted existing credential history")
	}
	for name, mutate := range map[string]func(*OCIRIssuanceEntry){
		"origin":           func(e *OCIRIssuanceEntry) { e.Origin.FoundationOperation = entityid.Derive("foreign") },
		"attempt omission": func(e *OCIRIssuanceEntry) { e.Attempts = nil },
		"wire omission":    func(e *OCIRIssuanceEntry) { e.Requests = nil },
		"active expiry":    func(e *OCIRIssuanceEntry) { e.Revision++; e.State.TokenExpires = e.State.TokenExpires.Add(time.Second) },
		"request expiry": func(e *OCIRIssuanceEntry) {
			for id, request := range e.Requests {
				request.Deadline = request.Deadline.Add(time.Second)
				e.Requests[id] = request
			}
		},
		"recipient": func(e *OCIRIssuanceEntry) {
			for id, attempt := range e.Attempts {
				attempt.VaultID = "ocid1.vault.oc1.sa-saopaulo-1.foreign"
				e.Attempts[id] = attempt
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			next := cloneOriginalNetBirdIssuerHistory(t, manager)
			entry := next.OCIRIssuances[key]
			mutate(&entry)
			next.OCIRIssuances[key] = entry
			if err := retainOriginalNetBirdOCIRJournal(manager, next); err == nil {
				t.Fatal("original uncertain authority or history changed")
			}
		})
	}
	next := cloneOriginalNetBirdIssuerHistory(t, manager)
	next.OCIRIssuances = nil
	if err := retainOriginalNetBirdOCIRJournal(manager, next); err == nil {
		t.Fatal("nested issuance sibling removed")
	}
	next = cloneOriginalNetBirdIssuerHistory(t, manager)
	next.OCIRIssuances["ocir-issuer."+strings.Repeat("f", 64)] = next.OCIRIssuances[key]
	if err := validateOriginalNetBirdOCIRJournal(next); err == nil {
		t.Fatal("unsigned fourth recipient entered original manager journal")
	}
}

func TestOriginalNetBirdOCIRRetainsPublicationAndUncertainDispatch(t *testing.T) {
	manager, journal, key := originalNetBirdIssuerHistoryFixture(t)
	next := cloneOriginalNetBirdIssuerHistory(t, manager)
	previous := next.OCIRIssuances[key]
	entry := next.OCIRIssuances[key]
	entry.Revision++
	entry.State.Stage, entry.State.TokenOperation, entry.State.PendingHash = "ready", "", ""
	entry.State.SecretID, entry.State.Version, entry.State.Hash = "ocid1.vaultsecret.oc1.sa-saopaulo-1.pull", 1, strings.Repeat("e", 64)
	entry.State.PublishedAt = time.Now().UTC()
	if err := journal.retainAttempt(&entry, previous); err != nil {
		t.Fatal(err)
	}
	next.OCIRIssuances[key] = entry
	if err := retainOriginalNetBirdOCIRJournal(manager, next); err != nil {
		t.Fatal(err)
	}
	attempt := entry.Attempts[previous.State.TokenOperation]
	if attempt.SecretID != entry.State.SecretID || attempt.Version != 1 || attempt.Hash != entry.State.Hash || !attempt.PublishedAt.Equal(entry.State.PublishedAt) ||
		attempt.PendingHash != previous.State.PendingHash || attempt.TokenID != previous.State.TokenID || len(entry.Requests) != 1 {
		t.Fatal("publication erased original credential attempt or unknown dispatch")
	}
	for _, request := range entry.Requests {
		if !request.Dispatches[0].FinishedAt.IsZero() || request.Dispatches[0].Sent {
			t.Fatal("uncertain physical outcome became a successful send")
		}
	}
	changed := cloneOriginalNetBirdIssuerHistory(t, next)
	value := changed.OCIRIssuances[key]
	for id, receipt := range value.Attempts {
		receipt.Hash = strings.Repeat("f", 64)
		value.Attempts[id] = receipt
	}
	changed.OCIRIssuances[key] = value
	if err := retainOriginalNetBirdOCIRJournal(next, changed); err == nil {
		t.Fatal("published credential receipt was rewritten")
	}
}
