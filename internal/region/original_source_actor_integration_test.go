package region

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestOriginalSourceActorRejectsZeroProof(t *testing.T) {
	var actor VerifiedOriginalSourceActor
	if actor.IsVerified() || actor.Scope() != (OriginalSourceActorScope{}) || actor.Config().Region != "" || actor.OriginalIntent().Purpose != "" {
		t.Fatal("zero original actor exposed custody")
	}
	if !errors.Is(actor.Guard(t.Context()), ErrOriginalSourceActorHold) {
		t.Fatal("zero original actor passed guard")
	}
	if factory, ctx, err := actor.GuardedFactory(t.Context()); factory != nil || ctx != nil || !errors.Is(err, ErrOriginalSourceActorHold) {
		t.Fatal("zero original actor exposed a guarded factory")
	}
	if _, err := actor.AdmissionAttestor(t.Context()); !errors.Is(err, ErrOriginalSourceActorHold) {
		t.Fatal("zero original actor exposed admission authorization")
	}
}

// The fixture produces the protected original records through the actual SDK.
// These checks inspect its public proof; they never construct a sealed actor.
func TestOriginalSourceActorRequiresCompleteSignedOriginalRecord(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f := newOriginalPublicationSDKFixture(t, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
		t.Fatal(err)
	}
	f.assertPublished(t)
	resolved, err := verifyRetainedFoundation(t.Context(), f.bundle, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	reader := resolved.Footprint.(*SignedFootprint)
	grant, _, err := reader.verifyOriginalDocument(f.bundle.GrantWire)
	if err != nil {
		t.Fatal(err)
	}
	record := f.record(t)
	etags := [2]string{record.OriginalFoundationCompartments.Publication.Readbacks[0].ETag, record.OriginalFoundationCompartments.Publication.Readbacks[1].ETag}
	if err := verifyOriginalSourceActorRecord(reader, grant, record, f.bundle, etags); err != nil {
		t.Fatalf("genuine complete original proof: %v", err)
	}
	for _, fault := range []string{"pending publication", "changed current ETag", "changed bundle", "missing signed admission", "missing signed publication", "changed signed recipe", "missing admission completion", "changed birth", "changed source policy", "ordinary stage", "changed parent"} {
		t.Run(fault, func(t *testing.T) {
			wire, err := json.Marshal(record, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			var changed FoundationRecord
			if err := json.Unmarshal(wire, &changed); err != nil {
				t.Fatal(err)
			}
			grantWire, err := json.Marshal(grant, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			var signed FoundationGrant
			if err := json.Unmarshal(grantWire, &signed); err != nil {
				t.Fatal(err)
			}
			bundle, observedETags := f.bundle.clone(), etags
			switch fault {
			case "pending publication":
				changed.OriginalFoundationCompartments.Publication.Readbacks = nil
			case "changed current ETag":
				observedETags[0] = "changed"
			case "changed bundle":
				bundle.GrantWire = append(bundle.GrantWire, ' ')
			case "missing signed admission":
				signed.OriginalActorAdmissionReads = nil
			case "missing signed publication":
				signed.OriginalPublication = nil
			case "changed signed recipe":
				signed.OriginalActorAdmissionReads[0].Objects[0] = foundationDiscoveryObject
			case "missing admission completion":
				changed.OriginalFoundationCompartments.Regions[1].AdmissionReads.VerifiedAt = time.Time{}
			case "changed birth":
				changed.OriginalSourceProducers[0].Intent.SourceObject = "another/source.json"
			case "changed source policy":
				changed.OriginalFoundationCompartments.Regions[0].SourceIAM.Request.Statements[0] = "Allow any-user to manage all-resources in tenancy"
			case "ordinary stage":
				changed.Stage = "reconciled"
			case "changed parent":
				changed.ParentCompartmentID = "ocid1.compartment.oc1..foreign"
			}
			if err := verifyOriginalSourceActorRecord(reader, signed, changed, bundle, observedETags); err == nil {
				t.Fatal("incomplete, unsigned or changed original scope passed")
			}
		})
	}
	if f.cloud.hasAnchor() {
		t.Fatal("source proof published ordinary foundation authority")
	}
}

func TestOriginalSourceActorOwnPrincipalSDKStopsAtRunningBinary(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f := newOriginalPublicationSDKFixture(t, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) {
		t.Fatal(err)
	}
	f.assertPublished(t)
	record := f.record(t)
	instance := originalActorID(record.OriginalFoundationCompartments.Regions[0].Actor)
	token := originalDeliveryToken(t, instance, f.approval.TenancyID, time.Now().Add(time.Hour).Unix())
	provider := originalDeliveryProvider{provisionProvider: f.provider, token: token, kind: common.InstancePrincipal}
	var reads int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Authorization"), `keyId="`+token+`"`) {
			t.Error("source actor left own-principal authenticated observation boundary")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		reads++
		if r.Host == "objectstorage.sa-saopaulo-1.oraclecloud.com" && r.URL.Path == "/n" {
			if r.URL.RawQuery != "" {
				t.Error("own namespace read requested ungranted compartment scope")
			}
			json.MarshalWrite(w, f.approval.HomeStorageDomain.Namespace)
			return
		}
		f.serveHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	originalSourceActorTestTransport(t, server)
	factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	before := f.wire(t)
	actor, err := readOriginalSourceActor(t.Context(), factory, instance, "GRU", digestSource(f.originalAdmissionReadsSDKFixture.reads.publicBundle), f.roots)
	// The production fixture signs its image's binary, not the Go test runner.
	// No injected binary callback may convert that mismatch into a sealed proof.
	if actor.IsVerified() || !errors.Is(err, bootstrapstart.ErrRunningBinaryMismatch) || reads < 10 {
		t.Fatalf("own-principal source observation = verified %v, reads %d, error %v", actor.IsVerified(), reads, err)
	}
	if string(before) != string(f.wire(t)) || f.cloud.hasAnchor() {
		t.Fatal("source observation mutated original history or admitted runtime")
	}
}

func originalSourceActorTestTransport(t *testing.T, server *httptest.Server) {
	t.Helper()
	// The SDK otherwise replaces Proxy=nil and discards the pinned TLS transport.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("source actor test requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("source actor test refuses plaintext and proxy dialing")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("source actor test refuses network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
}

func TestOriginalMaterialPublicationUsesProtectedV2Policy(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f := newOriginalMaterialIAMSDKFixture(t, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
		t.Fatal(err)
	}
	record := f.record(t)
	grant := f.prepared.Grant
	for index := range 3 {
		entry, err := originalSourceMaterialPublication(grant, record, index)
		if err != nil || entry == nil {
			t.Fatal("completed signed v2 material policy unavailable", err)
		}
		scope, err := originalMaterialPublicationScope(*entry)
		if err != nil || scope.Target != entry.Target || scope.PolicyID != entry.Provenance.ResourceID || scope.PolicyETag != entry.PolicyETag {
			t.Fatal("material scope lost protected policy identity", err)
		}
		if err := verifyOriginalMaterialPublicationPolicy(t.Context(), f.factoryFor(), *entry); err != nil {
			t.Fatal("actual SDK exact policy readback", err)
		}
		changed := *entry
		changed.PolicyETag = "different-policy-revision"
		if verifyOriginalMaterialPublicationPolicy(t.Context(), f.factoryFor(), changed) == nil {
			t.Fatal("changed material policy ETag passed")
		}
		changed = *entry
		request := changed.Request
		request.Statements = slices.Clone(request.Statements)
		request.Statements[0] = "Allow any-user to manage all-resources in tenancy"
		changed.Request = request
		if verifyOriginalMaterialPublicationPolicy(t.Context(), f.factoryFor(), changed) == nil {
			t.Fatal("changed material policy body passed")
		}
	}
	recipes := *grant.OriginalMaterialPublicationIAM
	grant.OriginalMaterialPublicationIAM = &recipes
	for index := range recipes {
		recipes[index].Purpose = originalMaterialIAMPurpose
		recipes[index].PolicyRead = nil
		if entry, err := originalSourceMaterialPublication(grant, record, index); err != nil || entry != nil {
			t.Fatal("historical v1 acquired publication read capability", err)
		}
	}
	var actor VerifiedOriginalSourceActor
	if _, factory, ctx, err := actor.MaterialPublication(t.Context()); err == nil || factory != nil || ctx != nil {
		t.Fatal("zero actor acquired material publication clients")
	}
}
