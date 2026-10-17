package region

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// The real signed networking SDK crosses TLS while the existing conditional
// Object Storage protocol fixture persists the actual foundation journal.
func TestNetBirdNetworkRecoversLostCreatesAndRejectsDrift(t *testing.T) {
	store, _, _ := foundationProtocolStore(t)
	const compartment = "ocid1.compartment.oc1..network"
	plan := map[string]any{"cell": "GRU", "region": foundationHomeRegion, "tenancy_id": "ocid1.tenancy.oc1..test", "network_cidr": "10.251.0.0/24", "subnet_cidr": "10.251.0.0/25",
		"resource_ids": map[string]any{"network_compartment": compartment}}
	profile := NetBirdManagerProfile{NetworkCIDR: "10.251.1.0/24", PrivateIP: "10.251.1.10"}
	var mu sync.Mutex
	live := map[string]map[string]any{}
	tokens := map[string]string{}
	posts, creates := 0, 0
	lost := true
	var cancelFirst context.CancelCauseFunc
	var nsgRules any = []any{}
	dnsServer := "VcnLocalPlusInternet"
	ids := map[string]string{"vcns": "vcn", "internetGateways": "internetgateway", "routeTables": "routetable", "securityLists": "securitylist", "networkSecurityGroups": "networksecuritygroup", "subnets": "subnet"}
	idFor := func(kind string) string { return "ocid1." + kind + ".oc1.sa-saopaulo-1.manager" }
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "" || !strings.Contains(r.Host, foundationHomeRegion) {
			t.Errorf("network request lost authenticated GRU identity: %s", r.Host)
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/20160918/"), "/")
		collection := parts[0]
		if r.Method == http.MethodGet && collection == "dhcps" {
			json.MarshalWrite(w, map[string]any{"id": idFor("dhcpoptions"), "vcnId": idFor("vcn"), "compartmentId": compartment, "lifecycleState": "AVAILABLE", "options": []map[string]any{{"type": "DomainNameServer", "serverType": dnsServer}}})
			return
		}
		if r.Method == http.MethodGet && len(parts) == 3 && parts[2] == "securityRules" {
			json.MarshalWrite(w, nsgRules)
			return
		}
		if r.Method == http.MethodGet && len(parts) == 2 && live[collection] != nil {
			json.MarshalWrite(w, live[collection])
			return
		}
		if r.Method != http.MethodPost || len(parts) != 1 || ids[collection] == "" {
			t.Errorf("unexpected network operation: %s %s", r.Method, r.URL)
			w.WriteHeader(400)
			return
		}
		var body map[string]any
		if err := json.UnmarshalRead(r.Body, &body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		wire, err := json.Marshal(body, json.Deterministic(true))
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		actualDigest := sha256.Sum256(wire)

		posts++
		token := r.Header.Get("opc-retry-token")
		record, _, err := store.Load(r.Context(), "GRU")
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		prepared := false
		for _, pending := range record.PendingCreates {
			if pending.Request.RetryToken == token && token != "" && pending.Request.RequestDigest == hex.EncodeToString(actualDigest[:]) {
				prepared = true
			}
		}
		if !prepared {
			t.Error("OCI create preceded its durable exact-token journal")
			w.WriteHeader(400)
			return
		}
		if old := tokens[token]; old != "" {
			if old != collection {
				t.Error("retry token crossed resource kinds")
			}
			json.MarshalWrite(w, live[collection])
			return
		}
		body["id"], body["lifecycleState"] = idFor(ids[collection]), "AVAILABLE"
		if collection == "vcns" {
			body["defaultDhcpOptionsId"] = idFor("dhcpoptions")
		}
		if collection == "subnets" {
			body["prohibitInternetIngress"] = false
		}
		live[collection], tokens[token] = body, collection
		creates++
		if lost {
			lost = false
			cancelFirst(errors.New("process interrupted after OCI accepted the create"))
			<-r.Context().Done()
			return
		}
		json.MarshalWrite(w, body)
	}))
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	original := http.DefaultTransport
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = original; transport.CloseIdleConnections() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider(plan["tenancy_id"].(string), "ocid1.user.oc1..test", foundationHomeRegion, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	digest := sha256.Sum256([]byte("root-signed-dedicated-network-intent"))
	record := FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: foundationHomeRegion, TenancyID: plan["tenancy_id"].(string), ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared",
		Generation: 1, IntentDigest: hex.EncodeToString(digest[:]), OperationID: entityid.New(), Epoch: 1, LeaseID: entityid.New(), ExpiresAt: now.Add(foundationLease), Stage: "foundation", StartedAt: now, UpdatedAt: now,
		ResourceIDs: map[string]string{"network_compartment": compartment}, AuxiliaryIDs: map[string]string{}, PendingCreates: map[string]PendingFoundationCreate{}}
	if _, err := store.CompareAndSwap(t.Context(), record, ""); err != nil {
		t.Fatal(err)
	}
	resume := func() FoundationProgress {
		record, etag, err := store.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		_, cancel := context.WithCancelCause(t.Context())
		t.Cleanup(func() { cancel(nil) })
		attempt := &foundationAttempt{controller: &FoundationController{Store: store, Authority: recoveryAuthority{}}, record: record, etag: etag, leaseID: record.LeaseID, epoch: record.Epoch, cancel: cancel}
		return FoundationProgress{OperationID: record.OperationID, BeforeWrite: attempt.beforeWrite, AuxiliaryIDs: maps.Clone(record.AuxiliaryIDs), CheckpointAuxiliary: attempt.checkpointAuxiliary, PrepareCreate: attempt.prepareCreate}
	}
	firstCtx, firstCancel := context.WithCancelCause(t.Context())
	cancelFirst = firstCancel
	t.Cleanup(func() { firstCancel(nil) })
	if _, _, err := ReconcileNetBirdNetwork(firstCtx, factory, plan, profile, resume()); err == nil {
		t.Fatal("lost accepted response succeeded")
	}
	saved, _, err := store.Load(t.Context(), "GRU")
	if err != nil || len(saved.PendingCreates) != 1 || len(saved.AuxiliaryIDs) != 0 {
		t.Fatalf("lost response did not retain journal: %+v %v", saved, err)
	}
	subnet, nsg, err := ReconcileNetBirdNetwork(t.Context(), factory, plan, profile, resume())
	if err != nil || subnet != idFor("subnet") || nsg != idFor("networksecuritygroup") {
		t.Fatalf("resume network: subnet=%s nsg=%s err=%v", subnet, nsg, err)
	}
	if creates != 6 || posts != 7 {
		t.Fatalf("resume duplicated capacity: creates=%d posts=%d", creates, posts)
	}
	saved, _, err = store.Load(t.Context(), "GRU")
	if err != nil || len(saved.PendingCreates) != 0 || len(saved.AuxiliaryIDs) != 6 {
		t.Fatalf("network ownership incomplete: %+v %v", saved, err)
	}
	if _, _, err := ReconcileNetBirdNetwork(t.Context(), factory, plan, profile, resume()); err != nil || posts != 7 {
		t.Fatalf("restart changed network: posts=%d err=%v", posts, err)
	}
	for _, drift := range []struct {
		collection, field string
		value             any
	}{
		{"vcns", "cidrBlocks", []string{"10.200.0.0/16"}},
		{"vcns", "byoipv6CidrBlocks", []string{"2001:db8::/64"}},
		{"internetGateways", "isEnabled", false},
		{"internetGateways", "routeTableId", idFor("routetable")},
		{"routeTables", "routeRules", []map[string]any{{"destination": "10.252.0.0/16", "destinationType": "CIDR_BLOCK", "networkEntityId": idFor("drg")}}},
		{"securityLists", "ingressSecurityRules", []map[string]any{{"source": "0.0.0.0/0", "protocol": "all"}}},
		{"subnets", "securityListIds", []string{idFor("securitylist") + "foreign"}},
		{"subnets", "ipv4CidrBlocks", []string{"10.251.2.0/24"}},
	} {
		t.Run("drift-"+drift.collection+"-"+drift.field, func(t *testing.T) {
			mu.Lock()
			old := live[drift.collection]
			live[drift.collection] = maps.Clone(old)
			live[drift.collection][drift.field] = drift.value
			mu.Unlock()
			_, _, err := ReconcileNetBirdNetwork(t.Context(), factory, plan, profile, resume())
			if err == nil || posts != 7 {
				t.Fatalf("drift accepted or mutated network: posts=%d err=%v", posts, err)
			}
			mu.Lock()
			live[drift.collection] = old
			mu.Unlock()
		})
	}
	for _, cidr := range []string{"10.200.0.0/16", "10.252.1.0/24", "10.208.0.0/24", "10.251.0.0/24"} {
		t.Run("reject-"+cidr, func(t *testing.T) {
			bad := profile
			bad.NetworkCIDR = cidr
			bad.PrivateIP = netip.MustParsePrefix(cidr).Addr().Next().Next().String()
			_, _, err := ReconcileNetBirdNetwork(t.Context(), factory, plan, bad, resume())
			if err == nil || posts != 7 {
				t.Fatalf("unowned CIDR admitted: %s err=%v", cidr, err)
			}
		})
	}
	for _, payload := range []any{nil, []map[string]any{{"direction": "INGRESS", "protocol": "all", "source": "0.0.0.0/0"}}} {
		mu.Lock()
		nsgRules = payload
		mu.Unlock()
		if _, _, err := ReconcileNetBirdNetwork(t.Context(), factory, plan, profile, resume()); err == nil || posts != 7 {
			t.Fatalf("unknown or broader NSG admitted: %v", err)
		}
	}
	mu.Lock()
	nsgRules = []any{}
	dnsServer = "CustomDnsServer"
	mu.Unlock()
	if _, _, err := ReconcileNetBirdNetwork(t.Context(), factory, plan, profile, resume()); err == nil || posts != 7 {
		t.Fatalf("foreign DNS admitted: %v", err)
	}
	mu.Lock()
	dnsServer = "VcnLocalPlusInternet"
	mu.Unlock()
	progress := resume()
	progress.AuxiliaryIDs = map[string]string{}
	progress.BeforeWrite = func(ctx context.Context, _ bool) (context.Context, func(), error) {
		return ctx, nil, errors.New("authority expired")
	}
	if _, _, err := ReconcileNetBirdNetwork(t.Context(), factory, plan, profile, progress); err == nil || posts != 7 {
		t.Fatalf("unfenced create reached OCI: %v", err)
	}
	released := false
	progress.BeforeWrite = func(context.Context, bool) (context.Context, func(), error) {
		return nil, func() { released = true }, nil
	}
	if _, _, err := ReconcileNetBirdNetwork(t.Context(), factory, plan, profile, progress); err == nil || posts != 7 || !released {
		t.Fatalf("invalid leased context was used or leaked: released=%v err=%v", released, err)
	}
}
