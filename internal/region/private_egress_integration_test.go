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
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// Private controllers remain private while their real signed SDK requests and
// conditional Object Storage journal recover an accepted NAT create and upgrade
// the existing Service-Gateway-only network with ETag-guarded full-list writes.
func TestPrivateEgressSDKDurableRecoveryAndExactUpgrade(t *testing.T) {
	store, _, _ := foundationProtocolStore(t)
	wire, err := os.ReadFile(filepath.Join("..", "..", "deploy", "oci-region", "sfo-1-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan map[string]any
	if err := json.Unmarshal(wire, &plan); err != nil {
		t.Fatal(err)
	}
	sec := plan["network_security"].(map[string]any)
	ids := plan["resource_ids"].(map[string]any)
	ids["nat_gateway"] = nil
	sec["route_rules"] = []any{map[string]any{"destination": sec["service_gateway_cidr_block"], "destination_type": "SERVICE_CIDR_BLOCK", "network_entity_id": "{service_gateway_id}"}, map[string]any{"destination": "0.0.0.0/0", "destination_type": "CIDR_BLOCK", "network_entity_id": "{nat_gateway_id}"}}
	oldEgress := []any{}
	for _, value := range sec["security_list_egress_rules"].([]any) {
		if value.(map[string]any)["destination"] != "0.0.0.0/0" {
			oldEgress = append(oldEgress, value)
		}
	}
	sec["security_list_egress_rules"] = append(slices.Clone(oldEgress), privateEgressRule("6", 443), privateEgressRule("17", 3478))
	const region = "us-sanjose-1"
	idFor := func(kind, key string) string {
		return "ocid1." + kind + ".oc1." + region + "." + strings.ReplaceAll(key, "_", "")
	}
	resources := map[string][]map[string]any{}
	add := func(collection, key, kind, name string, values map[string]any) {
		id := idFor(kind, key)
		if kind == "compartment" {
			id = "ocid1.compartment.oc1.." + strings.ReplaceAll(key, "_", "")
		}
		ids[key] = id
		row := maps.Clone(values)
		row["id"], row["displayName"], row["lifecycleState"] = id, name, "AVAILABLE"
		resources[collection] = append(resources[collection], row)
	}
	for _, role := range []string{"control", "network", "workload"} {
		name := plan["preview_compartment_names"].(map[string]any)[role].(string)
		add("compartments", role+"_compartment", "compartment", name, map[string]any{"name": name, "compartmentId": plan["parent_compartment_id"]})
		resources["compartments"][len(resources["compartments"])-1]["lifecycleState"] = "ACTIVE"
	}
	scope := map[string]any{"compartmentId": ids["network_compartment"]}
	add("vcns", "vcn", "vcn", "sfo-1-vcn", map[string]any{"compartmentId": ids["network_compartment"], "cidrBlock": plan["network_cidr"]})
	scope["vcnId"] = ids["vcn"]
	gateway := maps.Clone(scope)
	gateway["services"] = []any{map[string]any{"serviceId": sec["service_gateway_service_id"]}}
	add("serviceGateways", "service_gateway", "servicegateway", "sfo-1-service-gateway", gateway)
	route := maps.Clone(scope)
	route["routeRules"] = []any{map[string]any{"destination": sec["service_gateway_cidr_block"], "destinationType": "SERVICE_CIDR_BLOCK", "networkEntityId": ids["service_gateway"]}}
	add("routeTables", "route_table", "routetable", "sfo-1-private-routes", route)
	security := maps.Clone(scope)
	security["ingressSecurityRules"] = privateEgressWireRules(sec["security_list_ingress_rules"].([]any))
	security["egressSecurityRules"] = privateEgressWireRules(oldEgress)
	add("securityLists", "security_list", "securitylist", "sfo-1-private-security", security)
	subnet := maps.Clone(scope)
	subnet["cidrBlock"], subnet["prohibitPublicIpOnVnic"], subnet["prohibitInternetIngress"] = plan["subnet_cidr"], true, true
	subnet["routeTableId"], subnet["securityListIds"] = ids["route_table"], []any{ids["security_list"]}
	add("subnets", "subnet", "subnet", "sfo-1-private", subnet)
	for _, nsg := range []struct{ key, suffix string }{{"network_security_group", "controllers-nsg"}, {"workload_network_security_group", "databases-nsg"}} {
		add("networkSecurityGroups", nsg.key, "networksecuritygroup", "sfo-1-"+nsg.suffix, scope)
	}
	if _, err := ociregion.ValidatePlan(plan); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	posts, puts := 0, 0
	lost, stale, revoke := true, false, false
	token := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", "network-v1")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") || !strings.Contains(r.Host, region) {
			t.Errorf("private egress request escaped signed regional SDK: %s %s", r.Method, r.Host)
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/20160918/"), "/")
		collection := parts[0]
		if r.Method == http.MethodGet {
			if collection == "networkSecurityGroups" && len(parts) == 3 && parts[2] == "securityRules" {
				key := "nsg_rules"
				if parts[1] == ids["workload_network_security_group"] {
					key = "workload_nsg_rules"
				}
				rules := privateEgressWireRules(sec[key].([]any))
				for _, value := range rules {
					value.(map[string]any)["direction"] = "INGRESS"
				}
				json.MarshalWrite(w, rules)
				return
			}
			if len(parts) == 1 {
				json.MarshalWrite(w, resources[collection])
				return
			}
			for _, row := range resources[collection] {
				if row["id"] == parts[1] {
					json.MarshalWrite(w, row)
					return
				}
			}
		}
		var body map[string]any
		if err := json.UnmarshalRead(r.Body, &body); err != nil {
			t.Error(err)
		}
		if r.Method == http.MethodPost && collection == "natGateways" {
			posts++
			current, _, err := store.Load(r.Context(), "SFO")
			pending := current.PendingCreates["nat_gateway"]
			canonical, _ := json.Marshal(body, json.Deterministic(true))
			digest := sha256.Sum256(canonical)
			if err != nil || pending.Request.RequestDigest != hex.EncodeToString(digest[:]) || pending.Request.RetryToken == "" || pending.Request.RetryToken != r.Header.Get("opc-retry-token") {
				t.Error("NAT mutation preceded its exact serialized-request checkpoint")
			}
			if body["blockTraffic"] != false || body["compartmentId"] != ids["network_compartment"] || body["vcnId"] != ids["vcn"] || body["routeTableId"] != nil {
				t.Errorf("NAT escaped fixed egress scope: %v", body)
			}
			if token != "" && token != pending.Request.RetryToken {
				t.Error("NAT recovery changed retry token")
			}
			token = pending.Request.RetryToken
			if len(resources[collection]) == 0 {
				body["id"], body["lifecycleState"] = idFor("natgateway", "privateegress"), "AVAILABLE"
				resources[collection] = []map[string]any{body}
			}
			if lost {
				lost = false
				w.WriteHeader(http.StatusServiceUnavailable)
				io.WriteString(w, `{"code":"InternalError","message":"accepted response lost"}`)
				return
			}
			json.MarshalWrite(w, resources[collection][0])
			return
		}
		if r.Method == http.MethodPut && (collection == "routeTables" || collection == "securityLists") {
			puts++
			if r.Header.Get("If-Match") != "network-v1" || revoke {
				t.Error("private egress update lost ETag or current authority")
			}
			if stale {
				w.WriteHeader(http.StatusPreconditionFailed)
				io.WriteString(w, `{"code":"NoEtagMatch","message":"changed concurrently"}`)
				return
			}
			for key, value := range body {
				resources[collection][0][key] = value
			}
			json.MarshalWrite(w, resources[collection][0])
			return
		}
		t.Errorf("unexpected private egress SDK call %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusBadRequest)
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
	provider := common.NewRawConfigurationProvider(plan["tenancy_id"].(string), "ocid1.user.oc1..test", region, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: region, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	intentWire, _ := json.Marshal(plan, json.Deterministic(true))
	intentHash := sha256.Sum256(intentWire)
	record := FoundationRecord{SchemaVersion: 1, Cell: "SFO", OCIRegion: region, TenancyID: plan["tenancy_id"].(string), ParentCompartmentID: plan["parent_compartment_id"].(string), SharedCompartmentID: plan["shared_compartment_id"].(string), Generation: 1,
		IntentDigest: hex.EncodeToString(intentHash[:]), GrantSHA256: strings.Repeat("b", 64), OperationID: entityid.Derive("regional-foundation", plan["tenancy_id"].(string), "SFO", "1"), Epoch: 1, LeaseID: entityid.New(), ExpiresAt: now.Add(foundationLease), Stage: "foundation", StartedAt: now, UpdatedAt: now,
		ResourceIDs: map[string]string{}, AuxiliaryIDs: map[string]string{}, PendingCreates: map[string]PendingFoundationCreate{}}
	if _, err := store.CompareAndSwap(t.Context(), record, ""); err != nil {
		t.Fatal(err)
	}
	stop := errors.New("network checkpoint reached")
	run := func() error {
		saved, etag, err := store.Load(t.Context(), "SFO")
		if err != nil {
			return err
		}
		for key, id := range saved.ResourceIDs {
			ids[key] = id
		}
		_, cancel := context.WithCancelCause(t.Context())
		t.Cleanup(func() { cancel(nil) })
		attempt := &foundationAttempt{controller: &FoundationController{Store: store, Authority: recoveryAuthority{}}, record: saved, etag: etag, leaseID: saved.LeaseID, epoch: saved.Epoch, cancel: cancel}
		client := publicapi.NewClientWithFactory(factory)
		f := foundation.Foundation{Region: client, Home: client, OperationID: saved.OperationID, Apply: true, Out: io.Discard, Check: func(map[string]any) error { return nil },
			BeforeWrite: func(ctx context.Context, home bool) (context.Context, func(), error) {
				if revoke {
					return ctx, nil, errors.New("current signed grant revoked")
				}
				return attempt.beforeWrite(ctx, home)
			}, Guard: func(ctx context.Context) error { return attempt.guard(ctx) }, PrepareCreate: attempt.prepareCreate, CheckpointAuxiliary: attempt.checkpointAuxiliary,
			Checkpoint: func(ctx context.Context, key, id string) error {
				if err := attempt.checkpoint(ctx, key, id); err != nil {
					return err
				}
				if key == "subnet" {
					return stop
				}
				return nil
			}}
		_, err = f.Reconcile(t.Context(), plan)
		return err
	}
	if err := run(); err == nil || errors.Is(err, stop) {
		t.Fatalf("lost NAT response succeeded: %v", err)
	}
	saved, _, err := store.Load(t.Context(), "SFO")
	if err != nil || len(saved.PendingCreates) != 1 || saved.ResourceIDs["nat_gateway"] != "" || puts != 0 {
		t.Fatalf("NAT interruption lost durable pending identity: %+v %v puts=%d", saved, err, puts)
	}
	for _, change := range []string{"digest", "expired"} {
		original, etag, err := store.Load(t.Context(), "SFO")
		if err != nil {
			t.Fatal(err)
		}
		changed := original
		changed.PendingCreates = maps.Clone(original.PendingCreates)
		pending := changed.PendingCreates["nat_gateway"]
		if change == "digest" {
			pending.Request.RequestDigest = strings.Repeat("f", 64)
		} else {
			changed.StartedAt = time.Now().UTC().Add(-25 * time.Hour)
			pending.FirstAttemptAt = changed.StartedAt
		}
		changed.PendingCreates["nat_gateway"] = pending
		if _, err := store.CompareAndSwap(t.Context(), changed, etag); err != nil {
			t.Fatal(err)
		}
		if err := run(); err == nil || errors.Is(err, stop) || posts != 1 || puts != 0 {
			t.Fatalf("%s pending NAT request reached mutation: %v posts=%d puts=%d", change, err, posts, puts)
		}
		_, currentTag, err := store.Load(t.Context(), "SFO")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.CompareAndSwap(t.Context(), original, currentTag); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(); !errors.Is(err, stop) || posts != 2 || puts != 2 || len(resources["natGateways"]) != 1 {
		t.Fatalf("NAT upgrade recovery: err=%v posts=%d puts=%d", err, posts, puts)
	}
	saved, _, err = store.Load(t.Context(), "SFO")
	if err != nil || len(saved.PendingCreates) != 0 || saved.ResourceIDs["nat_gateway"] == "" || saved.ResourceProvenance["nat_gateway"].GrantSHA256 != record.GrantSHA256 || saved.ResourceProvenance["nat_gateway"].Create.Request.RetryToken != token {
		t.Fatalf("NAT checkpoint did not settle journal: %+v %v", saved, err)
	}
	if err := run(); !errors.Is(err, stop) || posts != 2 || puts != 2 {
		t.Fatalf("unchanged restart mutated network: %v posts=%d puts=%d", err, posts, puts)
	}
	if len(resources["routeTables"][0]["routeRules"].([]any)) != 2 || len(resources["securityLists"][0]["egressSecurityRules"].([]any)) != len(oldEgress)+2 || resources["subnets"][0]["prohibitPublicIpOnVnic"] != true {
		t.Fatal("private subnet did not retain SGW plus NAT and exact HTTPS/STUN egress")
	}
	securityLive := resources["securityLists"][0]
	securityLive["egressSecurityRules"] = append(securityLive["egressSecurityRules"].([]any), map[string]any{"destination": "0.0.0.0/0", "destinationType": "CIDR_BLOCK", "protocol": "all", "isStateless": false})
	if err := run(); err == nil || errors.Is(err, stop) || puts != 2 {
		t.Fatalf("broader egress accepted or overwritten: %v puts=%d", err, puts)
	}
	securityLive["egressSecurityRules"] = privateEgressWireRules(oldEgress)
	stale = true
	if err := run(); err == nil || errors.Is(err, stop) || puts != 3 {
		t.Fatalf("concurrent security update was overwritten: %v puts=%d", err, puts)
	}
	stale, revoke = false, true
	if err := run(); err == nil || errors.Is(err, stop) || puts != 3 {
		t.Fatalf("revoked grant reached OCI mutation: %v puts=%d", err, puts)
	}
	// Inspect through the actual SDK; the callback replaces only OCI transport.
	securityLive["egressSecurityRules"] = privateEgressWireRules(sec["security_list_egress_rules"].([]any))
	reader := sdkcli.NewClient(factory, "")
	engine := ociregion.Engine{Context: t.Context(), Dependency: func(name string, args []any, kwargs map[string]any) (any, error) {
		words := make([]string, len(args))
		for i, value := range args {
			words[i] = value.(string)
		}
		data, _, err := reader.Call(t.Context(), words)
		if err != nil {
			return nil, err
		}
		var value any
		err = json.Unmarshal(data, &value)
		return value, err
	}}
	if _, err := engine.Invoke("check_live_network", []any{plan, ids}, map[string]any{}); err != nil {
		t.Fatalf("private network SDK readback: %v", err)
	}
	resources["natGateways"][0]["blockTraffic"] = true
	if _, err := engine.Invoke("check_live_network", []any{plan, ids}, map[string]any{}); err == nil {
		t.Fatal("blocked NAT passed exact live inspection")
	}
}

func privateEgressRule(protocol string, port int) map[string]any {
	rule := map[string]any{"direction": "EGRESS", "protocol": protocol, "source": nil, "source_type": nil, "destination": "0.0.0.0/0", "destination_type": "CIDR_BLOCK", "tcp_min": nil, "tcp_max": nil, "udp_min": nil, "udp_max": nil, "stateless": false}
	if protocol == "6" {
		rule["tcp_min"], rule["tcp_max"] = port, port
	} else {
		rule["udp_min"], rule["udp_max"] = port, port
	}
	return rule
}

func privateEgressWireRules(values []any) []any {
	result := []any{}
	for _, value := range values {
		rule := value.(map[string]any)
		wire := map[string]any{"protocol": rule["protocol"], "isStateless": rule["stateless"]}
		for _, side := range []string{"source", "destination"} {
			if rule[side] != nil {
				wire[side], wire[side+"Type"] = rule[side], rule[side+"_type"]
			}
		}
		for _, protocol := range []string{"tcp", "udp"} {
			if rule[protocol+"_min"] != nil {
				wire[protocol+"Options"] = map[string]any{"destinationPortRange": map[string]any{"min": rule[protocol+"_min"], "max": rule[protocol+"_max"]}}
			}
		}
		result = append(result, wire)
	}
	return result
}
