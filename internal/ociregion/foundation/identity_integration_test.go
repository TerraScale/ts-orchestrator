package foundation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/command"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// This scenario crosses the actual signed SDK/HTTP provider boundary. It stops
// after the first durable OCID checkpoint, before downstream resources exist.
func TestFoundationSDKOwnershipCheckpointAndRecovery(t *testing.T) {
	const resourceID = "ocid1.compartment.oc1..ownedcontrol"
	const founderID = "ocid1.instance.oc1.us-sanjose-1.acceptedseed"
	const sourceName = "ts-bootstrap-source-0123456789abcdef0123456789abcdef"
	sourceTarget := vaultsecret.Target{CompartmentID: resourceID, VaultID: "ocid1.vault.oc1.sa-saopaulo-1.owned", KeyID: "ocid1.key.oc1.sa-saopaulo-1.owned"}
	sourceStatements, err := ociregion.BootstrapSourceStatements(founderID, sourceName, sourceTarget)
	if err != nil {
		t.Fatal(err)
	}
	if len(sourceStatements) != 5 {
		t.Fatalf("source IAM statements=%v", sourceStatements)
	}
	linkName := strings.Replace(sourceName, "ts-bootstrap-source-", "ts-bootstrap-source-link-", 1)
	linkStatements, err := ociregion.BootstrapSourceStatements(founderID, linkName, sourceTarget)
	if err != nil || command.JSON(linkStatements) != strings.ReplaceAll(command.JSON(sourceStatements), sourceName, linkName) {
		t.Fatalf("link source IAM changed exact scope: statements=%v err=%v", linkStatements, err)
	}
	for _, statement := range sourceStatements {
		if !strings.Contains(statement, "request.principal.id='"+founderID+"'") || !strings.Contains(statement, "request.principal.type='instance'") ||
			strings.Contains(statement, "SECRET_UPDATE") || strings.Contains(statement, "SECRET_INSPECT") || strings.Contains(statement, "dynamic-group") || strings.Contains(statement, "*") {
			t.Fatalf("source IAM escaped exact founder/read/create scope: %s", statement)
		}
	}
	for _, invalid := range []struct {
		founder, name string
		target        vaultsecret.Target
	}{
		{"ocid1.instance.oc1.us-sanjose-1.seed'", sourceName, sourceTarget},
		{founderID, "ts-bootstrap-source-*", sourceTarget},
		{founderID, sourceName, vaultsecret.Target{CompartmentID: resourceID, VaultID: "ocid1.vault.oc1.us-sanjose-1.foreign", KeyID: sourceTarget.KeyID}},
	} {
		if _, err := ociregion.BootstrapSourceStatements(invalid.founder, invalid.name, invalid.target); err == nil {
			t.Fatalf("invalid source IAM accepted: %+v", invalid)
		}
	}
	plan := loadPlan(t)
	controller, err := ociregion.RequiredControllerStatements(plan, Object{"key": sourceTarget.KeyID}, "owned/bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	bootstrapReads, bootstrapWrites := 0, 0
	for _, statement := range controller {
		if strings.Contains(statement, "target.object.name=/owned/bootstrap/bootstrap/v2/*/") {
			if strings.Contains(statement, "OBJECT_CREATE") || strings.Contains(statement, "OBJECT_OVERWRITE") {
				bootstrapWrites++
				if !strings.Contains(statement, "target.object.name != /owned/bootstrap/bootstrap/v2/material-source/*/") || strings.Contains(statement, "OBJECT_READ") {
					t.Fatalf("ordinary controller can rewrite source registration: %s", statement)
				}
			} else if strings.Contains(statement, "OBJECT_READ") {
				bootstrapReads++
			}
		}
		if strings.Contains(statement, "read secret-bundles") && !strings.Contains(statement, "where target.secret.name != /ts-bootstrap-source-*/") {
			t.Fatalf("controller can read source escrow: %s", statement)
		}
	}
	if bootstrapReads != 2 || bootstrapWrites != 2 {
		t.Fatalf("reserved source IAM reads=%d writes=%d", bootstrapReads, bootstrapWrites)
	}
	var live Object
	var state sync.Mutex
	var createToken string
	hideList := false
	writes, posts, guards, releases, inspections := 0, 0, 0, 0, 0
	setLive := func(value Object) { state.Lock(); live = value; state.Unlock() }
	numWrites := func() int { state.Lock(); defer state.Unlock(); return writes }
	numPosts := func() int { state.Lock(); defer state.Unlock(); return posts }
	parent := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state.Lock()
		defer state.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned OCI request")
		}
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/20160918/tenancies/"):
			io.WriteString(w, `{"homeRegionKey":"FRA"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/20160918/policies":
			var policy Object
			if err := json.UnmarshalRead(r.Body, &policy); err != nil {
				t.Error(err)
			}
			expected := sourceStatements
			if policy["name"] == "controller-scope" {
				expected = controller
			}
			if command.JSON(policy["statements"]) != command.JSON(expected) || policy["compartmentId"] != resourceID || !strings.Contains(r.Host, "eu-frankfurt-1") {
				t.Errorf("source policy transport changed exact scope: %v host=%s", policy, r.Host)
			}
			policy["id"] = "ocid1.policy.oc1..source"
			json.MarshalWrite(w, policy)
		case r.Method == http.MethodGet && r.URL.Path == "/20160918/compartments":
			if live == nil || hideList {
				io.WriteString(w, `[]`)
			} else {
				data, _ := json.Marshal([]Object{live})
				w.Write(data)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/20160918/compartments":
			posts++
			if !strings.Contains(r.Host, "eu-frankfurt-1") {
				t.Errorf("IAM write addressed non-home endpoint %s", r.Host)
			}
			if r.Header.Get("opc-retry-token") == "" {
				t.Error("create omitted retry token")
			}
			if createToken != "" {
				if r.Header.Get("opc-retry-token") != createToken {
					t.Error("restart changed durable retry token")
				}
				data, _ := json.Marshal(live)
				w.Write(data)
				return
			}
			writes++
			createToken = r.Header.Get("opc-retry-token")
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			if err := json.Unmarshal(body, &live); err != nil {
				t.Error(err)
			}
			live["id"], live["lifecycleState"] = resourceID, "ACTIVE"
			// OCI accepted the operation before its response was lost.
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"code":"InternalError","message":"response lost"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/20160918/compartments/"+resourceID:
			inspections++
			data, _ := json.Marshal(live)
			w.Write(data)
		default:
			t.Errorf("unexpected OCI request %s %s", r.Method, r.URL)
			http.Error(w, `{"code":"Unexpected"}`, http.StatusBadRequest)
		}
	}))
	defer server.Close()
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
	provider := common.NewRawConfigurationProvider(text(plan["tenancy_id"]), "ocid1.user.oc1..test", sfo, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: sfo, Retry: ociclient.RetryOptions{BaseDelay: time.Millisecond, MaxDelay: time.Millisecond}, Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceIdentity: {PerSecond: 10000, Burst: 10000}}})
	if err != nil {
		t.Fatal(err)
	}
	constructorContext, cancelConstructor := context.WithCancel(t.Context())
	foundation, err := New(constructorContext, factory, text(plan["tenancy_id"]))
	if err != nil {
		t.Fatal(err)
	}
	cancelConstructor()
	if err := foundation.buckets(t.Context(), plan, "", ""); err != nil {
		t.Fatalf("dry-run buckets queried an uncreated compartment: %v", err)
	}
	if _, err := foundation.Home.Call(t.Context(), "iam", "policy", "create", "--compartment-id", resourceID, "--name", "controller-scope", "--description", "test-only controller IAM", "--statements", command.JSON(controller)); err != nil {
		t.Fatal(err)
	}
	if _, err := foundation.Home.Call(t.Context(), "iam", "policy", "create", "--compartment-id", resourceID, "--name", "exact-founder-source", "--description", "test-only source IAM", "--statements", command.JSON(sourceStatements)); err != nil {
		t.Fatal(err)
	}
	foundation.OperationID = "durable-sfo-foundation"
	pending := map[string]CreateIdentity{}
	foundation.PrepareCreate = func(_ context.Context, identity CreateIdentity, recovery bool) error {
		old, exists := pending[identity.Key]
		if recovery && !exists || exists && old != identity {
			return errors.New("create has no matching durable pending request")
		}
		pending[identity.Key] = identity
		return nil
	}
	foundation.CheckpointAuxiliary = func(context.Context, string, string) error { return nil }
	foundation.Pause = func(context.Context, time.Duration) error { return nil }
	foundation.Guard = func(context.Context) error { return nil }
	foundation.BeforeWrite = func(_ context.Context, iam bool) (func(), error) {
		if !iam {
			t.Error("compartment mutation did not acquire home IAM authority")
		}
		guards++
		return func() { releases++ }, nil
	}
	checkpointed := false
	interrupted := errors.New("controller interrupted after durable checkpoint")
	foundation.Checkpoint = func(_ context.Context, key, id string) error {
		if key != "control_compartment" || id != resourceID {
			t.Errorf("checkpoint=%s %s", key, id)
		}
		checkpointed = true
		return interrupted
	}
	parent = text(plan["parent_compartment_id"])
	// Even exact ownership tags cannot authorize an uncheckpointed resource.
	setLive(Object{"id": resourceID, "name": "sfo-1-control", "compartmentId": parent, "lifecycleState": "ACTIVE", "freeformTags": Object{
		"terrascale.owner": "ts-orch", "terrascale.cell": "sfo-1", "terrascale.operation": foundation.OperationID,
	}})
	if _, err := foundation.Reconcile(t.Context(), plan); err == nil || !strings.Contains(err.Error(), "ownership") || numWrites() != 0 {
		t.Fatalf("foreign adoption: writes=%d err=%v", numWrites(), err)
	}
	setLive(nil)
	if _, err := foundation.Reconcile(t.Context(), plan); !errors.Is(err, interrupted) || !checkpointed || numWrites() != 1 || guards != 1 || releases != 1 {
		t.Fatalf("checkpoint boundary: writes=%d guards=%d releases=%d err=%v", numWrites(), guards, releases, err)
	}
	state.Lock()
	tags := obj(live["freeformTags"])
	owned := tags["terrascale.owner"] == "ts-orch" && tags["terrascale.cell"] == "sfo-1" && tags["terrascale.operation"] == foundation.OperationID
	state.Unlock()
	if !owned {
		t.Fatalf("creation omitted ownership: %v", tags)
	}
	if _, err := foundation.Reconcile(t.Context(), plan); !errors.Is(err, interrupted) || numWrites() != 1 || numPosts() != 3 {
		t.Fatalf("visible pending create did not recover exact retry result: writes=%d posts=%d err=%v", numWrites(), numPosts(), err)
	}
	// Replay an unknown response while provider listing is still stale. OCI
	// must see the same token across reconciliation calls and create only once.
	state.Lock()
	hideList = true
	state.Unlock()
	if _, err := foundation.Reconcile(t.Context(), plan); !errors.Is(err, interrupted) || numWrites() != 1 || numPosts() != 4 {
		t.Fatalf("unknown-result replay duplicated resource: posts=%d writes=%d err=%v", numPosts(), numWrites(), err)
	}
	state.Lock()
	hideList = false
	state.Unlock()
	// The controller restores this checkpoint after restart; an identical resource
	// is recovered without a second create, and a discovery miss cannot replace it.
	obj(plan["resource_ids"])["control_compartment"] = resourceID
	if _, err := foundation.Reconcile(t.Context(), plan); !errors.Is(err, interrupted) || numWrites() != 1 {
		t.Fatalf("restart duplicated resource: writes=%d err=%v", numWrites(), err)
	}
	setLive(nil)
	if _, err := foundation.Reconcile(t.Context(), plan); err == nil || !strings.Contains(err.Error(), "refusing replacement") || numWrites() != 1 {
		t.Fatalf("missing recorded resource replaced: writes=%d err=%v", numWrites(), err)
	}
	// Validation rejects malformed intent before even listing provider resources.
	plan["region"] = "eu-frankfurt-1"
	if _, err := foundation.Reconcile(t.Context(), plan); err == nil || numWrites() != 1 {
		t.Fatalf("invalid intent wrote provider resources: %v", err)
	}
	// A reusable foundation must inspect under the current reconciliation,
	// even after the context used for its initial home lookup has ended.
	inspectionIDs := Object{}
	for _, key := range []string{"control_compartment", "network_compartment", "workload_compartment", "vault", "key", "vcn", "subnet", "network_security_group", "security_list", "controller_dynamic_group", "controller_policy", "objectstorage_key_policy", "host_dynamic_group"} {
		inspectionIDs[key] = resourceID
	}
	inspectionPlan := Object{"resource_ids": inspectionIDs, "bootstrap_object_prefix": ""}
	state.Lock()
	initialInspections := inspections
	state.Unlock()
	if err := foundation.inspect(t.Context(), inspectionPlan); err == nil || !strings.Contains(err.Error(), "identity differs") {
		t.Fatalf("fresh inspection inherited constructor cancellation: %v", err)
	}
	state.Lock()
	before := inspections
	state.Unlock()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := foundation.inspect(canceled, inspectionPlan); err == nil {
		t.Fatal("canceled inspection succeeded")
	}
	state.Lock()
	defer state.Unlock()
	if inspections != before || before != initialInspections+1 {
		t.Fatalf("inspection cancellation reached provider: before=%d after=%d", before, inspections)
	}
}
