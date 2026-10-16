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
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
)

// This scenario crosses the actual signed SDK/HTTP provider boundary. It stops
// after the first durable OCID checkpoint, before downstream resources exist.
func TestFoundationSDKOwnershipCheckpointAndRecovery(t *testing.T) {
	const resourceID = "ocid1.compartment.oc1..ownedcontrol"
	var live Object
	writes, guards, releases := 0, 0, 0
	parent := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") == "" {
			t.Error("unsigned OCI request")
		}
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/20160918/tenancies/"):
			io.WriteString(w, `{"homeRegionKey":"FRA"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/20160918/compartments":
			if live == nil {
				io.WriteString(w, `[]`)
			} else {
				data, _ := json.Marshal([]Object{live})
				w.Write(data)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/20160918/compartments":
			writes++
			if !strings.Contains(r.Host, "eu-frankfurt-1") {
				t.Errorf("IAM write addressed non-home endpoint %s", r.Host)
			}
			if r.Header.Get("opc-retry-token") == "" {
				t.Error("create omitted retry token")
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			if err := json.Unmarshal(body, &live); err != nil {
				t.Error(err)
			}
			live["id"], live["lifecycleState"] = resourceID, "ACTIVE"
			data, _ := json.Marshal(live)
			w.Write(data)
		case r.Method == http.MethodGet && r.URL.Path == "/20160918/compartments/"+resourceID:
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
	plan := loadPlan(t)
	provider := common.NewRawConfigurationProvider(text(plan["tenancy_id"]), "ocid1.user.oc1..test", sfo, "test", string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: sfo, Limits: map[ociclient.Service]ociclient.Limit{ociclient.ServiceIdentity: {PerSecond: 10000, Burst: 10000}}})
	if err != nil {
		t.Fatal(err)
	}
	foundation, err := New(t.Context(), factory, text(plan["tenancy_id"]))
	if err != nil {
		t.Fatal(err)
	}
	foundation.OperationID = "durable-sfo-foundation"
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
	// Same-name foreign resources must be refused before any provider mutation.
	live = Object{"id": resourceID, "name": "sfo-1-control", "compartmentId": parent, "lifecycleState": "ACTIVE"}
	if _, err := foundation.Reconcile(t.Context(), plan); err == nil || !strings.Contains(err.Error(), "ownership") || writes != 0 {
		t.Fatalf("foreign adoption: writes=%d err=%v", writes, err)
	}
	live = nil
	if _, err := foundation.Reconcile(t.Context(), plan); !errors.Is(err, interrupted) || !checkpointed || writes != 1 || guards != 1 || releases != 1 {
		t.Fatalf("checkpoint boundary: writes=%d guards=%d releases=%d err=%v", writes, guards, releases, err)
	}
	tags := obj(live["freeformTags"])
	if tags["terrascale.owner"] != "ts-orch" || tags["terrascale.cell"] != "sfo-1" {
		t.Fatalf("creation omitted ownership: %v", tags)
	}
	// The controller restores this checkpoint after restart; an identical resource
	// is recovered without a second create, and a discovery miss cannot replace it.
	obj(plan["resource_ids"])["control_compartment"] = resourceID
	if _, err := foundation.Reconcile(t.Context(), plan); !errors.Is(err, interrupted) || writes != 1 {
		t.Fatalf("restart duplicated resource: writes=%d err=%v", writes, err)
	}
	live = nil
	if _, err := foundation.Reconcile(t.Context(), plan); err == nil || !strings.Contains(err.Error(), "refusing replacement") || writes != 1 {
		t.Fatalf("missing recorded resource replaced: writes=%d err=%v", writes, err)
	}
	// Validation rejects malformed intent before even listing provider resources.
	plan["region"] = "eu-frankfurt-1"
	if _, err := foundation.Reconcile(t.Context(), plan); err == nil || writes != 1 {
		t.Fatalf("invalid intent wrote provider resources: %v", err)
	}
}
