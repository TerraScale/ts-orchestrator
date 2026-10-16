package imagequalification

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConsoleSDKPinsOneRunKeyAndDeletesExactHistories(t *testing.T) {
	f := fixture(t)
	remote := &cloudFixture{hosts: map[string]map[string]any{}, tokens: map[string]string{}}
	key := publicSSHKey(t)
	var history map[string]any
	captures := 0
	foreign := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "instanceConsoleHistories") || strings.HasSuffix(r.URL.Path, "/vnicAttachments") || strings.Contains(r.URL.Path, "/vnics/") {
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("opc-request-id", "console-fixture")
			if strings.HasSuffix(r.URL.Path, "/vnicAttachments") {
				id := r.URL.Query().Get("instanceId")
				_ = json.MarshalWrite(w, []any{map[string]any{"id": "ocid1.vnicattachment.oc1..exact", "instanceId": id, "compartmentId": f.prepared.approval.Compartment, "subnetId": f.prepared.approval.Subnet, "vnicId": "ocid1.vnic.oc1..exact", "availabilityDomain": "fixture-ad", "lifecycleState": "ATTACHED"}})
				return
			}
			if strings.Contains(r.URL.Path, "/vnics/") {
				_ = json.MarshalWrite(w, map[string]any{"id": "ocid1.vnic.oc1..exact", "subnetId": f.prepared.approval.Subnet, "privateIp": "10.8.0.2", "isPrimary": true, "lifecycleState": "AVAILABLE"})
				return
			}
			if r.Method == http.MethodPost {
				if err := json.UnmarshalRead(r.Body, &history); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				captures++
				history["id"], history["availabilityDomain"], history["compartmentId"], history["lifecycleState"], history["timeCreated"] = "ocid1.consolehistory.oc1..exact", "fixture-ad", f.prepared.approval.Compartment, "SUCCEEDED", time.Now().UTC()
			} else if history == nil {
				w.WriteHeader(404)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/data") {
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("opc-bytes-remaining", "0")
				_, _ = fmt.Fprint(w, "fixture-private-console-sentinel\nTSQUAL_HOSTKEY "+f.prepared.approval.RunID+" "+key+"\n")
				return
			}
			if r.Method == http.MethodDelete {
				history = nil
				w.WriteHeader(204)
				return
			}
			if foreign {
				copy := map[string]any{}
				for k, v := range history {
					copy[k] = v
				}
				copy["instanceId"] = "ocid1.instance.oc1..foreign"
				_ = json.MarshalWrite(w, copy)
				return
			}
			_ = json.MarshalWrite(w, history)
			return
		}
		remote.serve(w, r)
	}))
	defer server.Close()
	client, err := newCloud(f.prepared, sdkFactory(t, f.prepared.Approval()), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "resources.json")
	if _, err := client.prepareResources(t.Context(), path, publicSSHKey(t)); err != nil {
		t.Fatal(err)
	}
	spec := f.prepared.approval.Hosts[0]
	observation, pin, err := client.consoleKey(t.Context(), path, spec)
	if err != nil {
		t.Fatal(err)
	}
	if pin != key || captures != 1 || observation.HostKeySHA256 != hashBytes([]byte(key)) || !validHash(observation.ConsoleSHA256) {
		t.Fatalf("console public pin differs: %+v", observation)
	}
	if _, _, err := client.consoleKey(t.Context(), path, spec); err != nil || captures != 1 {
		t.Fatalf("console restart replay: captures=%d err=%v", captures, err)
	}
	foreign = true
	if _, _, err := client.consoleKey(t.Context(), path, spec); err == nil {
		t.Fatal("cached console pin accepted a foreign instance history")
	}
	foreign = false
	originalKey := key
	key = publicSSHKey(t)
	if _, _, err := client.consoleKey(t.Context(), path, spec); err == nil {
		t.Fatal("cached console pin accepted changed authenticated console content")
	}
	key = originalKey
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "fixture-private-console-sentinel") {
		t.Fatal("raw console secrets retained")
	}
	j, err := client.load(path)
	if err != nil {
		t.Fatal(err)
	}
	foreign = true
	if err := client.cleanupConsole(t.Context(), path, &j); err == nil || history == nil {
		t.Fatal("foreign-instance console history deleted")
	}
	foreign = false
	if err := client.cleanup(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	if history != nil {
		t.Fatal("exact console history not deleted")
	}
}

func TestConsoleMarkerRejectsWrongRunDuplicateAndInvalidKeys(t *testing.T) {
	key := publicSSHKey(t)
	for _, content := range []string{"TSQUAL_HOSTKEY other " + key + "\n", "TSQUAL_HOSTKEY nativecase " + key + "\nTSQUAL_HOSTKEY nativecase " + key + "\n", "TSQUAL_HOSTKEY nativecase ssh-ed25519 invalid\n", strings.Repeat("x", maxConsoleBytes+1)} {
		if _, _, err := parseConsoleKey("nativecase", content); err == nil {
			t.Fatal("wrong, duplicate, invalid or oversized console marker accepted")
		}
	}
	if key, _, err := parseConsoleKey("nativecase", "boot in progress\n"); err != nil || key != "" {
		t.Fatal("missing marker should allow another bounded capture")
	}
}
