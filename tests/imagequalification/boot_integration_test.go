package imagequalification

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeBootRecoversExactCapabilityCreateAndRejectsForeignCleanup(t *testing.T) {
	f := fixture(t)
	remote := &cloudFixture{hosts: map[string]map[string]any{}, tokens: map[string]string{}, failCapabilityResponse: true}
	server := httptest.NewServer(http.HandlerFunc(remote.serve))
	defer server.Close()
	client, err := newCloud(f.prepared, sdkFactory(t, f.prepared.Approval()), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	path, public := filepath.Join(t.TempDir(), "resources.json"), publicSSHKey(t)
	partial, err := client.prepareResources(t.Context(), path, public)
	if err == nil || partial.CapabilityID != "" || partial.CapabilityVersion != "fixture-version" || partial.Intents["capability"].IsZero() || len(partial.Hosts) != 0 || remote.capabilityCreates != 1 {
		t.Fatalf("lost capability response was not durably bounded: journal=%+v err=%v", partial, err)
	}
	if err := client.cleanup(t.Context(), path); err == nil || !strings.Contains(err.Error(), "unresolved create intent") || remote.deletes != 0 {
		t.Fatalf("ambiguous capability create reported clean: deletes=%d err=%v", remote.deletes, err)
	}
	complete, err := client.prepareResources(t.Context(), path, public)
	if err != nil {
		t.Fatal(err)
	}
	if complete.CapabilityID == "" || remote.capabilityCreates != 1 || len(complete.Hosts) != 4 || remote.capabilityToken != client.token("capability") {
		t.Fatal("capability resume did not reuse exact token and canonical native boot contract")
	}
	tags := remote.capability["freeformTags"]
	remote.capability["freeformTags"] = map[string]any{runTag: "foreign"}
	if err := client.cleanup(t.Context(), path); err == nil || remote.deletes != 4 || remote.capability == nil || remote.image == nil || remote.object == nil {
		t.Fatalf("foreign capability cleanup crossed ownership boundary: deletes=%d err=%v", remote.deletes, err)
	}
	remote.capability["freeformTags"] = tags
	if err := client.cleanup(t.Context(), path); err != nil {
		t.Fatal(err)
	}
	j, err := client.load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !j.CapabilityDeleted || !j.ImageDeleted || !j.ObjectDeleted || remote.deletes != 7 {
		t.Fatalf("native boot cleanup incomplete: journal=%+v deletes=%d", j, remote.deletes)
	}
}
