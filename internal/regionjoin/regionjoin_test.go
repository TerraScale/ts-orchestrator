package regionjoin

import (
	"encoding/json/v2"
	"testing"
)

// The JSON names are the contract between founders and joiners of different releases.
func TestMaterialJSON(t *testing.T) {
	data, err := json.Marshal(Material{Founder: "ts-gru-1", Manager: "10.0.0.2:4242", WorkerToken: "token"})
	if err != nil || string(data) != `{"founder":"ts-gru-1","manager":"10.0.0.2:4242","workerToken":"token"}` {
		t.Fatalf("material JSON %s, %v", data, err)
	}
	if claim, err := decode("gru", `{"founder":"ts-gru-2","later":"field"}`); err != nil || claim != (Material{Founder: "ts-gru-2"}) {
		t.Fatalf("claim decode %+v, %v", claim, err)
	}
	for _, bad := range []string{`{}`, `not json`, `{"manager":"10.0.0.2:4242"}`} {
		if _, err := decode("gru", bad); err == nil {
			t.Fatalf("decoded %s", bad)
		}
	}
}
