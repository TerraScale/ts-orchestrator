package rootoci

import "testing"

func TestTaskTrafficRejectsCallerBackendAuthority(t *testing.T) {
	service := new(Service)
	for _, payload := range []string{
		`{}`, `{"role":""}`, `{"role":"terrabase","backends":[]}`,
		`{"role":"terrabase","health":true}`, `{"role":"terrabase","operationId":"chosen"}`,
	} {
		if service.validRequest(wireRequest{Operation: OperationReconcileTaskTraffic, Payload: []byte(payload)}) {
			t.Fatalf("caller-selected traffic authority accepted: %s", payload)
		}
	}
	if !service.validRequest(wireRequest{Operation: OperationReconcileTaskTraffic, Payload: []byte(`{"role":"terrabase"}`)}) {
		t.Fatal("finite signed-role selector rejected")
	}
	if OperationReconcileTaskTraffic.ReadOnly() {
		t.Fatal("traffic mutation admitted during startup reads")
	}
}
