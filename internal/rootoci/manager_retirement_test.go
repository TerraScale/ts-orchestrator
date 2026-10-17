package rootoci

import (
	"encoding/json/v2"
	"testing"
)

func TestControllerManagerRetirementBoundsAndAuthority(t *testing.T) {
	service := new(Service)
	request := RetireControllerManagerRequest{Cell: "GRU", Slot: "controller-a", PriorInstanceID: "ocid1.instance.oc1.sa-saopaulo-1.old", NodeID: "old-manager", NodeVersion: 9, Epoch: 7}
	for _, size := range []int{0, MaxControllerRetirementBytes, MaxControllerRetirementBytes + 1} {
		request.Retirement = make([]byte, size)
		payload, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		if got := service.validRequest(wireRequest{Operation: OperationRetireControllerManager, Payload: payload}); got != (size <= MaxControllerRetirementBytes) {
			t.Fatalf("retirement size %d accepted=%v", size, got)
		}
	}
	if service.validRequest(wireRequest{Operation: OperationRetireControllerManager, Payload: []byte(`{"force":true}`)}) {
		t.Fatal("caller-selected force removal accepted")
	}
	if OperationRetireControllerManager.ReadOnly() {
		t.Fatal("manager removal admitted during startup reads")
	}
}
