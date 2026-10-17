package rootoci

import "testing"

func TestQualificationOnlyAdmitsFixedReads(t *testing.T) {
	service := new(QualificationService)
	for _, operation := range []Operation{OperationInventory, OperationObserveFleet, OperationCosts, OperationReleaseChannel} {
		if service.validRequest(wireRequest{Operation: operation, Payload: []byte("{}")}) {
			t.Fatalf("unneeded qualification operation admitted: %s", operation)
		}
	}
	if !service.validRequest(wireRequest{Operation: OperationObserveLocalInstance, Payload: []byte("{}")}) || !service.validRequest(wireRequest{Operation: OperationObserveImage, Payload: []byte(`{"image_id":"ocid1.image.oc1.sa-saopaulo-1.test"}`)}) {
		t.Fatal("actual fixed qualification reads rejected")
	}
}
