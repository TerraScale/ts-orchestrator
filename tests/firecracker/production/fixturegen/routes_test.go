package fixturegen

import (
	"strings"
	"testing"
	"time"
)

func TestCapturedObjectRouteUsesExactSDKRequestURI(t *testing.T) {
	controller := Controller{Slot: "seed-a", InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.seed"}
	object := CapturedObject{Namespace: "namespace-a", Bucket: "ledger-bucket",
		ObjectName: "private/bootstrap/seed-a/attempt-1/result-abc.json", Body: []byte(`{"signed":true}`),
		ETag: `"etag"`, LastModified: time.Date(2026, 9, 26, 18, 0, 0, 0, time.UTC)}
	route, err := CapturedObjectRoute(controller, object)
	if err != nil {
		t.Fatal(err)
	}
	if route.ControllerSlot != controller.Slot || route.InstanceOCID != controller.InstanceOCID ||
		route.RequestURI != "/n/namespace-a/b/ledger-bucket/o/private/bootstrap/seed-a/attempt-1/result-abc.json" ||
		route.Host != "objectstorage.sa-saopaulo-1.oraclecloud.com" ||
		!strings.HasPrefix(route.BodyPath, "simulator/responses/") {
		t.Fatalf("captured object route differs from OCI SDK request: %+v", route)
	}
	missing, err := CapturedMissingRoute(controller, CapturedMissing{Namespace: object.Namespace,
		Bucket: object.Bucket, ObjectName: "private/bootstrap/seed-a/attempt-1/absent.json"})
	if err != nil || missing.Status != 404 || missing.BodyPath != "" || missing.ETag != "" ||
		missing.RequestURI != "/n/namespace-a/b/ledger-bucket/o/private/bootstrap/seed-a/attempt-1/absent.json" {
		t.Fatalf("captured expected-missing route mismatch: %+v, %v", missing, err)
	}
}
