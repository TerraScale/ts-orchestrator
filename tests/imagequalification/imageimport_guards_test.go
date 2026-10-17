package imagequalification

import (
	"errors"
	"net/http"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
)

type forbiddenImageImportDispatch struct{ calls *int }

func (d forbiddenImageImportDispatch) Do(*http.Request) (*http.Response, error) {
	*d.calls += 1
	return nil, errors.New("SDK fixture forbids network dispatch")
}

func TestImageUploaderPreservesExistingSDKRequestGuards(t *testing.T) {
	f := fixture(t)
	factory := sdkFactory(t, f.prepared.Approval())
	compute, err := factory.Compute()
	if err != nil {
		t.Fatal(err)
	}
	objects, err := factory.ObjectStorage()
	if err != nil {
		t.Fatal(err)
	}
	work, err := factory.WorkRequests()
	if err != nil {
		t.Fatal(err)
	}
	blocked, calls := errors.New("original SDK request guard blocked dispatch"), 0
	wireCalls := 0
	for _, base := range []*common.BaseClient{&compute.BaseClient, &objects.BaseClient, &work.BaseClient} {
		base.HTTPClient = forbiddenImageImportDispatch{calls: &wireCalls}
		base.Interceptor = func(*http.Request) error {
			calls++
			return blocked
		}
	}
	client := imageimport.NewClientFromSDK(compute, objects, work)
	if _, err := client.GetImage(t.Context(), "ocid1.image.oc1.sa-saopaulo-1.tested"); !errors.Is(err, blocked) {
		t.Fatalf("image SDK request bypassed original guard: %v", err)
	}
	if _, _, err := client.HeadObject(t.Context(), "namespace", "bucket", "object"); !errors.Is(err, blocked) {
		t.Fatalf("object SDK request bypassed original guard: %v", err)
	}
	if _, err := client.GetWorkRequest(t.Context(), "ocid1.workrequest.oc1..tested"); !errors.Is(err, blocked) {
		t.Fatalf("work request bypassed original guard: %v", err)
	}
	if calls != 3 || wireCalls != 0 {
		t.Fatalf("guard calls=%d, wire calls=%d; want three guarded requests and no dispatch", calls, wireCalls)
	}
}
