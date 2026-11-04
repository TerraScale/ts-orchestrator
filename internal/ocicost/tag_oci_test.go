package ocicost

import (
	"context"
	"maps"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestOCITagsRetagMergesAndSendsIfMatch(t *testing.T) {
	compute := &fakeCompute{instance: core.Instance{FreeformTags: map[string]string{"owner": "a", RegionTag: "gru"}}, etag: "e1"}
	tags := &OCITags{compute: compute}
	err := tags.Retag(t.Context(), Resource{ID: "ocid1.instance.a", Type: "Instance"},
		map[string]string{RegionTag: "GRU", ComponentTag: "controller"})
	if err != nil {
		t.Fatal(err)
	}
	if len(compute.updates) != 1 {
		t.Fatalf("updates = %d, want 1", len(compute.updates))
	}
	update := compute.updates[0]
	want := map[string]string{"owner": "a", RegionTag: "GRU", ComponentTag: "controller"}
	if *update.IfMatch != "e1" || !maps.Equal(update.UpdateInstanceDetails.FreeformTags, want) {
		t.Fatalf("update if-match %q tags %v, want e1 and %v", *update.IfMatch, update.UpdateInstanceDetails.FreeformTags, want)
	}
}

type fakeCompute struct {
	computeAPI
	instance  core.Instance
	etag      string
	getErr    error
	updateErr error
	updates   []core.UpdateInstanceRequest
}

func (f *fakeCompute) GetInstance(context.Context, core.GetInstanceRequest) (core.GetInstanceResponse, error) {
	if f.getErr != nil {
		return core.GetInstanceResponse{}, f.getErr
	}
	return core.GetInstanceResponse{Instance: f.instance, Etag: common.String(f.etag)}, nil
}
func (f *fakeCompute) UpdateInstance(_ context.Context, request core.UpdateInstanceRequest) (core.UpdateInstanceResponse, error) {
	f.updates = append(f.updates, request)
	return core.UpdateInstanceResponse{}, f.updateErr
}
