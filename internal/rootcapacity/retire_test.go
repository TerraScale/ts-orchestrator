package rootcapacity

import (
	"net/http"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestTerminalRequestsPreserveBootAndDataAndNeverInventDeleteTokens(t *testing.T) {
	child := region.PoolChildRecord{InstanceID: "original-instance", BootVolumeID: "original-boot"}
	terminate := terminateRequest(child, "original-instance-etag")
	if value(terminate.InstanceId) != child.InstanceID || value(terminate.IfMatch) != "original-instance-etag" ||
		terminate.PreserveBootVolume == nil || !*terminate.PreserveBootVolume ||
		terminate.PreserveDataVolumesCreatedAtLaunch == nil || !*terminate.PreserveDataVolumesCreatedAtLaunch {
		t.Fatal("termination widened original identity or implicitly deleted original boot/data volumes")
	}
	deletion := deleteBootRequest(child, "original-boot-etag")
	if value(deletion.BootVolumeId) != child.BootVolumeID || value(deletion.IfMatch) != "original-boot-etag" {
		t.Fatal("boot deletion changed original exact volume or conditional wire")
	}
	for _, request := range []common.OCIRequest{terminate, deletion} {
		raw, err := request.HTTPRequest(http.MethodDelete, "/original", nil, nil)
		if err != nil || raw.Header.Get("opc-retry-token") != "" {
			t.Fatalf("DELETE acquired an unsupported retry token: %v", err)
		}
	}
}
