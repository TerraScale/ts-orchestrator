//go:build linux

package host

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

func TestTerraBaseDataVolumeNameReuseGetsOneFreshFormatGrant(t *testing.T) {
	c, _, _, _, _ := testController(t)
	retired := Registration{Cell: "gru", Node: "gru-1-db-1", Roles: []string{terrabase.Role}, PublicKey: "first-host", Generation: 1,
		TerraBaseDataVolumeID: "ocid1.volume.oc1..retired"}
	const attempt = "014D2PF2DBSQQG28T5CY4TQKFF"
	ask := func(r Registration, volumeID, mounted string) (terraBaseFormatReply, error) {
		t.Helper()
		query := terraBaseFormatQuery{VolumeID: volumeID, Mounted: mounted}
		if mounted == "" {
			query.AttemptID = attempt
		}
		payload, err := protocol.EncodeJSON(query)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := c.serveTerraBaseFormat(t.Context(), request{Node: r.Node, Payload: payload}, r)
		if err != nil {
			return terraBaseFormatReply{}, err
		}
		return reply.(terraBaseFormatReply), nil
	}
	first, err := ask(retired, retired.TerraBaseDataVolumeID, "")
	if err != nil || !first.Granted {
		t.Fatalf("first volume grant = %+v, %v", first, err)
	}
	fresh := retired
	fresh.TerraBaseDataVolumeID = "ocid1.volume.oc1..fresh"
	second, err := ask(fresh, fresh.TerraBaseDataVolumeID, "")
	if err != nil || !second.Granted || second.UUID == first.UUID || second.VolumeID != fresh.TerraBaseDataVolumeID {
		t.Fatalf("reused name grant = %+v, %v; want fresh volume and filesystem", second, err)
	}
	for i, r := range []Registration{retired, fresh} {
		uuid := []string{first.UUID, second.UUID}[i]
		again, err := ask(r, r.TerraBaseDataVolumeID, "")
		if err != nil || !again.Granted || again.UUID != uuid {
			t.Fatalf("pending grant for %s = %+v, %v; want %s", r.TerraBaseDataVolumeID, again, err, uuid)
		}
		confirmed, err := ask(r, r.TerraBaseDataVolumeID, uuid)
		if err != nil || confirmed.Granted || confirmed.UUID != uuid {
			t.Fatalf("mounted confirmation for %s = %+v, %v", r.TerraBaseDataVolumeID, confirmed, err)
		}
		again, err = ask(r, r.TerraBaseDataVolumeID, "")
		if err != nil || again.Granted || again.UUID != uuid {
			t.Fatalf("closed grant for %s = %+v, %v", r.TerraBaseDataVolumeID, again, err)
		}
	}
	if _, err := ask(retired, fresh.TerraBaseDataVolumeID, ""); err == nil {
		t.Fatal("old registered host selected the new member's format grant")
	}
	if _, err := ask(fresh, retired.TerraBaseDataVolumeID, ""); err == nil {
		t.Fatal("new registered host selected the retired member's format grant")
	}
	if _, err := ask(fresh, "", ""); err == nil {
		t.Fatal("format request without volume identity accepted")
	}
}
