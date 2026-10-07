package manager

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// writeImageInput writes the image's netbird.json for a region other than
// the home region from its reviewed plan (TS-663): the plan's OCI region and
// every host's node name as its peer name. The region's servers enroll
// through the manager's public address, so there is no management_ip and no
// admin PAT. The home region's input carries the desired state's slots and
// is edited by hand.
func writeImageInput(planPath, setupKeySecretID, out string) error {
	wire, err := os.ReadFile(planPath)
	if err != nil {
		return err
	}
	var plan struct {
		Cell   string `json:"cell"`
		Region string `json:"region"`
		Hosts  []struct {
			Slot      string `json:"slot"`
			PrivateIP string `json:"private_ip"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(wire, &plan); err != nil {
		return fmt.Errorf("regional plan: %w", err)
	}
	if catalog.OCIRegion(plan.Cell) == "" || catalog.OCIRegion(plan.Cell) != plan.Region {
		return fmt.Errorf("regional plan cell %q and region %q are not a catalog region", plan.Cell, plan.Region)
	}
	if plan.Cell == catalog.Bootstrap {
		return errors.New("the home region's NetBird input is deploy/image/inputs/netbird-gru.json, which follows the desired state")
	}
	cell := naming.RegionCell(plan.Cell)
	config := client.Config{ManagementURL: DefaultManagementURL, Region: plan.Region,
		SetupKeySecretID: setupKeySecretID, PeerNames: map[string]string{}}
	for _, host := range plan.Hosts {
		name, err := cell.MemberSlot(host.Slot)
		if strings.HasPrefix(host.Slot, "controller-") {
			name, err = cell.ControllerSlot(host.Slot)
		}
		if err != nil {
			return err
		}
		config.PeerNames[host.PrivateIP] = name
	}
	file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return fmt.Errorf("cannot create the NetBird image input: %w", err)
	}
	err = json.MarshalWrite(file, config, jsontext.WithIndent("  "), json.Deterministic(true))
	if err == nil {
		_, err = file.WriteString("\n")
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	// The image builder reads it with the same validator.
	if err == nil {
		_, err = client.ValidateConfig(out)
	}
	if err != nil {
		os.Remove(out)
	}
	return err
}
