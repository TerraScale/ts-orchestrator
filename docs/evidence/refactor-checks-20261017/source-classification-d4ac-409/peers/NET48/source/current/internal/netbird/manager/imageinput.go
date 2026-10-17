package manager

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"os"
	"syscall"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

// writeImageInput writes public enrollment configuration for any catalog
// region. Hosts enroll under their OCI-provided hostname; no peer map is baked in.
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
	config := client.Config{ManagementURL: DefaultManagementURL, Region: plan.Region,
		SetupKeySecretID: setupKeySecretID}

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
