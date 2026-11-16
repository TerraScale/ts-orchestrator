package region

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// The original producer supplies its own sealed allocation; generic spending
// verification never accepts an original schema-3 grant.
type netBirdManagerAllocation interface {
	Slot() BootstrapSlotIntent
	IsVerified() bool
	InstallationID() string
	Generation() uint64
	GrantDigest() string
	BindingDigest() string
	ScopeDigest() string
	PhysicalScopeDigest() string
	OperationID() string
	ExpiresAt() time.Time
	Footprint() capacityinventory.Scope
	Revalidate(context.Context) error
	Validate(BootstrapLaunchRequest, capacityinventory.Quote, time.Time) error
}

func (launch NetBirdManagerLaunch) validateOriginalQuote(details core.LaunchInstanceDetails) error {
	q := launch.OriginalQuote
	if q == nil {
		return nil
	}
	source, ok := details.SourceDetails.(core.InstanceSourceViaImageDetails)
	shape := details.ShapeConfig
	if q.Validate() != nil || q.ScopeSHA256 != launch.PhysicalScopeSHA256 || q.Cell != "GRU" || details.CompartmentId == nil || q.CompartmentID != *details.CompartmentId ||
		details.Shape == nil || q.Shape != *details.Shape || shape == nil || shape.Ocpus == nil || shape.MemoryInGBs == nil || q.OCPUs != float64(*shape.Ocpus) || q.MemoryGB != float64(*shape.MemoryInGBs) ||
		!ok || source.BootVolumeSizeInGBs == nil || q.BootGB != float64(*source.BootVolumeSizeInGBs) || source.BootVolumeVpusPerGB == nil || *source.BootVolumeVpusPerGB != 10 {
		return errors.New("dedicated manager original quote differs from its exact SDK launch scope or billing geometry")
	}
	return nil
}

func validateNetBirdAllocation(allocation netBirdManagerAllocation, intent verifiedNetBirdIntent, compartment string) error {
	p, s := intent.intent.Profile, allocation.Slot()
	if !allocation.IsVerified() || !time.Now().Before(allocation.ExpiresAt()) || allocation.InstallationID() != intent.installationID || allocation.Generation() != intent.generation || allocation.GrantDigest() != intent.grantDigest ||
		s.Cell != "GRU" || s.Role != NetBirdManagerRole || s.Slot != NetBirdManagerRole || s.CompartmentID != compartment || s.ProfileSHA256 != intent.profileDigest || s.RecipeSHA256 != intent.recipeDigest ||
		s.Shape != p.Shape || s.OCPUs != float64(p.OCPUs) || s.MemoryGB != float64(p.MemoryGB) || s.BootGB != float64(p.BootVolumeGB) {
		return errors.New("dedicated manager differs from its current same-grant finite slot")
	}
	return nil
}

func netBirdLaunchDetails(intent NetBirdManagerIntent, compartment, subnet, nsg string) core.LaunchInstanceDetails {
	p := intent.Profile
	return core.LaunchInstanceDetails{AvailabilityDomain: new(p.AvailabilityDomain), CompartmentId: new(compartment), FaultDomain: new(p.FaultDomain),
		DisplayName: new("gru-1-netbird-manager"), Shape: new(p.Shape),
		ShapeConfig:       &core.LaunchInstanceShapeConfigDetails{Ocpus: new(p.OCPUs), MemoryInGBs: new(p.MemoryGB)},
		SourceDetails:     core.InstanceSourceViaImageDetails{ImageId: new(intent.ImageOCID), BootVolumeSizeInGBs: new(p.BootVolumeGB), BootVolumeVpusPerGB: new(int64(10))},
		CreateVnicDetails: &core.CreateVnicDetails{SubnetId: new(subnet), NsgIds: []string{nsg}, PrivateIp: new(p.PrivateIP), AssignPublicIp: new(true)}}
}

func netBirdRequestDigest(details core.LaunchInstanceDetails) (string, error) {
	request := core.LaunchInstanceRequest{LaunchInstanceDetails: details}
	httpRequest, err := request.HTTPRequest(http.MethodPost, "/20160918/instances", nil, nil)
	if err != nil {
		return "", err
	}
	if httpRequest.Body == nil {
		return "", errors.New("dedicated manager SDK request has no body")
	}
	defer httpRequest.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(httpRequest.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var object map[string]any
	if err := json.Unmarshal(wire, &object); err != nil {
		return "", err
	}
	wire, err = json.Marshal(object, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}
