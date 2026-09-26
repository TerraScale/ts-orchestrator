package fixturegen

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	jsonv1 "encoding/json"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/core"
)

// ComputeInventory is a per-instance, SDK-request-derived read inventory for
// the initial authenticated Compute/VNIC observation replayed on restart.
// The v1 encoder is required here because OCI SDK model types implement v1
// MarshalJSON methods used by their generated wire contract.
type ComputeInventory struct {
	Routes []Route
	Bodies map[string][]byte
}

func BuildComputeInventory(recipe SignedHistoryRecipe, guests GuestMaterialInputs) (ComputeInventory, error) {
	if !recipe.Anchor.IsVerified() || len(recipe.Observed) != 3 || len(guests.VNICs) != 3 ||
		recipe.Now.IsZero() {
		return ComputeInventory{}, errors.New("Compute inventory requires anchored three-slot observations")
	}
	anchor := recipe.Anchor.Anchor()
	plan, err := bootstrap.VerifyFounderPlan(recipe.FounderPlanWire, recipe.Roots,
		recipe.Anchor.Wire(), recipe.ManifestWires, recipe.Now,
		trust.Policy{MaxLifetime: 24 * time.Hour, ClockSkew: bootstrap.ManifestClockSkew})
	if err != nil {
		return ComputeInventory{}, err
	}
	imageOCID := plan.Plan().Peers[0].ImageOCID
	inventory := ComputeInventory{Bodies: make(map[string][]byte, 9)}
	add := func(slot, instanceOCID, requestURI, etag string, body []byte) error {
		if requestURI == "" || etag == "" || len(body) == 0 {
			return errors.New("Compute response lacks exact URI, ETag, or body")
		}
		name := "simulator/responses/" + historyDigest(body) + ".json"
		if previous, ok := inventory.Bodies[name]; ok && !bytes.Equal(previous, body) {
			return errors.New("Compute response digest collision")
		}
		inventory.Bodies[name] = bytes.Clone(body)
		inventory.Routes = append(inventory.Routes, Route{ControllerSlot: slot,
			InstanceOCID: instanceOCID, Host: "iaas.sa-saopaulo-1.oraclecloud.com",
			RequestURI: requestURI, Status: http.StatusOK, BodyPath: name,
			ETag: etag, LastModified: recipe.Now})
		return nil
	}
	for _, slot := range anchor.ControllerSlots {
		observed, ok := recipe.Observed[slot]
		vnic, hasVNIC := guests.VNICs[slot]
		if !ok || !hasVNIC || !strings.HasPrefix(observed.InstanceOCID,
			"ocid1.instance.oc1.sa-saopaulo-1.") ||
			!strings.HasPrefix(vnic.PrimaryVNICOCID, "ocid1.vnic.oc1.sa-saopaulo-1.") ||
			vnic.PrimaryPrivateIP == "" {
			return ComputeInventory{}, fmt.Errorf("controller %q lacks GRU Compute/VNIC identity", slot)
		}
		manifestWire := recipe.ManifestWires[slot]
		manifestEnvelope, err := trust.DecodeEnvelope(manifestWire)
		if err != nil {
			return ComputeInventory{}, err
		}
		manifest, err := bootstrap.VerifyManifest(manifestEnvelope, recipe.Roots,
			bootstrap.ManifestExpectation{DeploymentID: anchor.DeploymentID, Environment: anchor.Environment,
				ClusterID: anchor.ClusterID, Cell: anchor.Cell, Slot: slot,
				ImageOCID: imageOCID, StorageDomain: anchor.StorageDomain,
				ControllerSlots:  slices.Clone(anchor.ControllerSlots),
				IntentGeneration: anchor.InitialRegionIntentGeneration,
				IntentSHA256:     anchor.InitialRegionIntentSHA256}, recipe.Now, bootstrap.ManifestTrustPolicy())
		if err != nil {
			return ComputeInventory{}, fmt.Errorf("verify Compute slot manifest %q: %w", slot, err)
		}
		profile, ok := manifest.Profile(slot)
		if !ok {
			return ComputeInventory{}, fmt.Errorf("manifest has no Compute profile for %q", slot)
		}
		instanceBody, err := jsonv1.Marshal(core.Instance{Id: new(observed.InstanceOCID),
			CompartmentId: new(profile.CompartmentOCID), ImageId: new(manifest.Manifest().ImageOCID),
			AvailabilityDomain: new(profile.AvailabilityDomain), FaultDomain: new(profile.FaultDomain),
			Shape: new(profile.Shape), LifecycleState: core.InstanceLifecycleStateRunning})
		if err != nil {
			return ComputeInventory{}, err
		}
		instanceRequest, err := (core.GetInstanceRequest{InstanceId: new(observed.InstanceOCID)}).HTTPRequest(
			http.MethodGet, "/20160918/instances/{instanceId}", nil, nil)
		if err != nil {
			return ComputeInventory{}, err
		}
		if err := add(slot, observed.InstanceOCID, instanceRequest.URL.RequestURI(), observed.ETag, instanceBody); err != nil {
			return ComputeInventory{}, err
		}
		attachmentBody, err := jsonv1.Marshal([]core.VnicAttachment{{InstanceId: new(observed.InstanceOCID),
			CompartmentId: new(profile.CompartmentOCID), VnicId: new(vnic.PrimaryVNICOCID),
			SubnetId: new(profile.SubnetOCID), LifecycleState: core.VnicAttachmentLifecycleStateAttached}})
		if err != nil {
			return ComputeInventory{}, err
		}
		attachmentRequest, err := (core.ListVnicAttachmentsRequest{
			CompartmentId: new(profile.CompartmentOCID), InstanceId: new(observed.InstanceOCID), Limit: new(50),
		}).HTTPRequest(http.MethodGet, "/20160918/vnicAttachments", nil, nil)
		if err != nil {
			return ComputeInventory{}, err
		}
		if err := add(slot, observed.InstanceOCID, attachmentRequest.URL.RequestURI(),
			"attachments-"+slot, attachmentBody); err != nil {
			return ComputeInventory{}, err
		}
		vnicBody, err := jsonv1.Marshal(core.Vnic{Id: new(vnic.PrimaryVNICOCID),
			CompartmentId: new(profile.CompartmentOCID), AvailabilityDomain: new(profile.AvailabilityDomain),
			SubnetId: new(profile.SubnetOCID), PrivateIp: new(vnic.PrimaryPrivateIP), IsPrimary: new(true),
			NsgIds: slices.Clone(profile.NetworkSecurityGroupOCIDs), LifecycleState: core.VnicLifecycleStateAvailable})
		if err != nil {
			return ComputeInventory{}, err
		}
		vnicRequest, err := (core.GetVnicRequest{VnicId: new(vnic.PrimaryVNICOCID)}).HTTPRequest(
			http.MethodGet, "/20160918/vnics/{vnicId}", nil, nil)
		if err != nil {
			return ComputeInventory{}, err
		}
		if err := add(slot, observed.InstanceOCID, vnicRequest.URL.RequestURI(), "vnic-"+slot, vnicBody); err != nil {
			return ComputeInventory{}, err
		}
	}
	slices.SortFunc(inventory.Routes, func(a, b Route) int {
		return strings.Compare(a.ControllerSlot+"\n"+a.InstanceOCID+"\n"+a.Host+"\n"+a.RequestURI,
			b.ControllerSlot+"\n"+b.InstanceOCID+"\n"+b.Host+"\n"+b.RequestURI)
	})
	return inventory, nil
}
