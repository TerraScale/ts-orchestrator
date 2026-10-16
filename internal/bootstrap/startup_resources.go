package bootstrap

import (
	"encoding/json/v2"
	"slices"
	"time"
)

// StartupFounderResources binds the finite initial controller topology to the
// same grant as its profiles, image and template. It grants no later scaling.
type StartupFounderResources struct {
	LaunchDeadline time.Time              `json:"launchDeadline"`
	Slots          []StartupSlotResources `json:"slots"`
}

type StartupSlotResources struct {
	Slot                 string                `json:"slot"`
	ImageCompartmentOCID string                `json:"imageCompartmentOcid"`
	WholeOCPUs           uint32                `json:"wholeOcpus"`
	MemoryInGB           uint32                `json:"memoryInGb"`
	BootVolumeGB         uint32                `json:"bootVolumeGb"`
	BootVolumeTier       FounderBootVolumeTier `json:"bootVolumeTier"`
}

func (resources StartupFounderResources) Clone() StartupFounderResources {
	resources.Slots = slices.Clone(resources.Slots)
	return resources
}

func (resources StartupFounderResources) Validate(slots []string) error {
	if len(slots) != 3 || len(resources.Slots) != len(slots) || resources.LaunchDeadline.IsZero() || resources.LaunchDeadline.Location() != time.UTC {
		return ErrFounderPlanInvalid
	}
	for index, resource := range resources.Slots {
		if resource.Slot != slots[index] || !controllerSlotRE.MatchString(resource.Slot) || index > 0 && resource.Slot <= resources.Slots[index-1].Slot || !isOCID(resource.ImageCompartmentOCID, "compartment") || resource.WholeOCPUs == 0 || resource.MemoryInGB == 0 || resource.BootVolumeGB < founderMinBootVolumeGB || resource.BootVolumeGB > founderMaxBootVolumeGB || resource.BootVolumeTier != FounderBootVolumeTierBalanced {
			return ErrFounderPlanInvalid
		}
	}
	return nil
}

func (resources StartupFounderResources) Digest() (string, error) {
	wire, err := json.Marshal(resources, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestBytes(wire), nil
}

func ControllerBootstrapProfileDigest(profile LaunchProfile) (string, error) {
	wire, err := json.Marshal(profile, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestBytes(wire), nil
}

func ControllerBootstrapRecipeDigest(template StartupTemplate) (string, error) {
	wire, err := json.Marshal(template, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digestBytes(wire), nil
}
