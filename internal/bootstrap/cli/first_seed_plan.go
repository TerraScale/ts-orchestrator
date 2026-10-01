package cli

import (
	"fmt"
	"math/big"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// reviewedSeedPlan is the state-free seed preflight produced from the reviewed
// manual region plan, current cost admission, and verified signed manifest.
// The signed reservation carries the digest of its exact JSON bytes.
type reviewedSeedPlan struct {
	SchemaVersion           int       `json:"schema_version"`
	Slot                    string    `json:"slot"`
	Shape                   string    `json:"shape"`
	OCPUs                   int       `json:"ocpus"`
	MemoryGB                int       `json:"memory_gb"`
	BootGB                  int       `json:"boot_gb"`
	BootVPUsPerGB           int       `json:"boot_vpus_per_gb"`
	AssignPublicIP          bool      `json:"assign_public_ip"`
	CompartmentID           string    `json:"compartment_id"`
	AvailabilityDomain      string    `json:"availability_domain"`
	FaultDomain             string    `json:"fault_domain"`
	SubnetID                string    `json:"subnet_id"`
	NetworkSecurityGroupIDs []string  `json:"network_security_group_ids"`
	ImageID                 string    `json:"image_id"`
	AnchorSHA256            string    `json:"anchor_sha256"`
	ManifestSHA256          string    `json:"manifest_sha256"`
	ImageReceiptSHA256      string    `json:"image_receipt_sha256"`
	AdmissionSHA256         string    `json:"admission_sha256"`
	InventorySHA256         string    `json:"inventory_sha256"`
	AdmissionAdmittedAt     time.Time `json:"admission_admitted_at"`
	AdmissionExpiresAt      time.Time `json:"admission_expires_at"`
	MonthlyEstimateUSD      string    `json:"monthly_estimate_usd"`
	CreateIdentity          string    `json:"create_identity"`
}

func readReviewedSeedPlan(path, expectedSHA, createIdentity string, inputs seedInputs,
	now time.Time, requireCurrent bool,
) (reviewedSeedPlan, error) {
	wire, err := readBoundedRegular(path, 16<<10)
	if err != nil || !matchesSHA256(wire, expectedSHA) {
		return reviewedSeedPlan{}, fmt.Errorf("%w: reviewed manual seed plan digest differs from exact input", ErrSeedCLI)
	}
	var reviewed reviewedSeedPlan
	if err := protocol.DecodeStrict(wire, &reviewed, 16<<10); err != nil {
		return reviewedSeedPlan{}, fmt.Errorf("%w: decode reviewed manual seed plan: %v", ErrSeedCLI, err)
	}
	profile, ok := inputs.manifest.Profile(seedSlot)
	manifest := inputs.manifest.Manifest()
	amount, amountOK := new(big.Rat).SetString(reviewed.MonthlyEstimateUSD)
	if !ok || reviewed.SchemaVersion != 2 || reviewed.Slot != seedSlot ||
		reviewed.CreateIdentity != createIdentity || !seedCreateRE.MatchString(createIdentity) ||
		reviewed.AnchorSHA256 != inputs.anchor.Digest() ||
		reviewed.ManifestSHA256 != inputs.manifest.Digest() ||
		reviewed.ImageReceiptSHA256 != manifest.ReleaseReceiptSHA256 ||
		reviewed.Shape != profile.Shape || reviewed.CompartmentID != profile.CompartmentOCID ||
		reviewed.AvailabilityDomain != profile.AvailabilityDomain ||
		reviewed.FaultDomain != profile.FaultDomain || reviewed.SubnetID != profile.SubnetOCID ||
		!slices.Equal(reviewed.NetworkSecurityGroupIDs, profile.NetworkSecurityGroupOCIDs) ||
		reviewed.ImageID != manifest.ImageOCID || reviewed.AssignPublicIP ||
		reviewed.OCPUs != 1 || reviewed.MemoryGB != 6 || reviewed.BootGB != 50 ||
		reviewed.BootVPUsPerGB != 10 || !seedDigestRE.MatchString(reviewed.AdmissionSHA256) ||
		!seedDigestRE.MatchString(reviewed.InventorySHA256) || reviewed.AdmissionAdmittedAt.IsZero() ||
		reviewed.AdmissionExpiresAt.IsZero() ||
		!reviewed.AdmissionAdmittedAt.Before(reviewed.AdmissionExpiresAt) ||
		reviewed.AdmissionExpiresAt.Sub(reviewed.AdmissionAdmittedAt) > 20*time.Minute ||
		requireCurrent && (reviewed.AdmissionAdmittedAt.After(now) || !now.Before(reviewed.AdmissionExpiresAt)) ||
		!amountOK || amount.Sign() < 0 ||
		amount.Cmp(big.NewRat(combinedMonthlyCostCeilingUSD, 1)) > 0 {
		return reviewedSeedPlan{}, fmt.Errorf("%w: reviewed manual seed plan differs from signed authority or current budget", ErrSeedCLI)
	}
	return reviewed, nil
}
