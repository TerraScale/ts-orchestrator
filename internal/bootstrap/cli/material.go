package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

// runGenerateControllerMaterial creates the one durable local source for the
// three regional controller slots. Config and output contain public identities and
// digests only; private material stays in the owner-only directory.
func (c command) runGenerateControllerMaterial(args []string) error {
	return c.generateControllerMaterialAt(args, time.Now().UTC())
}

func (c command) generateControllerMaterialAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("generate-controller-material", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "reviewed controller material configuration JSON")
	configSHA := flags.String("config-sha256", "", "SHA-256 of the reviewed configuration")
	directory := flags.String("directory", "", "new owner-only material directory outside the checkout")
	outputPath := flags.String("out", "", "new public material inventory JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *configSHA == "" || *directory == "" || *outputPath == "" || flags.NArg() != 0 ||
		!filepath.IsAbs(*directory) || !filepath.IsAbs(*outputPath) || pathInside(*directory, *outputPath) {
		return errors.New("generate-controller-material requires --config, --config-sha256, --directory, and --out")
	}
	peerPath, ledgerPath := *outputPath+".peer.pem", *outputPath+".ledger.pem"
	for _, path := range []string{*outputPath, peerPath, ledgerPath} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return errors.New("public material output paths must not already exist")
		}
	}
	wire, err := c.readBoundedRegular(*configPath, 16<<10)
	if err != nil || !matchesSHA256(wire, *configSHA) {
		return errors.New("reviewed controller configuration digest does not match")
	}
	var config bootstrapmaterial.Config
	if err := json.Unmarshal(wire, &config, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("decode controller configuration: %w", err)
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	record, err := bootstrapmaterial.Generate(*directory, config, now)
	if err != nil {
		return err
	}
	if err := bootstrapmaterial.ValidateLive(*directory, record); err != nil {
		return err
	}
	public, err := json.Marshal(record)
	if err != nil {
		return err
	}
	peerPEM, err := materialPublicPEM(record.Public.PeerSignerPublicKey)
	if err != nil {
		return err
	}
	ledgerPEM, err := materialPublicPEM(record.Public.LedgerSignerPublicKey)
	if err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, public, 0o644); err != nil {
		return err
	}
	if err := c.writeNew(peerPath, peerPEM, 0o644); err != nil {
		return err
	}
	if err := c.writeNew(ledgerPath, ledgerPEM, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "controller material ready inventory=%s peer-public=%s ledger-public=%s expires=%s\n",
		*outputPath, peerPath, ledgerPath, record.ExpiresAt.Format(time.RFC3339))
	return nil
}

func materialPublicPEM(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, bootstrapmaterial.ErrMaterial
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(key))
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func matchesSHA256(wire []byte, expected string) bool {
	_, err := hex.DecodeString(expected)
	if err != nil || len(expected) != 64 {
		return false
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]) == expected
}

type manualFoundationReadback struct {
	SchemaVersion         int       `json:"schema_version"`
	PlanSHA256            string    `json:"plan_sha256"`
	InventorySHA256       string    `json:"inventory_sha256"`
	InspectedAt           time.Time `json:"inspected_at"`
	TenancyID             string    `json:"tenancy_id"`
	Cell                  string    `json:"cell"`
	OCIRegion             string    `json:"oci_region"`
	ControlCompartmentID  string    `json:"control_compartment_id"`
	NetworkCompartmentID  string    `json:"network_compartment_id"`
	WorkloadCompartmentID string    `json:"workload_compartment_id"`
	VaultID               string    `json:"vault_id"`
	KeyID                 string    `json:"key_id"`
}

type costAdmission struct {
	SchemaVersion         int       `json:"schema_version"`
	PlanSHA256            string    `json:"plan_sha256"`
	InventorySHA256       string    `json:"inventory_sha256"`
	AdmittedAt            time.Time `json:"admitted_at"`
	ExpiresAt             time.Time `json:"expires_at"`
	PreviewCompartmentIDs struct {
		Control  string `json:"control"`
		Network  string `json:"network"`
		Workload string `json:"workload"`
	} `json:"preview_compartment_ids"`
	Estimate struct {
		Currency string `json:"currency"`
		Total    string `json:"total"`
		Limit    string `json:"limit"`
		Headroom string `json:"headroom"`
	} `json:"estimate"`
}

type costInventory struct {
	SchemaVersion         int       `json:"schema_version"`
	PlanSHA256            string    `json:"plan_sha256"`
	TenancyID             string    `json:"tenancy_id"`
	CapturedAt            time.Time `json:"captured_at"`
	Regions               []string  `json:"regions"`
	PreviewCompartmentIDs struct {
		Control  string `json:"control"`
		Network  string `json:"network"`
		Workload string `json:"workload"`
	} `json:"preview_compartment_ids"`
}

var (
	sha256RE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rootTenancyRE = regexp.MustCompile(`^ocid1\.tenancy\.oc1\.\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
	compartmentRE = regexp.MustCompile(`^ocid1\.compartment\.oc1\.\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
)

type publicationGate struct {
	Readback manualFoundationReadback
	Target   bootstrapmaterial.VaultTarget
	Deadline time.Time
}

func validatePublicationGate(readbackWire, inventoryWire, admissionWire []byte, readbackSHA, inventorySHA,
	admissionSHA, planSHA, cell string, now time.Time) (publicationGate, error) {
	bad := errors.New("manual foundation readback or current cost admission does not authorize Vault publication")
	region, regionErr := bootstrapmaterial.MappedOCIRegion(cell)
	if regionErr != nil {
		return publicationGate{}, bad
	}
	if !matchesSHA256(readbackWire, readbackSHA) || !matchesSHA256(inventoryWire, inventorySHA) ||
		!matchesSHA256(admissionWire, admissionSHA) || !sha256RE.MatchString(planSHA) {
		return publicationGate{}, bad
	}
	var readback manualFoundationReadback
	var inventory costInventory
	var admission costAdmission
	if json.Unmarshal(readbackWire, &readback, json.RejectUnknownMembers(true)) != nil || json.Unmarshal(inventoryWire, &inventory) != nil ||
		json.Unmarshal(admissionWire, &admission) != nil {
		return publicationGate{}, bad
	}
	_, readbackOffset := readback.InspectedAt.Zone()
	if readback.SchemaVersion != 1 || readback.PlanSHA256 != planSHA ||
		readback.InventorySHA256 != inventorySHA || readback.InspectedAt.IsZero() ||
		readbackOffset != 0 || readback.InspectedAt.After(now) ||
		now.Sub(readback.InspectedAt) > 15*time.Minute ||
		!rootTenancyRE.MatchString(readback.TenancyID) ||
		readback.Cell != strings.ToUpper(cell) || readback.OCIRegion != region ||
		!compartmentRE.MatchString(readback.ControlCompartmentID) ||
		!compartmentRE.MatchString(readback.NetworkCompartmentID) ||
		!compartmentRE.MatchString(readback.WorkloadCompartmentID) ||
		readback.ControlCompartmentID == readback.NetworkCompartmentID ||
		readback.ControlCompartmentID == readback.WorkloadCompartmentID ||
		readback.NetworkCompartmentID == readback.WorkloadCompartmentID {
		return publicationGate{}, bad
	}
	if inventory.SchemaVersion != 2 || admission.SchemaVersion != 2 || inventory.PlanSHA256 != planSHA ||
		admission.PlanSHA256 != planSHA || admission.InventorySHA256 != inventorySHA ||
		inventory.TenancyID != readback.TenancyID || !slices.Contains(inventory.Regions, readback.OCIRegion) ||
		!compartmentRE.MatchString(inventory.PreviewCompartmentIDs.Control) ||
		!compartmentRE.MatchString(inventory.PreviewCompartmentIDs.Network) ||
		!compartmentRE.MatchString(inventory.PreviewCompartmentIDs.Workload) ||
		inventory.PreviewCompartmentIDs.Control != readback.ControlCompartmentID ||
		inventory.PreviewCompartmentIDs.Network != readback.NetworkCompartmentID ||
		inventory.PreviewCompartmentIDs.Workload != readback.WorkloadCompartmentID ||
		admission.PreviewCompartmentIDs != inventory.PreviewCompartmentIDs ||
		inventory.CapturedAt.IsZero() || inventory.CapturedAt.After(admission.AdmittedAt) ||
		inventory.CapturedAt.After(now) || now.Sub(inventory.CapturedAt) > 20*time.Minute ||
		admission.AdmittedAt.Sub(inventory.CapturedAt) > 20*time.Minute ||
		readback.InspectedAt.Before(admission.AdmittedAt) ||
		admission.AdmittedAt.After(now) || !now.Before(admission.ExpiresAt) ||
		admission.ExpiresAt.Sub(admission.AdmittedAt) > 20*time.Minute || admission.Estimate.Currency != "USD" {
		return publicationGate{}, bad
	}
	total, ok := new(big.Rat).SetString(admission.Estimate.Total)
	if !ok || total.Sign() < 0 {
		return publicationGate{}, bad
	}
	limit, ok := new(big.Rat).SetString(admission.Estimate.Limit)
	if !ok || limit.Sign() <= 0 || limit.Cmp(big.NewRat(combinedMonthlyCostCeilingUSD, 1)) > 0 || total.Cmp(limit) > 0 {
		return publicationGate{}, bad
	}
	headroom, ok := new(big.Rat).SetString(admission.Estimate.Headroom)
	if !ok || headroom.Sign() < 0 || new(big.Rat).Add(total, headroom).Cmp(limit) != 0 {
		return publicationGate{}, bad
	}
	target := bootstrapmaterial.VaultTarget{CompartmentOCID: readback.ControlCompartmentID,
		VaultOCID: readback.VaultID, KMSKeyOCID: readback.KeyID}
	if err := target.Validate(region); err != nil {
		return publicationGate{}, bad
	}
	deadline := admission.ExpiresAt
	if readbackDeadline := readback.InspectedAt.Add(15 * time.Minute); readbackDeadline.Before(deadline) {
		deadline = readbackDeadline
	}
	return publicationGate{Readback: readback, Target: target,
		Deadline: deadline}, nil
}

func (c command) runProvisionControllerMaterial(args []string) error {
	return c.provisionControllerMaterialAt(args, time.Now().UTC())
}

func (c command) provisionControllerMaterialAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("provision-controller-material", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "existing owner-only material directory")
	readbackPath := flags.String("manual-readback", "", "fresh authenticated manual foundation readback")
	readbackSHA := flags.String("manual-readback-sha256", "", "operator-pinned manual readback SHA-256")
	inventoryPath := flags.String("inventory", "", "current live OCI inventory")
	inventorySHA := flags.String("inventory-sha256", "", "operator-pinned inventory SHA-256")
	admissionPath := flags.String("cost-admission", "", "current cost admission")
	admissionSHA := flags.String("cost-admission-sha256", "", "operator-pinned cost admission SHA-256")
	planSHA := flags.String("cost-plan-sha256", "", "operator-pinned current plan SHA-256")
	configPath := flags.String("oci-config", "", "owner-only OCI API-key configuration")
	profile := flags.String("oci-profile", "DEFAULT", "OCI profile")
	outputPath := flags.String("out", "", "new public exact-version reference JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *readbackPath == "" || *readbackSHA == "" || *inventoryPath == "" ||
		*inventorySHA == "" || *admissionPath == "" || *admissionSHA == "" || *planSHA == "" ||
		*configPath == "" || *outputPath == "" || flags.NArg() != 0 || !filepath.IsAbs(*directory) ||
		!filepath.IsAbs(*outputPath) || pathInside(*directory, *outputPath) {
		return errors.New("provision-controller-material requires material, fresh manual foundation/cost evidence, OCI profile, and a public output path")
	}
	if _, err := os.Lstat(*outputPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("public reference output must not already exist")
	}
	record, err := bootstrapmaterial.Load(*directory)
	if err != nil || !now.Before(record.ExpiresAt) {
		return bootstrapmaterial.ErrMaterial
	}
	readbackWire, err := c.readBoundedRegular(*readbackPath, 16<<10)
	if err != nil {
		return err
	}
	inventoryWire, err := c.readBoundedRegular(*inventoryPath, 8<<20)
	if err != nil {
		return err
	}
	admissionWire, err := c.readBoundedRegular(*admissionPath, 64<<10)
	if err != nil {
		return err
	}
	gate, err := validatePublicationGate(readbackWire, inventoryWire, admissionWire, *readbackSHA,
		*inventorySHA, *admissionSHA, *planSHA, record.Config.Cell, now)
	if err != nil {
		return err
	}
	if record.Config.Region != gate.Readback.OCIRegion {
		return bootstrapmaterial.ErrMaterial
	}
	if err := bootstrapmaterial.ValidateLive(*directory, record); err != nil {
		return err
	}
	deadline := gate.Deadline
	if record.ExpiresAt.Before(deadline) {
		deadline = record.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(c.ctx, deadline)
	defer cancel()
	management, bundles, err := newMaterialOCIClients(ctx, *configPath, *profile, gate.Readback)
	if err != nil {
		return err
	}
	publication, err := bootstrapmaterial.Provision(ctx, *directory, gate.Target, management, bundles, now)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(publication)
	if err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "controller Vault references ready count=%d output=%s\n", len(publication.References), *outputPath)
	return nil
}

func pathInside(directory, path string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && relative != "." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
