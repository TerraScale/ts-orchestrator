package main

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
// three GRU controller slots. Config and output contain public identities and
// digests only; private material stays in the owner-only directory.
func runGenerateControllerMaterial(args []string) error {
	return generateControllerMaterialAt(args, time.Now().UTC())
}

func generateControllerMaterialAt(args []string, now time.Time) error {
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
	wire, err := readBoundedRegular(*configPath, 16<<10)
	if err != nil || !matchesSHA256(wire, *configSHA) {
		return errors.New("reviewed controller configuration digest does not match")
	}
	var config bootstrapmaterial.Config
	if err := json.Unmarshal(wire, &config, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("decode controller configuration: %w", err)
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
	if err := writeNew(*outputPath, public, 0o644); err != nil {
		return err
	}
	if err := writeNew(peerPath, peerPEM, 0o644); err != nil {
		return err
	}
	if err := writeNew(ledgerPath, ledgerPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("controller material ready inventory=%s peer-public=%s ledger-public=%s expires=%s\n",
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

type foundationReceipt struct {
	SchemaVersion         int    `json:"schema_version"`
	Status                string `json:"status"`
	SourceRevision        string `json:"source_revision"`
	StateRevision         string `json:"state_revision"`
	EncryptedStateSHA256  string `json:"encrypted_state_sha256"`
	EffectsSHA256         string `json:"effects_sha256"`
	CostPlanSHA256        string `json:"cost_plan_sha256"`
	TenancyID             string `json:"tenancy_id"`
	OCIRegion             string `json:"oci_region"`
	ReadbackAt            string `json:"readback_at"`
	ControlCompartmentID  string `json:"control_compartment_id"`
	WorkloadCompartmentID string `json:"workload_compartment_id"`
	VaultID               string `json:"vault_id"`
	KeyID                 string `json:"key_id"`
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
	gitRevisionRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256RE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rootTenancyRE = regexp.MustCompile(`^ocid1\.tenancy\.oc1\.\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
	compartmentRE = regexp.MustCompile(`^ocid1\.compartment\.oc1\.\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
)

func validatePublicationGate(receiptWire, inventoryWire, admissionWire []byte, receiptSHA, inventorySHA,
	admissionSHA, planSHA string, now time.Time) (bootstrapmaterial.VaultTarget, error) {
	bad := errors.New("foundation readback or current cost admission does not authorize Vault publication")
	if !matchesSHA256(receiptWire, receiptSHA) || !matchesSHA256(inventoryWire, inventorySHA) ||
		!matchesSHA256(admissionWire, admissionSHA) || !sha256RE.MatchString(planSHA) {
		return bootstrapmaterial.VaultTarget{}, bad
	}
	var foundation foundationReceipt
	var inventory costInventory
	var admission costAdmission
	if json.Unmarshal(receiptWire, &foundation, json.RejectUnknownMembers(true)) != nil || json.Unmarshal(inventoryWire, &inventory) != nil ||
		json.Unmarshal(admissionWire, &admission) != nil {
		return bootstrapmaterial.VaultTarget{}, bad
	}
	readbackAt, err := time.Parse(time.RFC3339, foundation.ReadbackAt)
	_, readbackOffset := readbackAt.Zone()
	if err != nil || readbackOffset != 0 ||
		!strings.HasSuffix(foundation.ReadbackAt, "Z") && !strings.HasSuffix(foundation.ReadbackAt, "+00:00") ||
		foundation.SchemaVersion != 1 ||
		foundation.Status != "foundation-ready" || !gitRevisionRE.MatchString(foundation.SourceRevision) ||
		!gitRevisionRE.MatchString(foundation.StateRevision) || !sha256RE.MatchString(foundation.EncryptedStateSHA256) ||
		!sha256RE.MatchString(foundation.EffectsSHA256) || !sha256RE.MatchString(foundation.CostPlanSHA256) ||
		foundation.CostPlanSHA256 != planSHA ||
		!rootTenancyRE.MatchString(foundation.TenancyID) || foundation.OCIRegion != "sa-saopaulo-1" ||
		readbackAt.After(now) || now.Sub(readbackAt) > 15*time.Minute {
		return bootstrapmaterial.VaultTarget{}, bad
	}
	if inventory.SchemaVersion != 2 || admission.SchemaVersion != 2 || inventory.PlanSHA256 != planSHA ||
		admission.PlanSHA256 != planSHA || admission.InventorySHA256 != inventorySHA ||
		inventory.TenancyID != foundation.TenancyID || !slices.Contains(inventory.Regions, foundation.OCIRegion) ||
		!compartmentRE.MatchString(inventory.PreviewCompartmentIDs.Control) ||
		!compartmentRE.MatchString(inventory.PreviewCompartmentIDs.Network) ||
		!compartmentRE.MatchString(inventory.PreviewCompartmentIDs.Workload) ||
		inventory.PreviewCompartmentIDs.Control != foundation.ControlCompartmentID ||
		inventory.PreviewCompartmentIDs.Workload != foundation.WorkloadCompartmentID ||
		admission.PreviewCompartmentIDs != inventory.PreviewCompartmentIDs ||
		inventory.CapturedAt.IsZero() || inventory.CapturedAt.After(admission.AdmittedAt) ||
		now.Sub(inventory.CapturedAt) > 20*time.Minute || admission.AdmittedAt.Sub(inventory.CapturedAt) > 20*time.Minute ||
		admission.AdmittedAt.After(now) || !now.Before(admission.ExpiresAt) ||
		admission.ExpiresAt.Sub(admission.AdmittedAt) > 20*time.Minute || admission.Estimate.Currency != "USD" {
		return bootstrapmaterial.VaultTarget{}, bad
	}
	total, ok := new(big.Rat).SetString(admission.Estimate.Total)
	if !ok || total.Sign() < 0 {
		return bootstrapmaterial.VaultTarget{}, bad
	}
	limit, ok := new(big.Rat).SetString(admission.Estimate.Limit)
	if !ok || limit.Sign() <= 0 || limit.Cmp(big.NewRat(100, 1)) > 0 || total.Cmp(limit) > 0 {
		return bootstrapmaterial.VaultTarget{}, bad
	}
	headroom, ok := new(big.Rat).SetString(admission.Estimate.Headroom)
	if !ok || headroom.Sign() < 0 || new(big.Rat).Add(total, headroom).Cmp(limit) != 0 {
		return bootstrapmaterial.VaultTarget{}, bad
	}
	target := bootstrapmaterial.VaultTarget{CompartmentOCID: foundation.ControlCompartmentID,
		VaultOCID: foundation.VaultID, KMSKeyOCID: foundation.KeyID}
	if err := target.Validate(); err != nil {
		return bootstrapmaterial.VaultTarget{}, bad
	}
	return target, nil
}

func runProvisionControllerMaterial(args []string) error {
	return provisionControllerMaterialAt(args, time.Now().UTC())
}

func provisionControllerMaterialAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("provision-controller-material", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := flags.String("directory", "", "existing owner-only material directory")
	receiptPath := flags.String("foundation-receipt", "", "current applied foundation readback receipt")
	receiptSHA := flags.String("foundation-sha256", "", "operator-pinned receipt SHA-256")
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
	if *directory == "" || *receiptPath == "" || *receiptSHA == "" || *inventoryPath == "" ||
		*inventorySHA == "" || *admissionPath == "" || *admissionSHA == "" || *planSHA == "" ||
		*configPath == "" || *outputPath == "" || flags.NArg() != 0 || !filepath.IsAbs(*directory) ||
		!filepath.IsAbs(*outputPath) || pathInside(*directory, *outputPath) {
		return errors.New("provision-controller-material requires material, current reviewed foundation/cost evidence, OCI profile, and a public output path")
	}
	if _, err := os.Lstat(*outputPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("public reference output must not already exist")
	}
	receiptWire, err := readBoundedRegular(*receiptPath, 16<<10)
	if err != nil {
		return err
	}
	inventoryWire, err := readBoundedRegular(*inventoryPath, 8<<20)
	if err != nil {
		return err
	}
	admissionWire, err := readBoundedRegular(*admissionPath, 64<<10)
	if err != nil {
		return err
	}
	target, err := validatePublicationGate(receiptWire, inventoryWire, admissionWire, *receiptSHA,
		*inventorySHA, *admissionSHA, *planSHA, now)
	if err != nil {
		return err
	}
	record, err := bootstrapmaterial.Load(*directory)
	if err != nil || record.Config.Region != "sa-saopaulo-1" || !now.Before(record.ExpiresAt) {
		return bootstrapmaterial.ErrMaterial
	}
	if err := bootstrapmaterial.ValidateLive(*directory, record); err != nil {
		return err
	}
	management, bundles, err := bootstrapmaterial.NewOCIClients(*configPath, *profile)
	if err != nil {
		return err
	}
	var cost costAdmission
	var foundation foundationReceipt
	if err := json.Unmarshal(admissionWire, &cost); err != nil {
		return err
	}
	if err := json.Unmarshal(receiptWire, &foundation); err != nil {
		return err
	}
	readbackAt, err := time.Parse(time.RFC3339, foundation.ReadbackAt)
	if err != nil {
		return err
	}
	deadline := cost.ExpiresAt
	if readbackDeadline := readbackAt.Add(15 * time.Minute); readbackDeadline.Before(deadline) {
		deadline = readbackDeadline
	}
	if record.ExpiresAt.Before(deadline) {
		deadline = record.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	publication, err := bootstrapmaterial.Provision(ctx, *directory, target, management, bundles, now)
	if err != nil {
		return err
	}
	wire, err := json.Marshal(publication)
	if err != nil {
		return err
	}
	if err := writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	fmt.Printf("controller Vault references ready count=%d output=%s\n", len(publication.References), *outputPath)
	return nil
}

func pathInside(directory, path string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." && relative != "." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
