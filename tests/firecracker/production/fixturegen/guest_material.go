package fixturegen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

// GuestObservation is the exact VNIC and network identity accepted during
// each synthetic first install. Network compartment and VCN facts are
// host-side inputs for the authenticated Compute replay; they are not guest
// configuration. The packet must serve matching responses before a
// production-mode VM run can be claimed.
type GuestObservation struct {
	PrimaryVNICOCID        string
	PrimaryPrivateIP       string
	NetworkCompartmentOCID string
	VCNOCID                string
}

// GuestMaterialInputs supplies private service material by each manifest's
// exact target filename. It must match the signed secret references; the
// packet builder never copies an offline root private key into a guest.
type GuestMaterialInputs struct {
	Binary               []byte
	Credentials          map[string]map[string][]byte
	Configs              map[string][]byte
	SimulatorCA          []byte
	SimulatorCertificate []byte
	SimulatorPrivateKey  []byte
	IMDS                 map[string]IMDSIdentity
	VNICs                map[string]GuestObservation
	ServiceUID           uint32
	ServiceGID           uint32
}

// IMDSIdentity is host-only instance-principal material served to one guest.
// It is signed into the packet but must never be installed as a guest file.
type IMDSIdentity struct {
	TenancyID    string
	Certificate  []byte
	PrivateKey   []byte
	Intermediate []byte
}

// BuildVerifiedGuestMaterial constructs each accepted marker from completed
// public ledger state and obtains the three service-owned floor/lock artifacts
// from bootstrapstart's verified source-backed staging APIs.
func BuildVerifiedGuestMaterial(ctx context.Context, recipe SignedHistoryRecipe,
	completed CompletedHistories, input GuestMaterialInputs,
) (map[string][]byte, error) {
	if !recipe.Anchor.IsVerified() || len(recipe.RootPrivateKey) != ed25519.PrivateKeySize ||
		len(input.Binary) == 0 ||
		len(input.Credentials) != 3 || len(input.Configs) != 3 || len(input.VNICs) != 3 || len(input.IMDS) != 3 ||
		input.ServiceUID == 0 || input.ServiceGID == 0 {
		return nil, errors.New("guest material lacks verified anchor, binary, or three slot inputs")
	}
	rootPublic, ok := recipe.RootPrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("offline root key is not Ed25519")
	}
	rootID, err := trust.KeyID(rootPublic)
	if err != nil || len(recipe.Roots) != 1 || !bytes.Equal(recipe.Roots[rootID], rootPublic) {
		return nil, errors.New("guest trust root differs from verified offline signer")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(rootPublic)
	if err != nil {
		return nil, err
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if err := validateFixtureCA(input.SimulatorCA, recipe.Now); err != nil {
		return nil, err
	}
	if err := validateSimulatorTLS(input.SimulatorCA, input.SimulatorCertificate,
		input.SimulatorPrivateKey, recipe.Now); err != nil {
		return nil, err
	}
	selectionSource, err := BuildFounderSelectionSource(ctx, recipe)
	if err != nil {
		return nil, err
	}
	anchor := recipe.Anchor.Anchor()
	identityWire, err := protocol.EncodeJSON(bootstrapstart.BakedIdentity{
		SchemaVersion: 1, DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, Cell: anchor.Cell,
	})
	if err != nil {
		return nil, err
	}
	material := map[string][]byte{
		"input/orchestrator":    bytes.Clone(input.Binary),
		"simulator/tls/oci.crt": bytes.Clone(input.SimulatorCertificate),
		"simulator/tls/oci.key": bytes.Clone(input.SimulatorPrivateKey),
	}
	directoryPlan := make([]GuestDirectory, 0, len(anchor.ControllerSlots)*2)
	for _, slot := range anchor.ControllerSlots {
		state := completed.Seed
		if slot != "seed-a" {
			var exists bool
			state, exists = completed.Peers[slot]
			if !exists {
				return nil, fmt.Errorf("managed controller %q has no completed history", slot)
			}
		}
		if state.Manifest == nil || state.ManifestRecord == nil || state.Result == nil ||
			state.ResultRecord == nil || state.Head.ResultDigest != state.ResultRecord.SHA256 ||
			state.Result.InstanceOCID != recipe.Observed[slot].InstanceOCID {
			return nil, fmt.Errorf("controller %q lacks exact completed ledger state", slot)
		}
		receipt := state.PeerReceiptRecord
		if slot == "seed-a" {
			receipt = state.SeedReceiptRecord
		}
		if receipt == nil {
			return nil, fmt.Errorf("controller %q lacks signed install receipt", slot)
		}
		vnic, ok := input.VNICs[slot]
		if !ok || !strings.HasPrefix(vnic.PrimaryVNICOCID, "ocid1.vnic.oc1.sa-saopaulo-1.") ||
			vnic.PrimaryPrivateIP == "" {
			return nil, fmt.Errorf("controller %q lacks GRU primary VNIC identity", slot)
		}
		networkFiles, err := productionNetworkFiles(vnic.PrimaryPrivateIP)
		if err != nil {
			return nil, fmt.Errorf("controller %q network: %w", slot, err)
		}
		imds, ok := input.IMDS[slot]
		if !ok || !strings.HasPrefix(imds.TenancyID, "ocid1.tenancy.") ||
			strings.ContainsAny(imds.TenancyID, " \r\n") ||
			len(imds.Certificate) == 0 || len(imds.PrivateKey) == 0 || len(imds.Intermediate) == 0 {
			return nil, fmt.Errorf("controller %q lacks host-only IMDS identity", slot)
		}
		imdsRoot := "simulator/imds/" + slot + "/"
		material[imdsRoot+"tenancy.txt"] = []byte(imds.TenancyID)
		material[imdsRoot+"leaf.pem"] = bytes.Clone(imds.Certificate)
		material[imdsRoot+"leaf.key"] = bytes.Clone(imds.PrivateKey)
		material[imdsRoot+"intermediate.pem"] = bytes.Clone(imds.Intermediate)
		credentials, ok := input.Credentials[slot]
		if !ok {
			return nil, fmt.Errorf("controller %q has no prepared service material", slot)
		}
		if err := validateControllerConfig(input.Configs[slot], slot, state.Result.InstanceOCID,
			vnic.PrimaryPrivateIP, input.VNICs, credentials); err != nil {
			return nil, fmt.Errorf("controller %q configuration: %w", slot, err)
		}
		materialDigests, err := expectedGuestMaterials(*state.Manifest, slot, credentials)
		if err != nil {
			return nil, err
		}
		marker := bootstrapstart.AcceptedInstall{SchemaVersion: 1,
			AnchorSHA256: recipe.Anchor.Digest(), ManifestSHA256: state.ManifestRecord.SHA256,
			ReceiptSHA256: receipt.SHA256, ImageReceiptSHA256: state.Manifest.ReleaseReceiptSHA256,
			DeploymentID: anchor.DeploymentID, Cell: string(anchor.Cell), Slot: slot,
			SeedSlot: "seed-a", ImageOCID: state.Manifest.ImageOCID,
			InstanceOCID: state.Result.InstanceOCID, PrimaryVNICOCID: vnic.PrimaryVNICOCID,
			PrimaryPrivateIP: vnic.PrimaryPrivateIP, HeadAttempt: state.Head.Attempt,
			HeadGeneration: state.Head.Generation, ResultSHA256: state.ResultRecord.SHA256,
			BinarySHA256: historyDigest(input.Binary), MaterialSHA256: materialDigests,
			AcceptedAt: recipe.Now}
		markerWire, err := protocol.EncodeJSON(marker)
		if err != nil {
			return nil, err
		}
		baked := bootstrapstart.BakedInputs{Identity: bootstrapstart.BakedIdentity{
			SchemaVersion: 1, DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, Cell: anchor.Cell,
		}, Roots: recipe.Roots, AnchorWire: recipe.Anchor.Wire()}
		var artifacts []bootstrapstart.FounderFloorArtifact
		if slot == "seed-a" {
			artifacts, err = bootstrapstart.BuildVerifiedSeedFloorArtifacts(ctx, baked, marker, state,
				selectionSource, input.ServiceUID, input.ServiceGID, recipe.Now)
		} else {
			artifacts, err = bootstrapstart.BuildVerifiedPeerFloorArtifacts(ctx, baked, marker, state,
				selectionSource, input.ServiceUID, input.ServiceGID, recipe.Now)
		}
		if err != nil {
			return nil, fmt.Errorf("verify and stage %s founder floor: %w", slot, err)
		}
		floorFiles, err := checkedFloorArtifacts(artifacts, input.ServiceUID, input.ServiceGID)
		if err != nil {
			return nil, err
		}
		for _, artifact := range artifacts {
			if artifact.Directory {
				directoryPlan = append(directoryPlan, GuestDirectory{ControllerSlot: slot,
					GuestPath: artifact.Path, Mode: uint32(artifact.Mode), OwnerRole: "service:" + slot,
					UID: artifact.UID, GID: artifact.GID})
			}
		}
		directoryPlan = append(directoryPlan, GuestDirectory{ControllerSlot: slot,
			GuestPath: serviceSecretsGuestDir, Mode: 0o700, OwnerRole: "service:" + slot,
			UID: input.ServiceUID, GID: input.ServiceGID})
		root := "controllers/" + slot + "/guest-root/"
		material[root+"etc/terrascale-orchestrator/bootstrap/identity.json"] = bytes.Clone(identityWire)
		material[root+"etc/terrascale-orchestrator/controller.json"] = bytes.Clone(input.Configs[slot])
		material[root+"usr/local/share/ca-certificates/ts-fixture-oci.crt"] = bytes.Clone(input.SimulatorCA)
		for guestPath, body := range networkFiles {
			material[root+strings.TrimPrefix(guestPath, "/")] = body
		}
		material[root+"etc/terrascale-orchestrator/bootstrap/anchor.json"] = recipe.Anchor.Wire()
		material[root+"etc/terrascale-orchestrator/bootstrap/trust-roots/001.pem"] = bytes.Clone(rootPEM)
		material[root+"var/lib/terrascale-orchestrator-bootstrap/accepted-install.json"] = markerWire
		for name, body := range credentials {
			material[root+"var/lib/terrascale-orchestrator-secrets/"+name] = bytes.Clone(body)
		}
		for name, body := range floorFiles {
			material[root+name] = body
		}
	}
	directoryWire, err := protocol.EncodeJSON(directoryPlan)
	if err != nil {
		return nil, err
	}
	if _, err := parseGuestDirectories(directoryWire, materialControllers(anchor.ControllerSlots, recipe.Observed),
		func(path string) bool { _, ok := material[path]; return ok }); err != nil {
		return nil, err
	}
	material[guestDirectoryPlanPath] = directoryWire
	return material, nil
}

func materialControllers(slots []string, observed map[string]ObservedController) []Controller {
	controllers := make([]Controller, 0, len(slots))
	for _, slot := range slots {
		controllers = append(controllers, Controller{Slot: slot,
			InstanceOCID: observed[slot].InstanceOCID, GuestRoot: "controllers/" + slot + "/guest-root"})
	}
	return controllers
}

func expectedGuestMaterials(manifest bootstrap.Manifest, slot string, bodies map[string][]byte) (map[string]string, error) {
	want := make(map[string]string)
	for _, reference := range manifest.Secrets {
		if reference.Purpose != bootstrap.SecretRegionalShared &&
			!(reference.Purpose == bootstrap.SecretController && reference.Slot == slot) &&
			!((reference.Purpose == bootstrap.SecretSeedFounder || reference.Purpose == bootstrap.SecretSeedLedgerSigner) &&
				slot == manifest.SeedSlot) {
			continue
		}
		want[reference.TargetFile] = reference.SHA256
	}
	if len(want) == 0 || len(want) != len(bodies) {
		return nil, fmt.Errorf("controller %q credential set differs from signed manifest", slot)
	}
	for name, digest := range want {
		if !canonicalPath(name) || strings.Contains(name, "/") || historyDigest(bodies[name]) != digest {
			return nil, fmt.Errorf("controller %q credential %q differs from signed digest", slot, name)
		}
	}
	return want, nil
}

func checkedFloorArtifacts(artifacts []bootstrapstart.FounderFloorArtifact, uid, gid uint32) (map[string][]byte, error) {
	directory := bootstrapstart.FounderSelectionFloorDirectory
	if len(artifacts) != 3 {
		return nil, errors.New("verified founder floor did not return directory, lock, and floor")
	}
	files := make(map[string][]byte, 2)
	seen := make([]string, 0, 3)
	for _, artifact := range artifacts {
		if artifact.UID != uid || artifact.GID != gid {
			return nil, errors.New("verified founder floor owner differs from service account")
		}
		switch artifact.Path {
		case directory:
			if !artifact.Directory || artifact.Mode != 0o700 || len(artifact.Bytes) != 0 {
				return nil, errors.New("verified founder floor directory is invalid")
			}
		case filepath.Join(directory, ".founder-selection-floor.lock"):
			if artifact.Directory || artifact.Mode != 0o600 || len(artifact.Bytes) != 0 {
				return nil, errors.New("verified founder lock is invalid")
			}
			files[strings.TrimPrefix(artifact.Path, "/")] = []byte{}
		case filepath.Join(directory, "founder-selection-floor.json"):
			if artifact.Directory || artifact.Mode != 0o600 || len(artifact.Bytes) == 0 {
				return nil, errors.New("verified founder floor is invalid")
			}
			files[strings.TrimPrefix(artifact.Path, "/")] = bytes.Clone(artifact.Bytes)
		default:
			return nil, errors.New("verified founder floor returned an unexpected path")
		}
		seen = append(seen, artifact.Path)
	}
	slices.Sort(seen)
	if seen[0] == seen[1] || seen[1] == seen[2] || len(files) != 2 {
		return nil, errors.New("verified founder floor artifacts are duplicated")
	}
	return files, nil
}
