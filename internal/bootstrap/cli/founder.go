package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// renderFounderContinuityAt derives the canonical continuity candidate for one
// installed controller from its accepted marker, the genesis anchor and the
// generated material the marker pins. The credential cutoff uses the same
// computation the controller performs on its installed files.
func (c command) renderFounderContinuityAt(args []string) error {
	flags := flag.NewFlagSet("render-founder-continuity", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	markerPath := flags.String("marker", "", "canonical accepted-install marker JSON")
	anchorPath := flags.String("anchor", "", "historical root-signed genesis anchor")
	materialDirectory := flags.String("material-directory", "", "generated controller material the marker pins")
	generation := flags.Uint64("selector-generation", 0, "read-only selector generation the proof joins")
	outputPath := flags.String("out", "", "new canonical continuity candidate JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *markerPath == "" || *anchorPath == "" || *materialDirectory == "" || *generation < 2 ||
		*outputPath == "" || flags.NArg() != 0 {
		return errors.New("render-founder-continuity requires --marker, --anchor, --material-directory, --selector-generation >= 2, and --out")
	}
	markerWire, err := c.readBoundedRegular(*markerPath, 16<<10)
	if err != nil {
		return err
	}
	var marker bootstrapstart.AcceptedInstall
	if err := protocol.DecodeStrict(markerWire, &marker, 16<<10); err != nil {
		return err
	}
	if canonical, err := protocol.EncodeJSON(marker); err != nil || !bytes.Equal(markerWire, canonical) {
		return errors.New("accepted marker must be canonical JSON")
	}
	anchorWire, err := c.readBoundedRegular(*anchorPath, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return err
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return err
	}
	var anchor bootstrap.BootstrapAnchor
	if err := protocol.DecodeStrict(anchorEnvelope.Payload, &anchor, bootstrap.MaxBootstrapAnchorBytes); err != nil {
		return err
	}
	anchorDigest := sha256.Sum256(anchorWire)
	if hex.EncodeToString(anchorDigest[:]) != marker.AnchorSHA256 || anchor.DeploymentID != marker.DeploymentID ||
		string(anchor.Cell) != marker.Cell {
		return errors.New("accepted marker belongs to another genesis anchor")
	}
	read := func(name string) ([]byte, error) {
		want := marker.MaterialSHA256[name]
		data, err := os.ReadFile(filepath.Join(*materialDirectory, name))
		if err != nil {
			return nil, err
		}
		got := sha256.Sum256(data)
		if want == "" || hex.EncodeToString(got[:]) != want {
			return nil, fmt.Errorf("material file %s differs from the accepted marker", name)
		}
		return data, nil
	}
	validUntil, err := bootstrapstart.CredentialValidUntil(read, bootstrapstart.SlotCredentialFiles(marker.Slot))
	if err != nil {
		return err
	}
	credentialDigest, err := bootstrap.InstallContinuityCredentialDigest(marker.MaterialSHA256)
	if err != nil {
		return err
	}
	markerDigest := sha256.Sum256(markerWire)
	candidate := bootstrap.InstallContinuity{SchemaVersion: 1, DeploymentID: marker.DeploymentID,
		Environment: anchor.Environment, ClusterID: anchor.ClusterID, Cell: anchor.Cell, OCIRegion: anchor.OCIRegion,
		Slot: marker.Slot, GenesisAnchorSHA256: marker.AnchorSHA256,
		AcceptedMarkerSHA256: hex.EncodeToString(markerDigest[:]), ManifestSHA256: marker.ManifestSHA256,
		ResultSHA256: marker.ResultSHA256, ReceiptSHA256: marker.ReceiptSHA256,
		ImageReceiptSHA256: marker.ImageReceiptSHA256, ImageOCID: marker.ImageOCID,
		InstanceOCID: marker.InstanceOCID, PrimaryVNICOCID: marker.PrimaryVNICOCID,
		PrimaryPrivateIP: marker.PrimaryPrivateIP, LedgerAttempt: marker.HeadAttempt,
		LedgerGeneration: marker.HeadGeneration, AcceptedAt: marker.AcceptedAt, BinarySHA256: marker.BinarySHA256,
		MaterialSHA256: marker.MaterialSHA256, CredentialSHA256: credentialDigest,
		CredentialValidUntil: validUntil, SelectorGeneration: *generation}
	encoded, err := protocol.EncodeJSON(candidate)
	if err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "rendered founder continuity slot=%s generation=%d credential-valid-until=%s\n",
		candidate.Slot, candidate.SelectorGeneration, validUntil.Format(time.RFC3339))
	return nil
}

func (c command) signFounderContinuityAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-founder-continuity", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "reviewed read-only continuity payload JSON")
	markerPath := flags.String("marker", "", "canonical accepted-install marker JSON")
	anchorPath := flags.String("anchor", "", "historical root-signed genesis anchor")
	publicPath := flags.String("root-key", "", "offline root public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only offline root private key PEM")
	outputPath := flags.String("out", "", "new signed continuity envelope")
	validFor := flags.Duration("valid-for", 24*time.Hour, "continuity validity bounded by credentials")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidatePath == "" || *markerPath == "" || *anchorPath == "" || *publicPath == "" ||
		*privatePath == "" || *outputPath == "" || flags.NArg() != 0 {
		return errors.New("sign-founder-continuity requires --candidate, --marker, --anchor, --root-key, --signing-key, and --out")
	}
	now = now.Round(0).UTC()
	policy := bootstrap.InstallContinuityTrustPolicy()
	if now.IsZero() || *validFor <= 0 || *validFor > policy.MaxLifetime {
		return errors.New("continuity signing time or validity is invalid")
	}
	candidateWire, err := c.readBoundedRegular(*candidatePath, bootstrap.MaxInstallContinuityBytes)
	if err != nil {
		return err
	}
	var candidate bootstrap.InstallContinuity
	if err := protocol.DecodeStrict(candidateWire, &candidate, bootstrap.MaxInstallContinuityBytes); err != nil {
		return err
	}
	canonical, err := protocol.EncodeJSON(candidate)
	if err != nil || !bytes.Equal(candidateWire, canonical) {
		return errors.New("continuity candidate must be canonical JSON")
	}
	markerWire, err := c.readBoundedRegular(*markerPath, 16<<10)
	if err != nil {
		return err
	}
	var marker bootstrapstart.AcceptedInstall
	if err := protocol.DecodeStrict(markerWire, &marker, 16<<10); err != nil {
		return err
	}
	canonical, err = protocol.EncodeJSON(marker)
	if err != nil || !bytes.Equal(markerWire, canonical) {
		return errors.New("accepted marker must be canonical JSON")
	}
	markerDigest := sha256.Sum256(markerWire)
	credentialDigest, err := bootstrap.InstallContinuityCredentialDigest(marker.MaterialSHA256)
	if err != nil {
		return err
	}
	if candidate.AcceptedMarkerSHA256 != hex.EncodeToString(markerDigest[:]) ||
		candidate.DeploymentID != marker.DeploymentID || string(candidate.Cell) != marker.Cell ||
		candidate.Slot != marker.Slot || candidate.GenesisAnchorSHA256 != marker.AnchorSHA256 ||
		candidate.ManifestSHA256 != marker.ManifestSHA256 || candidate.ResultSHA256 != marker.ResultSHA256 ||
		candidate.ReceiptSHA256 != marker.ReceiptSHA256 || candidate.ImageReceiptSHA256 != marker.ImageReceiptSHA256 ||
		candidate.ImageOCID != marker.ImageOCID || candidate.InstanceOCID != marker.InstanceOCID ||
		candidate.PrimaryVNICOCID != marker.PrimaryVNICOCID || candidate.PrimaryPrivateIP != marker.PrimaryPrivateIP ||
		candidate.LedgerAttempt != marker.HeadAttempt || candidate.LedgerGeneration != marker.HeadGeneration ||
		!candidate.AcceptedAt.Equal(marker.AcceptedAt) || candidate.BinarySHA256 != marker.BinarySHA256 ||
		!maps.Equal(candidate.MaterialSHA256, marker.MaterialSHA256) || candidate.CredentialSHA256 != credentialDigest {
		return errors.New("continuity candidate differs from accepted marker or credential inventory")
	}
	public, err := readRootPublicKey(*publicPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		return err
	}
	private, err := readRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return errors.New("root signing key does not match public key")
	}
	anchorWire, err := c.readBoundedRegular(*anchorPath, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return err
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return err
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(anchorEnvelope, roots,
		bootstrap.BootstrapAnchorExpectation{DeploymentID: marker.DeploymentID,
			Environment: candidate.Environment, Cell: candidate.Cell},
		marker.AcceptedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil || anchor.Digest() != marker.AnchorSHA256 ||
		anchor.Anchor().ClusterID != candidate.ClusterID || anchor.Anchor().OCIRegion != candidate.OCIRegion {
		return errors.New("continuity candidate differs from historical genesis anchor")
	}
	expiresAt := minTime(now.Add(*validFor), candidate.CredentialValidUntil)
	signed, err := bootstrap.SignInstallContinuity(candidate, now, expiresAt, private)
	if err != nil {
		return err
	}
	encoded, err := trust.EncodeEnvelope(signed)
	if err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, encoded, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed founder continuity slot=%s generation=%d digest=%x expires=%s\n",
		candidate.Slot, candidate.SelectorGeneration, sha256.Sum256(encoded), expiresAt.Format(time.RFC3339))
	return nil
}

func (c command) signFounderSelectionAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-founder-selection", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "reviewed read-only selector payload JSON")
	identityPath := flags.String("identity", "", "canonical baked deployment identity JSON")
	publicPath := flags.String("root-key", "", "offline root public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only offline root private key PEM")
	outputPath := flags.String("out", "", "new signed selector envelope")
	validFor := flags.Duration("valid-for", 24*time.Hour, "selector validity")
	var proofPaths stringListFlag
	flags.Var(&proofPaths, "proof", "signed immutable continuity envelope; repeat for each slot")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidatePath == "" || *identityPath == "" || *publicPath == "" || *privatePath == "" ||
		*outputPath == "" || len(proofPaths) != 3 || flags.NArg() != 0 {
		return errors.New("sign-founder-selection requires --candidate, --identity, --root-key, --signing-key, --out, and three --proof files")
	}
	identity, err := readFounderIdentity(*identityPath)
	if err != nil {
		return err
	}
	payload, err := c.readBoundedRegular(*candidatePath, 4096)
	if err != nil {
		return err
	}
	selection, err := bootstrapstart.ValidateFounderContinuitySelectionCandidate(payload, identity)
	if err != nil {
		return err
	}
	public, err := readRootPublicKey(*publicPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		return err
	}
	private, err := readRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return errors.New("root signing key does not match public key")
	}
	now = now.Round(0).UTC()
	policy := bootstrap.BootstrapAnchorTrustPolicy()
	if now.IsZero() || *validFor <= 0 || *validFor > policy.MaxLifetime {
		return errors.New("selector validity is invalid")
	}
	proofs, err := readFounderProofFiles(proofPaths)
	if err != nil {
		return err
	}
	expiresAt := now.Add(*validFor)
	for _, pin := range selection.Continuities {
		wire := proofs[pin.Slot]
		if len(wire) == 0 {
			return errors.New("selector is missing a signed proof for one slot")
		}
		proof, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return err
		}
		expiresAt = minTime(expiresAt, proof.ExpiresAt)
	}
	if !expiresAt.After(now) {
		return errors.New("signed continuity proof leaves no selector validity")
	}
	envelope, err := trust.Sign(payload, trust.Scope{Domain: bootstrapstart.FounderSelectionDomain,
		DeploymentID: identity.DeploymentID, Cell: string(identity.Cell), Environment: identity.Environment,
		Role: "deployment-anchor", Slot: "region"}, now, expiresAt, private)
	if err != nil {
		return err
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(wire)
	if err := verifyFounderProofFiles(proofPaths, selection, roots, hex.EncodeToString(hash[:]), now); err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "signed read-only founder selection generation=%d digest=%x expires=%s\n",
		selection.Generation, hash, envelope.ExpiresAt.Format(time.RFC3339))
	return nil
}

func (c command) publishFounderSelectionAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("publish-founder-selection", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	selectionPath := flags.String("selection", "", "root-signed read-only selector envelope")
	identityPath := flags.String("identity", "", "canonical baked deployment identity JSON")
	anchorPath := flags.String("anchor", "", "historical root-signed genesis anchor")
	publicPath := flags.String("root-key", "", "offline root public key PEM")
	configPath := flags.String("oci-config", "", "OCI API-key config file")
	profile := flags.String("oci-profile", "DEFAULT", "OCI config profile")
	var proofPaths stringListFlag
	flags.Var(&proofPaths, "proof", "signed immutable continuity envelope; repeat for each slot")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *selectionPath == "" || *identityPath == "" || *anchorPath == "" || *publicPath == "" ||
		*configPath == "" || len(proofPaths) != 3 || flags.NArg() != 0 {
		return errors.New("publish-founder-selection requires --selection, --identity, --anchor, --root-key, --oci-config, and three --proof files")
	}
	identity, err := readFounderIdentity(*identityPath)
	if err != nil {
		return err
	}
	public, err := readRootPublicKey(*publicPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		return err
	}
	anchorWire, err := c.readBoundedRegular(*anchorPath, bootstrap.MaxBootstrapAnchorBytes)
	if err != nil {
		return err
	}
	anchorEnvelope, err := trust.DecodeEnvelope(anchorWire)
	if err != nil {
		return err
	}
	anchor, err := bootstrap.VerifyHistoricalBootstrapAnchor(anchorEnvelope, roots,
		identity.AnchorExpectation(), anchorEnvelope.IssuedAt, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return err
	}
	selectionWire, err := c.readBoundedRegular(*selectionPath, 4096)
	if err != nil {
		return err
	}
	proofs, err := readFounderProofFiles(proofPaths)
	if err != nil {
		return err
	}
	region, err := identity.Cell.OCIRegion()
	if err != nil {
		return err
	}
	client, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(
		common.CustomProfileConfigProvider(*configPath, *profile))
	if err != nil {
		return err
	}
	client.SetRegion(region)
	if err := bootstrapstart.PublishFounderContinuities(c.ctx, anchor,
		identity, roots, selectionWire, proofs, &client, now.Round(0).UTC()); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "published read-only founder selection digest=%x\n", sha256.Sum256(selectionWire))
	return nil
}

func readFounderIdentity(path string) (bootstrapstart.BakedIdentity, error) {
	wire, err := readBoundedRegular(path, 4096)
	if err != nil {
		return bootstrapstart.BakedIdentity{}, err
	}
	var identity bootstrapstart.BakedIdentity
	if err := protocol.DecodeStrict(wire, &identity, 4096); err != nil {
		return bootstrapstart.BakedIdentity{}, err
	}
	canonical, err := protocol.EncodeJSON(identity)
	if err != nil || !bytes.Equal(wire, canonical) || identity.SchemaVersion != 1 {
		return bootstrapstart.BakedIdentity{}, errors.New("founder identity must be canonical version-1 JSON")
	}
	return identity, nil
}

func readFounderProofFiles(paths []string) (map[string][]byte, error) {
	proofs := make(map[string][]byte, len(paths))
	for _, path := range paths {
		wire, err := readBoundedRegular(path, 32<<10)
		if err != nil {
			return nil, err
		}
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return nil, err
		}
		var claim bootstrap.InstallContinuity
		if err := protocol.DecodeStrict(envelope.Payload, &claim, bootstrap.MaxInstallContinuityBytes); err != nil {
			return nil, err
		}
		if _, exists := proofs[claim.Slot]; exists {
			return nil, errors.New("duplicate continuity proof slot")
		}
		proofs[claim.Slot] = wire
	}
	return proofs, nil
}

func verifyFounderProofFiles(paths []string, selection bootstrapstart.FounderSelection,
	roots trust.Keyring, selectorSHA256 string, now time.Time,
) error {
	proofs, err := readFounderProofFiles(paths)
	if err != nil {
		return err
	}
	for _, pin := range selection.Continuities {
		wire, ok := proofs[pin.Slot]
		hash := sha256.Sum256(wire)
		if !ok || hex.EncodeToString(hash[:]) != pin.SHA256 {
			return errors.New("continuity proof does not match selector slot pin")
		}
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil {
			return err
		}
		var claim bootstrap.InstallContinuity
		if err := protocol.DecodeStrict(envelope.Payload, &claim, bootstrap.MaxInstallContinuityBytes); err != nil {
			return err
		}
		_, err = bootstrap.VerifyCurrentInstallContinuity(envelope, roots,
			bootstrap.InstallContinuityExpectation{Install: claim, SelectorGeneration: selection.Generation,
				SelectorSHA256: selectorSHA256, PinnedContinuitySHA256: pin.SHA256},
			now, bootstrap.InstallContinuityTrustPolicy())
		if err != nil {
			return fmt.Errorf("verify continuity proof for %s: %w", pin.Slot, err)
		}
	}
	return nil
}
