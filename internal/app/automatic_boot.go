package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart/materialsource"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"golang.org/x/sys/unix"
)

const automaticStartupGrantFilename = "startup-grant.json"
const automaticStartupAuthorityFilename = "startup-authority.json"

type automaticFoundation struct {
	foundations region.FoundationResolver
	factory     *ociclient.Factory
	anchor      bootstrap.VerifiedBootstrapAnchor
	baked       bootstrapstart.BakedInputs
	imds        bootstrapstart.DescriptorSource
	instanceID  string
	cell        string
	observed    bootstrapstart.InstanceObservation
}

// foundationDiscovery observes identity and trust without creating material or
// granting the observed host permission to found or join a regional cluster.
func foundationDiscovery(ctx context.Context) (automaticFoundation, error) {
	imds := bootstrapstart.NewIMDSClient()
	instanceID, err := imds.FetchInstanceID(ctx)
	if err != nil {
		return automaticFoundation{}, fmt.Errorf("discover local OCI instance identity: %w", err)
	}
	parts := strings.Split(instanceID, ".")
	if len(parts) != 5 {
		return automaticFoundation{}, bootstrapstart.ErrInstanceObservation
	}
	entry, ok := catalog.CellForOCIRegion(parts[3])
	if !ok {
		return automaticFoundation{}, errors.New("local OCI instance region is outside the region catalog")
	}
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return automaticFoundation{}, err
	}
	if baked.Identity.Cell != oci.Region(entry.Cell) {
		return automaticFoundation{}, errors.New("local OCI instance region differs from bootstrap identity")
	}
	envelope, err := trust.DecodeEnvelope(baked.AnchorWire)
	if err != nil {
		return automaticFoundation{}, err
	}
	anchor, err := bootstrap.VerifyBootstrapAnchor(envelope, baked.Roots,
		baked.Identity.AnchorExpectation(), time.Now().UTC(), bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		return automaticFoundation{}, fmt.Errorf("verify foundation discovery anchor: %w", err)
	}
	if anchor.Anchor().OCIRegion != entry.OCIRegion || anchor.Anchor().Cell != oci.Region(entry.Cell) {
		return automaticFoundation{}, errors.New("local OCI instance differs from signed bootstrap region")
	}
	factory, err := ociclient.InstancePrincipal(entry.OCIRegion)
	if err != nil {
		return automaticFoundation{}, err
	}
	observer, err := bootstrapstart.NewOCIInstanceObserver(oci.Region(entry.Cell), factory.Provider())
	if err != nil {
		return automaticFoundation{}, err
	}
	observed, err := observer.ObserveInstance(ctx, instanceID)
	if err != nil {
		return automaticFoundation{}, err
	}
	if observed.InstanceOCID != instanceID || observed.LifecycleState != "RUNNING" {
		return automaticFoundation{}, bootstrapstart.ErrInstanceObservation
	}
	foundations, err := region.NewFoundationDiscovery(factory, anchor, baked.Roots)
	if err != nil {
		return automaticFoundation{}, err
	}
	return automaticFoundation{foundations: foundations, factory: factory, anchor: anchor,
		baked: baked, imds: imds, instanceID: instanceID, cell: entry.Cell, observed: observed}, nil
}

func automaticControllerSlot(ctx context.Context, local *automaticFoundation, grant region.VerifiedBootstrapMaterial) (string, error) {
	if local == nil || local.factory == nil || local.imds == nil || !local.anchor.IsVerified() {
		return "", bootstrapstart.ErrInstanceObservation
	}
	startup, err := grant.Startup()
	if err != nil {
		return "", err
	}
	if _, err := automaticStartupSigners(startup.TrustedSigners); err != nil {
		return "", err
	}
	config, anchor := grant.Config(), local.anchor.Anchor()
	if config.DeploymentID != anchor.DeploymentID || config.ClusterID != anchor.ClusterID ||
		config.Environment != anchor.Environment || config.Cell != strings.ToLower(local.cell) ||
		config.Region != anchor.OCIRegion || !time.Now().Before(grant.ExpiresAt()) {
		return "", errors.New("bootstrap material authority differs from the local signed installation")
	}
	descriptor, err := local.imds.FetchDescriptor(ctx)
	if err != nil {
		return "", fmt.Errorf("read automatic bootstrap controller role: %w", err)
	}
	if descriptor.SchemaVersion != 1 || !slices.Contains(anchor.ControllerSlots, descriptor.Slot) {
		return "", errors.New("local role is outside the signed controller slots")
	}
	image, err := release.VerifyImageCurrent(startup.ReleaseImageReceiptWire, startup.ReleaseDelegationWire,
		local.baked.Roots, release.ImageExpectation{Environment: config.Environment, LogicalRegion: local.cell,
			OCIImageOCID: startup.ImageOCID, Architecture: strings.TrimPrefix(startup.ImageArchitecture, "linux-")}, time.Now().UTC())
	if err != nil {
		return "", fmt.Errorf("verify current automatic bootstrap image: %w", err)
	}
	if _, err := bootstrapstart.VerifyCurrentRunningBinary(image); err != nil {
		return "", err
	}
	observer, err := bootstrapstart.NewOCIInstanceObserver(anchor.Cell, local.factory.Provider())
	if err != nil {
		return "", err
	}
	observed, err := observer.ObserveInstance(ctx, local.instanceID)
	if err != nil {
		return "", err
	}
	for _, profile := range startup.Profiles {
		if profile.Slot != descriptor.Slot {
			continue
		}
		actualNSGs, expectedNSGs := slices.Clone(observed.NSGOCIDs), slices.Clone(profile.NetworkSecurityGroupOCIDs)
		slices.Sort(actualNSGs)
		slices.Sort(expectedNSGs)
		if observed.InstanceOCID != local.instanceID || observed.ImageOCID != startup.ImageOCID ||
			observed.CompartmentOCID != profile.CompartmentOCID || observed.AvailabilityDomain != profile.AvailabilityDomain ||
			observed.FaultDomain != profile.FaultDomain || observed.Shape != profile.Shape || observed.SubnetOCID != profile.SubnetOCID ||
			!slices.Equal(actualNSGs, expectedNSGs) || observed.LifecycleState != "RUNNING" || !observed.PrimaryVNIC ||
			!strings.HasPrefix(observed.PrimaryVNICOCID, "ocid1.vnic.") {
			return "", bootstrapstart.ErrInstanceObservation
		}
		for _, slot := range config.Slots {
			if slot.Name == descriptor.Slot && slot.PrivateIP == observed.PrimaryPrivateIP {
				local.observed = observed
				return descriptor.Slot, nil
			}
		}
		return "", errors.New("controller private address differs from signed material inventory")
	}
	return "", errors.New("signed startup authority has no local controller profile")
}

func automaticStartupSigners(wire []byte) ([]TrustedSignerConfig, error) {
	var signers []TrustedSignerConfig
	if err := protocol.DecodeStrict(wire, &signers, bootstrap.MaxControllerConfigBytes); err != nil {
		return nil, fmt.Errorf("decode signed startup operator grants: %w", err)
	}
	if len(signers) == 0 || len(signers) > 64 {
		return nil, errors.New("signed startup operator grants are absent or oversized")
	}
	if _, err := newSignerSet(signers); err != nil {
		return nil, err
	}
	return signers, nil
}

func automaticControllerConfig(manifest bootstrap.Manifest, record bootstrapmaterial.Record, signerWire []byte, now time.Time) (bootstrap.Manifest, error) {
	signers, err := automaticStartupSigners(signerWire)
	if err != nil {
		return bootstrap.Manifest{}, err
	}
	config, err := ControllerConfigFromRecord(manifest, record, signers[0], now)
	if err != nil {
		return bootstrap.Manifest{}, err
	}
	config.Controller.TrustedSigners = signers
	wire, err := protocol.EncodeJSON(config)
	if err != nil || len(wire) > bootstrap.MaxControllerConfigBytes {
		return bootstrap.Manifest{}, errors.New("derived controller configuration exceeds its size bound")
	}
	manifest.ControllerConfig = wire
	manifest.ControllerConfigSHA256 = controllerSHA256(wire)
	if _, err := ValidateSignedControllerConfig(manifest, ""); err != nil {
		return bootstrap.Manifest{}, fmt.Errorf("validate derived controller configuration: %w", err)
	}
	return manifest, nil
}

func automaticVaultTarget(ctx context.Context, local automaticFoundation, grant region.VerifiedBootstrapMaterial) (bootstrapmaterial.VaultTarget, error) {
	record, err := local.foundations.Resolve(ctx, local.cell)
	if err != nil {
		return bootstrapmaterial.VaultTarget{}, err
	}
	config := grant.Config()
	if !grant.IsVerified() || !time.Now().Before(grant.ExpiresAt()) || record.Generation != grant.Generation() ||
		record.Cell != local.cell || record.OCIRegion != config.Region || strings.ToLower(record.Cell) != config.Cell {
		return bootstrapmaterial.VaultTarget{}, errors.New("bootstrap publication foundation differs from the current signed material authority")
	}
	target, err := record.VaultTarget()
	if err != nil {
		return bootstrapmaterial.VaultTarget{}, err
	}
	template, err := bootstrap.VerifyStartupTemplate(grant.FoundationGrantWire(), local.baked.Roots, local.anchor, time.Now().UTC())
	if err != nil {
		return bootstrapmaterial.VaultTarget{}, err
	}
	signed := template.VaultTarget()
	if signed.CompartmentOCID != target.CompartmentID || signed.VaultOCID != target.VaultID || signed.KMSKeyOCID != target.KeyID {
		return bootstrapmaterial.VaultTarget{}, errors.New("regional foundation Vault differs from the signed startup publication destination")
	}
	return bootstrapmaterial.VaultTarget{CompartmentOCID: target.CompartmentID, VaultOCID: target.VaultID, KMSKeyOCID: target.KeyID}, nil
}

// VerifiedAutomaticInstall retains only a house-rendered installation tied to
// the same signed startup template, owned host and exact durable source.
type VerifiedAutomaticInstall struct {
	template bootstrap.VerifiedStartupTemplate
	material materialsource.VerifiedColdStartMaterial
	founder  bootstrapstart.VerifiedSourceFounder
	manifest bootstrap.Manifest
	configs  map[string][]byte
}

func newVerifiedAutomaticInstall(ctx context.Context, local *automaticFoundation, template bootstrap.VerifiedStartupTemplate, material materialsource.VerifiedColdStartMaterial) (VerifiedAutomaticInstall, error) {
	if local == nil || local.factory == nil || !template.IsVerified() || !material.IsVerified() ||
		!bytes.Equal(template.GrantWire(), material.Grant().FoundationGrantWire()) ||
		template.InstallationID() != material.Grant().InstallationID() || template.Generation() != material.Grant().Generation() ||
		template.PlanDigest() != material.Grant().PlanDigest() {
		return VerifiedAutomaticInstall{}, errors.New("automatic installation startup and material authorities differ")
	}
	if err := material.VerifyCurrent(ctx); err != nil {
		return VerifiedAutomaticInstall{}, err
	}
	founder, err := bootstrapstart.VerifySourceFounder(ctx, local.factory, template)
	if err != nil {
		return VerifiedAutomaticInstall{}, err
	}
	if founder.InstanceID() != local.instanceID {
		return VerifiedAutomaticInstall{}, errors.New("automatic installation founder differs from the local instance")
	}
	slot := founder.SeedSlot()
	observed, err := founder.ObserveCurrent(ctx)
	if err != nil {
		return VerifiedAutomaticInstall{}, err
	}
	local.observed = observed
	target, err := automaticVaultTarget(ctx, *local, material.Grant())
	if err != nil {
		return VerifiedAutomaticInstall{}, err
	}
	publication, signedTarget := material.Publication(), template.VaultTarget()
	if publication.Target != target || signedTarget.CompartmentOCID != target.CompartmentOCID ||
		signedTarget.VaultOCID != target.VaultOCID || signedTarget.KMSKeyOCID != target.KMSKeyOCID {
		return VerifiedAutomaticInstall{}, errors.New("automatic installation publication differs from the signed owned regional Vault target")
	}
	references := make([]bootstrap.SecretReference, 0, len(publication.References))
	for _, reference := range publication.References {
		references = append(references, reference.Reference)
	}
	configs := make(map[string][]byte, len(local.anchor.Anchor().ControllerSlots))
	var localManifest bootstrap.Manifest
	for _, controllerSlot := range local.anchor.Anchor().ControllerSlots {
		manifest, err := template.ManifestFor(controllerSlot, references)
		if err != nil {
			return VerifiedAutomaticInstall{}, err
		}
		manifest, err = automaticControllerConfig(manifest, material.Record(), template.Template().TrustedSigners, time.Now().UTC())
		if err != nil {
			return VerifiedAutomaticInstall{}, err
		}
		configs[controllerSlot] = bytes.Clone(manifest.ControllerConfig)
		if controllerSlot == slot {
			if _, err := ValidateSignedControllerConfig(manifest, observed.PrimaryPrivateIP); err != nil {
				return VerifiedAutomaticInstall{}, err
			}
			localManifest = manifest
		}
	}
	if localManifest.Slot != slot {
		return VerifiedAutomaticInstall{}, errors.New("automatic installation seed is outside the signed controller slots")
	}
	return VerifiedAutomaticInstall{template: template, material: material, founder: founder, manifest: localManifest, configs: configs}, nil
}

func (install VerifiedAutomaticInstall) bindAuthority(ctx context.Context) (bootstrap.DerivedStartupAuthority, error) {
	if !install.template.IsVerified() || !install.material.IsVerified() || !install.founder.IsVerified() ||
		install.founder.GrantDigest() != install.template.GrantDigest() || install.founder.TemplateDigest() != install.template.TemplateDigest() ||
		!bytes.Equal(install.configs[install.manifest.Slot], install.manifest.ControllerConfig) {
		return bootstrap.DerivedStartupAuthority{}, errors.New("automatic installation has no verified local rendering")
	}
	_, guarded, err := install.founder.GuardedFactory(ctx)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	projection, err := materialsource.NewStartupProjection(install.template, install.material, install.manifest.Slot)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	authority, err := projection.BindConfigs(guarded, install.configs)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if !bytes.Equal(authority.Manifest().ControllerConfig, install.manifest.ControllerConfig) {
		return bootstrap.DerivedStartupAuthority{}, errors.New("durable automatic installation differs from its local rendering")
	}
	return authority, nil
}

func (install VerifiedAutomaticInstall) install(ctx context.Context) (bootstrap.DerivedStartupAuthority, error) {
	authority, err := install.bindAuthority(ctx)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if err := installAutomaticControllerFiles(ctx, authority); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	return authority, nil
}

func automaticPeerAuthority(ctx context.Context, local *automaticFoundation, grant region.VerifiedBootstrapMaterial,
	template bootstrap.VerifiedStartupTemplate, authority bootstrap.DerivedStartupAuthority,
) (bootstrap.DerivedStartupAuthority, error) {
	if !template.IsVerified() || !authority.IsVerified() || !bytes.Equal(template.GrantWire(), authority.GrantWire()) ||
		!bytes.Equal(template.GrantWire(), grant.FoundationGrantWire()) {
		return bootstrap.DerivedStartupAuthority{}, errors.New("automatic peer startup authorities differ")
	}
	if err := authority.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	slot, err := automaticControllerSlot(ctx, local, grant)
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	manifest := authority.Manifest()
	if manifest.Slot != slot || slot == template.Template().SeedSlot {
		return bootstrap.DerivedStartupAuthority{}, errors.New("automatic peer proof does not name the local non-founding slot")
	}
	if _, err := automaticVaultTarget(ctx, *local, grant); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if err := validateAutomaticAuthorityRendering(authority); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if _, err := ValidateSignedControllerConfig(manifest, local.observed.PrimaryPrivateIP); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	return authority, nil
}

func validateAutomaticAuthorityRendering(authority bootstrap.DerivedStartupAuthority) error {
	if !authority.IsVerified() {
		return errors.New("automatic installation authority is unverified")
	}
	var record bootstrapmaterial.Record
	if err := protocol.DecodeStrict(authority.MaterialRecord(), &record, 1<<20); err != nil {
		return err
	}
	manifest := authority.Manifest()
	rendered, err := automaticControllerConfig(manifest, record, authority.TrustedSigners(), time.Now().UTC())
	if err != nil {
		return err
	}
	if !bytes.Equal(rendered.ControllerConfig, manifest.ControllerConfig) {
		return errors.New("automatic installation configuration differs from the house renderer")
	}
	return nil
}

func loadAutomaticStartupAuthority(ctx context.Context, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring,
	objects bootstrap.ObjectStorageClient,
) (bootstrap.DerivedStartupAuthority, bool, error) {
	grant, grantErr := readInstalledControllerFile(controllerConfigDirectory, automaticStartupGrantFilename, 0, 0, 0o444, 1<<20)
	wire, wireErr := readInstalledControllerFile(controllerConfigDirectory, automaticStartupAuthorityFilename, 0, 0, 0o444, bootstrap.MaxManifestBytes)
	if errors.Is(grantErr, os.ErrNotExist) && errors.Is(wireErr, os.ErrNotExist) {
		return bootstrap.DerivedStartupAuthority{}, false, nil
	}
	if err := errors.Join(grantErr, wireErr); err != nil {
		return bootstrap.DerivedStartupAuthority{}, true, fmt.Errorf("read durable automatic startup authority: %w", err)
	}
	authority, err := bootstrap.RestoreDerivedStartupAuthority(ctx, grant, anchor, roots, objects, wire, time.Now().UTC())
	if err != nil {
		return bootstrap.DerivedStartupAuthority{}, true, err
	}
	if err := validateAutomaticAuthorityRendering(authority); err != nil {
		return bootstrap.DerivedStartupAuthority{}, true, err
	}
	return authority, true, nil
}

func installAutomaticControllerFiles(ctx context.Context, authority bootstrap.DerivedStartupAuthority) error {
	if err := authority.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return err
	}
	if err := validateAutomaticAuthorityRendering(authority); err != nil {
		return err
	}
	dir, err := openControllerConfigDirectory(controllerConfigDirectory)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	for _, file := range []bootstrap.ControllerConfigFile{
		{Name: automaticStartupGrantFilename, Bytes: authority.GrantWire()},
		{Name: automaticStartupAuthorityFilename, Bytes: authority.Wire()},
	} {
		if err := installExactControllerFile(dir, file.Name, file.Bytes, 0, 0, 0o444); err != nil {
			return err
		}
	}
	manifest := authority.Manifest()
	for _, file := range manifest.ControllerFiles {
		if err := installExactControllerFile(dir, file.Name, file.Bytes, 0, 0, 0o444); err != nil {
			return err
		}
	}
	return installExactControllerFile(dir, controllerConfigFilename, manifest.ControllerConfig, 0, 0, 0o444)
}

// ControllerConfigFromRecord derives the fixed controller configuration from
// the exact credential inventory and the admitted installation's public inputs.
func ControllerConfigFromRecord(manifest bootstrap.Manifest, record bootstrapmaterial.Record,
	grant TrustedSignerConfig, now time.Time,
) (Config, error) {
	publicKey, keyErr := base64.StdEncoding.Strict().DecodeString(record.Public.ControllerResponsePublicKey)
	prefix, prefixErr := netip.ParsePrefix(record.Config.SubnetCIDR)
	if record.SchemaVersion != 1 || record.Config.DeploymentID != manifest.DeploymentID ||
		record.Config.ClusterID != manifest.ClusterID || record.Config.Environment != manifest.Environment ||
		record.Config.Cell != strings.ToLower(string(manifest.Cell)) || record.Config.Region != manifest.OCIRegion ||
		len(record.Config.Slots) != len(manifest.ControllerSlots) || len(record.Config.Slots) != 3 ||
		!now.Before(record.ExpiresAt) || record.IssuedAt.IsZero() ||
		keyErr != nil || len(publicKey) != ed25519.PublicKeySize ||
		prefixErr != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix {
		return Config{}, errors.New("reviewed material record does not match the candidate deployment")
	}
	secretFiles := make(map[string]bootstrapmaterial.File, len(record.Files))
	for _, file := range record.Files {
		if file.Name == "" || file.Name != filepath.Base(file.Name) || file.SHA256 == "" ||
			file.MaxBytes <= 0 || len(secretFiles) >= 64 {
			return Config{}, errors.New("reviewed material inventory is invalid")
		}
		if _, exists := secretFiles[file.Name]; exists {
			return Config{}, errors.New("reviewed material inventory repeats an output")
		}
		secretFiles[file.Name] = file
	}
	for _, reference := range manifest.Secrets {
		file, exists := secretFiles[reference.TargetFile]
		if !exists || file.Purpose != reference.Purpose || file.Slot != reference.Slot ||
			file.SHA256 != reference.SHA256 || file.MaxBytes != reference.MaxBytes {
			return Config{}, fmt.Errorf("signed material reference %s differs from reviewed source", reference.TargetFile)
		}
	}
	// Material generated before the member CA existed renders without it.
	for _, name := range []string{"terrabase-member-ca.pem", "terrabase-member-ca.key"} {
		if record.HasMemberCA() && !slices.ContainsFunc(manifest.Secrets, func(reference bootstrap.SecretReference) bool {
			return reference.TargetFile == name && reference.Purpose == bootstrap.SecretHostIssuer
		}) {
			return Config{}, fmt.Errorf("candidate manifest does not reference the TerraBase member CA secret %s", name)
		}
	}
	addresses := make(map[string]string, len(record.Config.Slots))
	for index, slot := range record.Config.Slots {
		address, err := netip.ParseAddr(slot.PrivateIP)
		if err != nil || slot.Name != manifest.ControllerSlots[index] || !address.Is4() || !prefix.Contains(address) ||
			address == prefix.Addr() || address == prefix.Addr().Next() || address.String() != slot.PrivateIP {
			return Config{}, errors.New("reviewed controller slot address or order differs from signed candidate")
		}
		if slices.ContainsFunc(record.Config.Slots[:index], func(prior bootstrapmaterial.Slot) bool {
			return prior.PrivateIP == slot.PrivateIP
		}) {
			return Config{}, errors.New("reviewed controller private addresses repeat")
		}
		addresses[slot.Name] = slot.PrivateIP
	}
	host, exists := addresses[manifest.Slot]
	if !exists {
		return Config{}, errors.New("candidate slot is absent from reviewed controller inventory")
	}
	path := func(name string) string { return filepath.Join(bootstrapstart.MaterialDirectory, name) }
	tls := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path(manifest.Slot + "-tls-cert.pem"),
		KeyFile: path(manifest.Slot + "-tls-key.pem")}
	routes := make([]string, 0, len(record.Config.Slots)-1)
	for _, slot := range record.Config.Slots {
		if slot.Name != manifest.Slot {
			routes = append(routes, "nats-route://"+slot.PrivateIP+":6222")
		}
	}
	cfg := Config{Version: ConfigVersion,
		NATS: natscell.Config{Cell: record.Config.Cell, Instance: manifest.Slot, Replicas: len(record.Config.Slots),
			ClientRole: "controller", URL: "tls://" + host + ":4222", CredentialsFile: path(manifest.Slot + ".creds"),
			TLS: tls, Embedded: &natscell.Embedded{Host: host, Port: 4222, RouteHost: host, RoutePort: 6222,
				Routes: routes, StoreDir: "/var/lib/terrascale-orchestrator-controller/nats", StoreMaxBytes: 4 << 30,
				TLS: tls, RouteTLS: tls, RouteUser: "ts-route", RoutePasswordFile: path("route-password"),
				OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"),
				CellJWTFile: path("cell.jwt"), SystemCredentialsFile: path("system.creds"),
				TicketPublicKeyFile: path("ticket.pub"), BrokerIDs: slices.Clone(manifest.ControllerSlots)}},
		Controller: ControllerConfig{CandidateID: entityid.Derive("controller", manifest.DeploymentID, string(manifest.Cell), manifest.Slot),
			ArtifactStoreMaxBytes: 512 << 20,
			ResponseKeyFile:       path(manifest.Slot + "-response.key"), BrokerTicketKeyFile: path("ticket.key"),
			HostNATSIssuerSeedFile:      path("host-nats-issuer.seed"),
			HostTLSIssuerKeyFile:        path("host-tls-issuer-key.pem"),
			HostTLSIssuerCertFile:       path("host-tls-issuer-cert.pem"),
			HostEnrollmentListenAddress: host + ":8443",
			OciRegionIntentFile:         "/etc/terrascale-orchestrator/oci-region-intent.json",
			OciRegionConfig:             "/etc/terrascale-orchestrator/oci-region.json",
			PlacementConfig:             "/etc/terrascale-orchestrator/placement.json",
			TrustedSigners:              []TrustedSignerConfig{grant}},
	}
	if record.HasMemberCA() {
		cfg.Controller.TerraBaseCACertFile = path("terrabase-member-ca.pem")
		cfg.Controller.TerraBaseCAKeyFile = path("terrabase-member-ca.key")
	}
	return cfg, nil
}
