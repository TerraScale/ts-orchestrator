package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/membership"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

const controllerConfigDirectory = "/etc/terrascale-orchestrator"
const controllerConfigFilename = "controller.json"
const controllerManifestFilename = "controller-manifest.json"

// ValidateSignedControllerConfig checks, before signing, that the config is
// this binary's canonical app.Config JSON with a valid role-specific meaning.
func ValidateSignedControllerConfig(manifest bootstrap.Manifest, observedPrivateIP string) (Config, error) {
	cfg, err := ValidateInstalledControllerConfig(manifest, observedPrivateIP)
	if err != nil {
		return Config{}, err
	}
	canonical, err := protocol.EncodeJSON(cfg)
	if err != nil || !bytes.Equal(canonical, manifest.ControllerConfig) {
		return Config{}, errors.New("signed controller config must be canonical app.Config JSON")
	}
	return cfg, nil
}

// ValidateLoadedControllerConfig is ValidateInstalledControllerConfig for the
// loaded config, whose digest must be want: the config an adopted material
// generation pins for the slot (TS-668), or else the manifest's own.
func ValidateLoadedControllerConfig(manifest bootstrap.Manifest, config []byte, want, observedPrivateIP string,
) (Config, error) {
	manifest.ControllerConfig, manifest.ControllerConfigSHA256 = config, want
	return ValidateInstalledControllerConfig(manifest, observedPrivateIP)
}

// ValidateInstalledControllerConfig checks the role-specific meaning of the
// exact signed bytes. Guest installation and every restart re-check configs
// that an older or newer binary signed, so the digest covers the bytes, not a
// re-encoding. observedPrivateIP is empty during offline signing and is the
// independently observed primary VNIC address on the guest.
func ValidateInstalledControllerConfig(manifest bootstrap.Manifest, observedPrivateIP string) (Config, error) {
	if len(manifest.ControllerConfig) > bootstrap.MaxControllerConfigBytes ||
		controllerSHA256(manifest.ControllerConfig) != manifest.ControllerConfigSHA256 {
		return Config{}, errors.New("signed controller config differs from its signed digest")
	}
	cfg, err := decodeConfig(manifest.ControllerConfig)
	if err != nil {
		return Config{}, fmt.Errorf("decode signed controller config: %w", err)
	}
	hostConfig := cfg.Host
	if len(hostConfig.Roles) == 0 {
		hostConfig.Roles = nil
	}
	if cfg.NATS.Cell != strings.ToLower(string(manifest.Cell)) || cfg.NATS.Instance != manifest.Slot ||
		cfg.NATS.Replicas != len(manifest.ControllerSlots) || cfg.NATS.Lab || cfg.NATS.Embedded == nil ||
		cfg.Controller.CandidateID != manifest.Slot || !reflect.DeepEqual(hostConfig, HostConfig{}) ||
		cfg.Operator != (OperatorConfig{}) ||
		cfg.Controller.OciRegionConfig != controllerSidecarPath("oci-region.json") ||
		cfg.Controller.OciRegionIntentFile != controllerSidecarPath("oci-region-intent.json") ||
		cfg.Controller.PlacementConfig != controllerSidecarPath("placement.json") ||
		cfg.NATS.NKeySeedFile != "" || cfg.Controller.TrustKeyFile != "" || cfg.Controller.SpecTrust != nil {
		return Config{}, errors.New("signed controller config does not match role, slot, or fixed paths")
	}
	if observedPrivateIP != "" && (cfg.NATS.Embedded.Host != observedPrivateIP ||
		cfg.NATS.Embedded.RouteHost != observedPrivateIP) {
		return Config{}, errors.New("signed broker addresses differ from the observed primary VNIC")
	}
	address, addressErr := netip.ParseAddr(cfg.NATS.Embedded.Host)
	if addressErr != nil || !address.Is4() || !address.IsPrivate() || address.String() != cfg.NATS.Embedded.Host ||
		cfg.NATS.Embedded.RouteHost != cfg.NATS.Embedded.Host || cfg.NATS.Embedded.Port != 4222 ||
		cfg.NATS.Embedded.RoutePort != 6222 || cfg.NATS.URL != "tls://"+cfg.NATS.Embedded.Host+":4222" ||
		cfg.NATS.Embedded.StoreDir != "/var/lib/terrascale-orchestrator-controller/nats" ||
		cfg.NATS.Embedded.StoreMaxBytes < 2<<30 || cfg.NATS.Embedded.StoreMaxBytes > 8<<30 ||
		cfg.NATS.Embedded.RouteUser != "ts-route" || len(cfg.NATS.Embedded.Users) != 0 ||
		!slices.Equal(cfg.NATS.Embedded.BrokerIDs, manifest.ControllerSlots) ||
		len(cfg.NATS.Embedded.Routes) != len(manifest.ControllerSlots)-1 {
		return Config{}, errors.New("signed controller broker runtime is outside the reviewed shape")
	}
	seenRoutes := make(map[string]bool, len(cfg.NATS.Embedded.Routes))
	for _, route := range cfg.NATS.Embedded.Routes {
		if !strings.HasPrefix(route, "nats-route://") || !strings.HasSuffix(route, ":6222") ||
			seenRoutes[route] || route == "nats-route://"+cfg.NATS.Embedded.Host+":6222" {
			return Config{}, errors.New("signed controller route is invalid or duplicated")
		}
		peer, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(route, "nats-route://"), ":6222"))
		if err != nil || !peer.Is4() || !peer.IsPrivate() {
			return Config{}, errors.New("signed controller route address is invalid")
		}
		seenRoutes[route] = true
	}
	if cfg.Controller.HostEnrollmentListenAddress != cfg.NATS.Embedded.Host+":8443" {
		return Config{}, errors.New("host enrollment listener differs from the signed controller address")
	}
	if err := validateSignedObservability(cfg); err != nil {
		return Config{}, err
	}
	// The Machines API has no signed listener, TLS material or load balancer
	// yet (docs/machines-api.md, slice 7); until it does, a production
	// controller must not try to bind it.
	if cfg.Controller.MachinesAPI != nil {
		return Config{}, errors.New("signed controller config may not enable machines_api yet")
	}
	if _, err := buildSignerPolicy(cfg); err != nil {
		return Config{}, fmt.Errorf("signed controller operator grant: %w", err)
	}
	if len(manifest.ControllerFiles) != len(bootstrap.ControllerConfigFileNames) {
		return Config{}, errors.New("signed controller sidecars are incomplete")
	}
	for index, file := range manifest.ControllerFiles {
		if file.Name != bootstrap.ControllerConfigFileNames[index] ||
			controllerSHA256(file.Bytes) != file.SHA256 {
			return Config{}, errors.New("signed controller sidecar digest or name is invalid")
		}
	}
	secretFiles := make(map[string]struct{}, len(manifest.Secrets))
	for _, reference := range manifest.Secrets {
		if reference.Purpose == bootstrap.SecretRegionalShared ||
			reference.Purpose == bootstrap.SecretHostIssuer ||
			reference.Purpose == bootstrap.SecretController && reference.Slot == manifest.Slot ||
			(reference.Purpose == bootstrap.SecretSeedFounder || reference.Purpose == bootstrap.SecretSeedLedgerSigner) &&
				manifest.Slot == manifest.SeedSlot {
			secretFiles[reference.TargetFile] = struct{}{}
		}
	}
	paths := []string{cfg.NATS.CredentialsFile, cfg.NATS.TLS.CAFile, cfg.NATS.TLS.CertFile,
		cfg.NATS.TLS.KeyFile, cfg.NATS.Embedded.TLS.CAFile, cfg.NATS.Embedded.TLS.CertFile,
		cfg.NATS.Embedded.TLS.KeyFile, cfg.NATS.Embedded.RouteTLS.CAFile,
		cfg.NATS.Embedded.RouteTLS.CertFile, cfg.NATS.Embedded.RouteTLS.KeyFile,
		cfg.NATS.Embedded.RoutePasswordFile, cfg.NATS.Embedded.OperatorJWTFile,
		cfg.NATS.Embedded.SystemJWTFile, cfg.NATS.Embedded.CellJWTFile,
		cfg.NATS.Embedded.SystemCredentialsFile, cfg.NATS.Embedded.TicketPublicKeyFile,
		cfg.Controller.ResponseKeyFile, cfg.Controller.BrokerTicketKeyFile,
		cfg.Controller.HostNATSIssuerSeedFile, cfg.Controller.HostTLSIssuerKeyFile,
		cfg.Controller.HostTLSIssuerCertFile}
	for _, path := range paths {
		name := filepath.Base(path)
		if path == "" || path != filepath.Join(bootstrapstart.MaterialDirectory, name) {
			return Config{}, errors.New("controller credential path escapes the signed material directory")
		}
		if _, exists := secretFiles[name]; !exists {
			return Config{}, fmt.Errorf("controller credential %s is absent from signed material", name)
		}
	}
	// Interregion files come from an adopted material generation, whose pins
	// restart admission checks (TS-668); they too live in the directory.
	for _, path := range cfg.NATS.Embedded.InterRegion.Files() {
		if path != filepath.Join(bootstrapstart.MaterialDirectory, filepath.Base(path)) {
			return Config{}, errors.New("interregion credential path escapes the signed material directory")
		}
	}
	// The C# TerraBase member CA is host-issuer material: configured exactly
	// when signed, at its fixed paths, as the live credential check requires.
	_, signedCACert := secretFiles["terrabase-member-ca.pem"]
	_, signedCAKey := secretFiles["terrabase-member-ca.key"]
	if cfg.Controller.TerraBaseCACertFile != "" || cfg.Controller.TerraBaseCAKeyFile != "" || signedCACert || signedCAKey {
		if !signedCACert || !signedCAKey ||
			cfg.Controller.TerraBaseCACertFile != filepath.Join(bootstrapstart.MaterialDirectory, "terrabase-member-ca.pem") ||
			cfg.Controller.TerraBaseCAKeyFile != filepath.Join(bootstrapstart.MaterialDirectory, "terrabase-member-ca.key") {
			return Config{}, errors.New("TerraBase member CA is not the signed slot material")
		}
	}
	// Without the member CA no member gets a certificate or starts.
	if _, terraBase := cfg.Controller.Workloads[terrabase.Role]; terraBase && !signedCACert {
		return Config{}, errors.New("a signed TerraBase workload profile needs the signed member CA")
	}
	if err := validateWorkloadProfiles(cfg.NATS.Cell, cfg.Controller.Workloads); err != nil {
		return Config{}, fmt.Errorf("signed controller workloads: %w", err)
	}
	if err := validateAutoscaleConfig(cfg.Controller.Autoscale, cfg.Controller.Workloads); err != nil {
		return Config{}, fmt.Errorf("signed controller autoscale: %w", err)
	}
	if path := cfg.NATS.Embedded.MembershipCredentialsFile; path != "" {
		if _, signed := secretFiles["membership.creds"]; !signed ||
			path != filepath.Join(bootstrapstart.MaterialDirectory, "membership.creds") {
			return Config{}, errors.New("membership credentials are not the signed slot material")
		}
	}
	if settings := cfg.Controller.Membership; settings != nil {
		if err := settings.Validate(); err != nil {
			return Config{}, fmt.Errorf("signed controller membership: %w", err)
		}
		if settings.RetirementEvidenceDir != "" && settings.RetirementEvidenceDir != membership.DefaultRetirementEvidenceDir {
			return Config{}, errors.New("signed controller membership evidence directory must be the fixed path")
		}
	}
	if cfg.Controller.ResponseKeyFile != filepath.Join(bootstrapstart.MaterialDirectory, manifest.Slot+"-response.key") ||
		cfg.Controller.BrokerTicketKeyFile != filepath.Join(bootstrapstart.MaterialDirectory, "ticket.key") ||
		cfg.Controller.HostNATSIssuerSeedFile != filepath.Join(bootstrapstart.MaterialDirectory, "host-nats-issuer.seed") ||
		cfg.Controller.HostTLSIssuerKeyFile != filepath.Join(bootstrapstart.MaterialDirectory, "host-tls-issuer-key.pem") ||
		cfg.Controller.HostTLSIssuerCertFile != filepath.Join(bootstrapstart.MaterialDirectory, "host-tls-issuer-cert.pem") {
		return Config{}, errors.New("controller response or broker-ticket key does not match the slot")
	}
	intent, err := oci.ParseRegionIntent(manifest.ControllerFiles[0].Bytes)
	if err != nil || intent.Generation != manifest.IntentGeneration ||
		manifest.ControllerFiles[0].SHA256 != manifest.IntentSHA256 {
		return Config{}, errors.New("controller regional intent differs from signed anchor pin")
	}
	region, err := oci.ParseRegionConfig(manifest.ControllerFiles[1].Bytes)
	if err != nil || region.Validate(intent) != nil || region.Region != manifest.Cell {
		return Config{}, errors.New("controller fleet config differs from signed region")
	}
	var placement managedPlacementSettings
	if err := protocol.DecodeStrict(manifest.ControllerFiles[2].Bytes, &placement, bootstrap.MaxControllerSidecarBytes); err != nil ||
		placement.Environment != manifest.Environment || placement.MemberRole == "" ||
		placement.TickMillis < 0 || placement.TickMillis > 300_000 ||
		placement.TickMillis > 0 && placement.TickMillis < 100 {
		return Config{}, errors.New("controller placement config differs from signed environment")
	}
	// Controller start refuses the same overlap; refuse it before signing.
	if _, exists := cfg.Controller.Workloads[placement.MemberRole]; exists {
		return Config{}, fmt.Errorf("placement member role %q overlaps a generic delivery workload profile", placement.MemberRole)
	}
	return cfg, nil
}

// validateSignedObservability keeps a signed controller's telemetry listener
// on loopback or on its own signed private broker address, never on another
// interface, and keeps any token or TLS file under the signed config root.
func validateSignedObservability(cfg Config) error {
	settings := cfg.Observability
	if err := settings.Validate(); err != nil {
		return fmt.Errorf("signed controller observability: %w", err)
	}
	if settings.Enabled() {
		address, err := netip.ParseAddrPort(settings.Address())
		if err != nil || !address.Addr().IsLoopback() && address.Addr().String() != cfg.NATS.Embedded.Host {
			return errors.New("signed observability listener must bind loopback or the signed broker address")
		}
	}
	for _, path := range []string{settings.BearerTokenFile, settings.TLSCertFile, settings.TLSKeyFile} {
		if path != "" && (filepath.Clean(path) != path ||
			!strings.HasPrefix(path, controllerConfigDirectory+"/")) {
			return errors.New("signed observability files must live under the controller config directory")
		}
	}
	return nil
}

func controllerSidecarPath(name string) string {
	return filepath.Join(controllerConfigDirectory, name)
}

func controllerSHA256(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}
