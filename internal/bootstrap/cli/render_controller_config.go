package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

// renderControllerConfigAt creates one deterministic production role config
// from a hash-pinned material inventory and reviewed public inputs. The
// resulting exact bytes are subsequently embedded by sign-manifest.
func (c command) renderControllerConfigAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("render-controller-config", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "reviewed unsigned per-slot manifest")
	candidateSHA := flags.String("candidate-sha256", "", "reviewed unsigned manifest SHA-256")
	recordPath := flags.String("material-record", "", "reviewed public material inventory")
	recordSHA := flags.String("material-record-sha256", "", "reviewed public inventory SHA-256")
	grantPath := flags.String("operator-grant", "", "reviewed canonical operator grant JSON")
	grantSHA := flags.String("operator-grant-sha256", "", "reviewed operator grant SHA-256")
	intentPath := flags.String("oci-region-intent", "", "reviewed regional intent JSON")
	intentSHA := flags.String("oci-region-intent-sha256", "", "reviewed regional intent SHA-256")
	regionPath := flags.String("oci-region-config", "", "reviewed fleet JSON")
	regionSHA := flags.String("oci-region-config-sha256", "", "reviewed fleet SHA-256")
	placementPath := flags.String("placement-config", "", "reviewed placement JSON")
	placementSHA := flags.String("placement-config-sha256", "", "reviewed placement SHA-256")
	profilePath := flags.String("terrabase-profile", "", "deprecated: optional reviewed C# TerraBase workload profile JSON; apply it as a root-signed cell spec terrabase entry instead")
	profileSHA := flags.String("terrabase-profile-sha256", "", "reviewed TerraBase workload profile SHA-256")
	authProfilePath := flags.String("ts-auth-profile", "", "deprecated: optional reviewed ts-auth workload profile JSON, requires pinned service; apply ts-auth as a cell spec service instead")
	authProfileSHA := flags.String("ts-auth-profile-sha256", "", "reviewed ts-auth workload profile SHA-256")
	authServicePath := flags.String("ts-auth-service", "", "reviewed ts-auth service spec JSON; requires pinned profile")
	authServiceSHA := flags.String("ts-auth-service-sha256", "", "reviewed ts-auth service spec SHA-256")
	kvSnapshotPath := flags.String("kv-snapshot", "", "optional reviewed KV snapshot location JSON (controller.kv_snapshot)")
	kvSnapshotSHA := flags.String("kv-snapshot-sha256", "", "reviewed KV snapshot location SHA-256")
	outputPath := flags.String("out", "", "new canonical controller role JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *outputPath == "" {
		return errors.New("render-controller-config requires one new --out and no positional arguments")
	}
	withTSAuth := *authProfilePath != "" || *authProfileSHA != "" || *authServicePath != "" || *authServiceSHA != ""
	if withTSAuth && (*authProfilePath == "" || *authProfileSHA == "" || *authServicePath == "" || *authServiceSHA == "") {
		return errors.New("ts-auth requires --ts-auth-profile, --ts-auth-profile-sha256, --ts-auth-service, and --ts-auth-service-sha256 together")
	}
	candidateWire, err := readPinnedControllerFile(*candidatePath, *candidateSHA, bootstrap.MaxManifestBytes)
	if err != nil {
		return fmt.Errorf("read reviewed manifest candidate: %w", err)
	}
	var manifest bootstrap.Manifest
	if err := protocol.DecodeStrict(candidateWire, &manifest, bootstrap.MaxManifestBytes); err != nil {
		return err
	}
	if len(manifest.ControllerConfig) != 0 || len(manifest.ControllerFiles) != 0 ||
		manifest.ControllerConfigSHA256 != "" {
		return errors.New("render candidate already contains controller configuration")
	}
	recordWire, err := readPinnedControllerFile(*recordPath, *recordSHA, 1<<20)
	if err != nil {
		return fmt.Errorf("read reviewed material record: %w", err)
	}
	var record bootstrapmaterial.Record
	if err := protocol.DecodeStrict(recordWire, &record, 1<<20); err != nil {
		return err
	}
	grantWire, err := readPinnedControllerFile(*grantPath, *grantSHA, 4<<10)
	if err != nil {
		return fmt.Errorf("read reviewed operator grant: %w", err)
	}
	var grant app.TrustedSignerConfig
	if err := protocol.DecodeStrict(grantWire, &grant, 4<<10); err != nil {
		return err
	}
	canonicalGrant, err := protocol.EncodeJSON(grant)
	if err != nil || !bytes.Equal(canonicalGrant, grantWire) {
		return errors.New("operator grant must use canonical app JSON")
	}
	cfg, err := controllerConfigFromRecord(manifest, record, grant, now)
	if err != nil {
		return err
	}
	// The C# release path delivers TerraBase as a generic workload profile;
	// ValidateSignedControllerConfig below checks it as controller start does.
	if *profilePath != "" || *profileSHA != "" {
		profileWire, err := readPinnedControllerFile(*profilePath, *profileSHA, 64<<10)
		if err != nil {
			return fmt.Errorf("read reviewed TerraBase profile: %w", err)
		}
		var profile app.WorkloadProfile
		if err := protocol.DecodeStrict(profileWire, &profile, 64<<10); err != nil {
			return fmt.Errorf("decode reviewed TerraBase profile: %w", err)
		}
		if cfg.Controller.TerraBaseCACertFile == "" {
			return errors.New("a TerraBase profile needs the member CA; regenerate the controller material")
		}
		cfg.Controller.Workloads = map[string]app.WorkloadProfile{terrabase.Role: profile}
	}
	// The snapshot location is boot configuration: restore runs before any
	// KV bucket exists, so it cannot come from the cell spec.
	if *kvSnapshotPath != "" || *kvSnapshotSHA != "" {
		snapshotWire, err := readPinnedControllerFile(*kvSnapshotPath, *kvSnapshotSHA, 4<<10)
		if err != nil {
			return fmt.Errorf("read reviewed KV snapshot location: %w", err)
		}
		if err := protocol.DecodeStrict(snapshotWire, &cfg.Controller.KVSnapshot, 4<<10); err != nil {
			return fmt.Errorf("decode reviewed KV snapshot location: %w", err)
		}
		if !cfg.Controller.KVSnapshot.Enabled {
			return errors.New("a reviewed KV snapshot location must be enabled")
		}
		if err := cfg.Controller.KVSnapshot.Validate(); err != nil {
			return fmt.Errorf("reviewed KV snapshot location: %w", err)
		}
	}
	if withTSAuth {
		profileWire, err := readPinnedControllerFile(*authProfilePath, *authProfileSHA, 64<<10)
		if err != nil {
			return fmt.Errorf("read reviewed ts-auth profile: %w", err)
		}
		var profile app.WorkloadProfile
		if err := protocol.DecodeStrict(profileWire, &profile, 64<<10); err != nil {
			return fmt.Errorf("decode reviewed ts-auth profile: %w", err)
		}
		serviceWire, err := readPinnedControllerFile(*authServicePath, *authServiceSHA, 64<<10)
		if err != nil {
			return fmt.Errorf("read reviewed ts-auth service: %w", err)
		}
		var service workload.ServiceSpec
		if err := protocol.DecodeStrict(serviceWire, &service, 64<<10); err != nil {
			return fmt.Errorf("decode reviewed ts-auth service: %w", err)
		}
		if service.Role != tsauth.Role || service.Environment != manifest.Environment {
			return errors.New("reviewed ts-auth service must use role ts-auth and the candidate environment")
		}
		if cfg.Controller.Workloads == nil {
			cfg.Controller.Workloads = make(map[string]app.WorkloadProfile)
		}
		cfg.Controller.Workloads[tsauth.Role] = profile
		cfg.Controller.Autoscale = &app.AutoscaleConfig{Enabled: true, Services: []workload.ServiceSpec{service}}
	}
	wire, err := protocol.EncodeJSON(cfg)
	if err != nil || len(wire) > bootstrap.MaxControllerConfigBytes {
		return errors.New("rendered controller config exceeds signed size bound")
	}
	manifest.ControllerConfig = wire
	manifest.ControllerConfigSHA256 = controllerConfigDigest(wire)
	for index, source := range []struct{ path, digest string }{
		{*intentPath, *intentSHA}, {*regionPath, *regionSHA}, {*placementPath, *placementSHA},
	} {
		body, err := readPinnedControllerFile(source.path, source.digest, bootstrap.MaxControllerSidecarBytes)
		if err != nil {
			return fmt.Errorf("read reviewed %s: %w", bootstrap.ControllerConfigFileNames[index], err)
		}
		manifest.ControllerFiles = append(manifest.ControllerFiles, bootstrap.ControllerConfigFile{
			Name: bootstrap.ControllerConfigFileNames[index], SHA256: source.digest, Bytes: body,
		})
	}
	if _, err := app.ValidateSignedControllerConfig(manifest, ""); err != nil {
		return err
	}
	if err := c.writeNew(*outputPath, wire, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "rendered controller config slot=%s sha256=%s\n", manifest.Slot, manifest.ControllerConfigSHA256)
	return nil
}

func controllerConfigFromRecord(manifest bootstrap.Manifest, record bootstrapmaterial.Record,
	grant app.TrustedSignerConfig, now time.Time,
) (app.Config, error) {
	publicKey, keyErr := base64.StdEncoding.Strict().DecodeString(record.Public.ControllerResponsePublicKey)
	prefix, prefixErr := netip.ParsePrefix(record.Config.SubnetCIDR)
	if record.SchemaVersion != 1 || record.Config.DeploymentID != manifest.DeploymentID ||
		record.Config.ClusterID != manifest.ClusterID || record.Config.Environment != manifest.Environment ||
		record.Config.Cell != strings.ToLower(string(manifest.Cell)) || record.Config.Region != manifest.OCIRegion ||
		len(record.Config.Slots) != len(manifest.ControllerSlots) || len(record.Config.Slots) != 3 ||
		!now.Before(record.ExpiresAt) || record.IssuedAt.IsZero() ||
		keyErr != nil || len(publicKey) != ed25519.PublicKeySize ||
		prefixErr != nil || !prefix.Addr().Is4() || !prefix.Addr().IsPrivate() || prefix.Masked() != prefix {
		return app.Config{}, errors.New("reviewed material record does not match the candidate deployment")
	}
	secretFiles := make(map[string]bootstrapmaterial.File, len(record.Files))
	for _, file := range record.Files {
		if file.Name == "" || file.Name != filepath.Base(file.Name) || file.SHA256 == "" ||
			file.MaxBytes <= 0 || len(secretFiles) >= 64 {
			return app.Config{}, errors.New("reviewed material inventory is invalid")
		}
		if _, exists := secretFiles[file.Name]; exists {
			return app.Config{}, errors.New("reviewed material inventory repeats an output")
		}
		secretFiles[file.Name] = file
	}
	for _, reference := range manifest.Secrets {
		file, exists := secretFiles[reference.TargetFile]
		if !exists || file.Purpose != reference.Purpose || file.Slot != reference.Slot ||
			file.SHA256 != reference.SHA256 || file.MaxBytes != reference.MaxBytes {
			return app.Config{}, fmt.Errorf("signed material reference %s differs from reviewed source", reference.TargetFile)
		}
	}
	// Material generated before the member CA existed renders without it.
	for _, name := range []string{"terrabase-member-ca.pem", "terrabase-member-ca.key"} {
		if record.HasMemberCA() && !slices.ContainsFunc(manifest.Secrets, func(reference bootstrap.SecretReference) bool {
			return reference.TargetFile == name && reference.Purpose == bootstrap.SecretHostIssuer
		}) {
			return app.Config{}, fmt.Errorf("candidate manifest does not reference the TerraBase member CA secret %s", name)
		}
	}
	addresses := make(map[string]string, len(record.Config.Slots))
	for index, slot := range record.Config.Slots {
		address, err := netip.ParseAddr(slot.PrivateIP)
		if err != nil || slot.Name != manifest.ControllerSlots[index] || !address.Is4() || !prefix.Contains(address) ||
			address == prefix.Addr() || address == prefix.Addr().Next() || address.String() != slot.PrivateIP {
			return app.Config{}, errors.New("reviewed controller slot address or order differs from signed candidate")
		}
		if slices.ContainsFunc(record.Config.Slots[:index], func(prior bootstrapmaterial.Slot) bool {
			return prior.PrivateIP == slot.PrivateIP
		}) {
			return app.Config{}, errors.New("reviewed controller private addresses repeat")
		}
		addresses[slot.Name] = slot.PrivateIP
	}
	host, exists := addresses[manifest.Slot]
	if !exists {
		return app.Config{}, errors.New("candidate slot is absent from reviewed controller inventory")
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
	cfg := app.Config{Version: app.ConfigVersion,
		NATS: natscell.Config{Cell: record.Config.Cell, Instance: manifest.Slot, Replicas: len(record.Config.Slots),
			ClientRole: "controller", URL: "tls://" + host + ":4222", CredentialsFile: path(manifest.Slot + ".creds"),
			TLS: tls, Embedded: &natscell.Embedded{Host: host, Port: 4222, RouteHost: host, RoutePort: 6222,
				Routes: routes, StoreDir: "/var/lib/terrascale-orchestrator-controller/nats", StoreMaxBytes: 4 << 30,
				TLS: tls, RouteTLS: tls, RouteUser: "ts-route", RoutePasswordFile: path("route-password"),
				OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"),
				CellJWTFile: path("cell.jwt"), SystemCredentialsFile: path("system.creds"),
				TicketPublicKeyFile: path("ticket.pub"), BrokerIDs: slices.Clone(manifest.ControllerSlots)}},
		Controller: app.ControllerConfig{CandidateID: entityid.Derive("controller", manifest.DeploymentID, string(manifest.Cell), manifest.Slot),
			ArtifactStoreMaxBytes: 512 << 20,
			ResponseKeyFile:       path(manifest.Slot + "-response.key"), BrokerTicketKeyFile: path("ticket.key"),
			HostNATSIssuerSeedFile:      path("host-nats-issuer.seed"),
			HostTLSIssuerKeyFile:        path("host-tls-issuer-key.pem"),
			HostTLSIssuerCertFile:       path("host-tls-issuer-cert.pem"),
			HostEnrollmentListenAddress: host + ":8443",
			OciRegionIntentFile:         "/etc/terrascale-orchestrator/oci-region-intent.json",
			OciRegionConfig:             "/etc/terrascale-orchestrator/oci-region.json",
			PlacementConfig:             "/etc/terrascale-orchestrator/placement.json",
			TrustedSigners:              []app.TrustedSignerConfig{grant}},
	}
	if record.HasMemberCA() {
		cfg.Controller.TerraBaseCACertFile = path("terrabase-member-ca.pem")
		cfg.Controller.TerraBaseCAKeyFile = path("terrabase-member-ca.key")
	}
	return cfg, nil
}

func controllerConfigDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}
