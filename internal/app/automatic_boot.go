package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type automaticFoundation struct {
	foundations region.FoundationResolver
	factory     *ociclient.Factory
	anchor      bootstrap.VerifiedBootstrapAnchor
	baked       bootstrapstart.BakedInputs
	imds        bootstrapstart.IMDSClient
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
