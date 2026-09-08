//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualartifact"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"

	natsserver "github.com/nats-io/nats-server/v2/server"
	natsclient "github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/hostcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

const artifactReleaseHostname = "releases.terrascale.tech"

type qualificationRuntimeServices struct {
	mu               sync.Mutex
	bootstrapIssuer  *vmqualbootstrap.Issuer
	controlSeeds     map[string]vmcontrolseed.Material
	engineSeeds      map[string]*vmengineconfig.Material
	runAdmissions    map[string]vmcontrolseed.RunAdmission
	runMaterials     map[string]*vmcontrolseed.RunMaterial
	controlAdmission *qualificationControlAdmission

	plan           vmnet.NetworkPlan
	artifacts      []guestArtifactInput
	publicKey      ed25519.PublicKey
	manifest       []byte
	caCertificate  []byte
	tlsCertificate tls.Certificate
	resources      map[string][]byte

	natsAuthority       *qualificationNATSAuthority
	controlConnections  []*natsclient.Conn
	controlSigners      []*security.CommandSignatureSigner
	controlClients      map[string]*hostcontrol.Client
	controlRegions      []bootstrap.ControlRegionBinding
	controlRuntime      bootstrap.ControlRuntime
	controlSource       QualificationControlRuntimeSource
	controlReady        map[string]bool
	controlConfigure    sync.Once
	controlConfigureErr error
	natsStoreParent     *os.Root
	natsStoreName       string
	natsStoreRunID      string
	stateRoot           string
	backup              *qualificationBackupFixture
	timeService         *qualificationTimeService
	nats                *natsserver.Server
	httpServer          *http.Server
	httpListener        net.Listener
	httpDone            chan error
	started             bool
	closed              bool
}

// SetQualificationControlRuntimeSource installs the admitted guest producer
// used when the final declared guest reaches the ready transition.
func (services *qualificationRuntimeServices) SetQualificationControlRuntimeSource(source QualificationControlRuntimeSource) error {
	if services == nil || source == nil {
		return bootstrap.ErrControlRuntimeUnavailable
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.closed || services.controlSource != nil || len(services.controlReady) != 0 {
		return bootstrap.ErrControlRuntimeUnavailable
	}
	services.controlSource = source
	return nil
}

func newQualificationServices(config vmqual.Config, plan vmnet.NetworkPlan, architecture vmimage.Architecture) (qualificationServices, error) {
	if err := plan.Validate(); err != nil {
		return nil, fmt.Errorf("vmqual: qualification service network plan: %w", err)
	}
	if err := validateQualificationServicePlan(plan); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(config.StateRoot) || filepath.Clean(config.StateRoot) != config.StateRoot {
		return nil, errors.New("vmqual: durable qualification admission requires an absolute owned state root")
	}
	admissionDirectory := filepath.Join(config.StateRoot, "qualification-admission-"+plan.RunID)
	artifacts, publicKey, err := loadProductionArtifacts(config, architecture)
	if err != nil {
		return nil, err
	}
	cleanupArtifacts := true
	defer func() {
		if cleanupArtifacts {
			zeroArtifactInputs(artifacts)
			zeroBytes(publicKey)
		}
	}()
	artifactListener, _ := plan.Listener("artifacts")
	resources := make(map[string][]byte, len(artifacts)*2)
	for index := range artifacts {
		artifactPath, signaturePath := vmqualartifact.ReleasePaths(artifacts[index].manifest.Component, artifacts[index].manifest.Version)
		artifacts[index].manifest.Source = "https://" + artifactReleaseHostname + ":" + strconv.Itoa(int(artifactListener.Port)) + artifactPath
		resources[artifactPath] = artifacts[index].binary
		resources[signaturePath] = artifacts[index].signature
	}
	manifest, err := desiredHostManifest(artifacts, artifactListener.Port)
	if err != nil {
		return nil, err
	}
	var engineSeeds map[string]*vmengineconfig.Material
	if config.TerraBaseDeclarationFile != "" {
		bindings := launchEngineBindings(plan)
		for _, artifact := range artifacts {
			if artifact.manifest.Component == "terrabase" {
				engineSeeds, err = vmengineconfig.Load(config.TerraBaseDeclarationFile, artifact.manifest.SHA256, artifact.manifest.Version, bindings)
				if err != nil {
					return nil, err
				}
			}
		}
		defer func() {
			if cleanupArtifacts {
				for _, seed := range engineSeeds {
					seed.Clear()
				}
			}
		}()
	}
	certificate, caCertificate, err := vmqualartifact.GenerateCertificate(artifactReleaseHostname, time.Now().UTC(), backupFixtureHostname)
	if err != nil {
		return nil, err
	}
	certificate, caCertificate, err = persistQualificationArtifactTLS(admissionDirectory, plan.RunID, certificate, caCertificate)
	if err != nil {
		return nil, err
	}
	authority, err := newQualificationNATSAuthority(plan)
	if err != nil {
		return nil, err
	}
	var controlAdmission *qualificationControlAdmission
	if config.QualificationControlDeclarationFile != "" {
		artifactPins := make(map[string]vmimage.GuestArtifact, len(artifacts))
		for _, artifact := range artifacts {
			artifactPins[artifact.manifest.Component] = artifact.manifest
		}
		controlAdmission, err = loadQualificationControlDeclaration(config.QualificationControlDeclarationFile, plan, architecture, artifactPins)
		if err != nil {
			authority.close()
			return nil, err
		}
		defer func() {
			if cleanupArtifacts {
				controlAdmission.Clear()
			}
		}()
		for host, identity := range controlAdmission.memberships {
			if previous := authority.memberships[host]; previous != nil {
				clear(previous.PrivatePEM)
			}
			copy := *identity
			copy.PrivatePEM = bytes.Clone(identity.PrivatePEM)
			authority.memberships[host] = &copy
		}
	}
	authority, err = persistQualificationAuthority(admissionDirectory, plan, authority)
	if err != nil {
		return nil, err
	}
	if controlAdmission != nil {
		for host, identity := range controlAdmission.memberships {
			if authority.memberships[host] == nil || authority.memberships[host].PublicKey != identity.PublicKey {
				authority.close()
				return nil, errors.New("vmqual: declared membership differs from durable initial admission")
			}
		}
	}
	var candidates []vmcontrolseed.Guest
	for _, region := range plan.Regions {
		if string(region.Code) != "GRU" {
			continue
		}
		for _, guest := range region.Guests {
			membership := authority.memberships[guest.ID]
			if membership == nil {
				authority.close()
				return nil, errors.New("vmqual: declared GRU membership identity missing")
			}
			candidates = append(candidates, vmcontrolseed.Guest{ID: guest.ID, Address: guest.Address, MembershipPublicKey: membership.PublicKey})
		}
	}
	var publication *vmcontrolseed.PreliminaryPublicationDeclaration
	if config.PreliminaryPublicationFile != "" {
		if config.PreliminaryCaptureMaxSnapshotBytes == 0 || config.PreliminaryCaptureMaxTotalBytes == 0 {
			authority.close()
			return nil, errors.New("vmqual: publication requires explicit preliminary capture")
		}
		publication, err = vmcontrolseed.LoadPreliminaryPublicationDeclaration(config.PreliminaryPublicationFile)
		if err != nil {
			authority.close()
			return nil, err
		}
		defer publication.Clear()
	}
	controlSeeds, err := vmcontrolseed.LoadOrCreateGRU(admissionDirectory, plan.RunID, candidates, func() (map[string]vmcontrolseed.Material, error) {
		if config.PreliminaryCaptureMaxSnapshotBytes != 0 || config.PreliminaryCaptureMaxTotalBytes != 0 {
			return vmcontrolseed.GenerateGRUWithPreliminaryCapture(plan.RunID, candidates, vmcontrolseed.PreliminaryCaptureDeclaration{MaxSnapshotBytes: config.PreliminaryCaptureMaxSnapshotBytes, MaxTotalBytes: config.PreliminaryCaptureMaxTotalBytes, Publication: publication})
		}
		return vmcontrolseed.GenerateGRU(plan.RunID, candidates)
	})
	if err != nil {
		authority.close()
		return nil, err
	}
	bootstrapIssuer, err := vmqualbootstrap.NewPersistentIssuer(admissionDirectory, plan.RunID)
	if err != nil {
		for _, seed := range controlSeeds {
			seed.Clear()
		}
		authority.close()
		return nil, err
	}
	services := &qualificationRuntimeServices{
		plan: plan, artifacts: artifacts, publicKey: publicKey, manifest: manifest, controlSeeds: controlSeeds, engineSeeds: engineSeeds,
		caCertificate: caCertificate, tlsCertificate: certificate, resources: resources,
		natsAuthority: authority, stateRoot: config.StateRoot, bootstrapIssuer: bootstrapIssuer,
	}
	services.controlAdmission = controlAdmission
	if controlAdmission != nil {
		services.controlSource = controlAdmission.source
	}
	if config.QualificationRunDeclarationFile != "" {
		declaration, loadErr := vmcontrolseed.LoadRunDeclaration(config.QualificationRunDeclarationFile)
		if loadErr != nil {
			_ = services.Close(context.Background())
			return nil, loadErr
		}
		services.runAdmissions = make(map[string]vmcontrolseed.RunAdmission, len(declaration.Hosts))
		for _, admission := range declaration.Hosts {
			if _, owned := services.controlSeeds[admission.HostID]; !owned {
				_ = services.Close(context.Background())
				return nil, errors.New("vmqual: run declaration contains an unowned initial controller")
			}
			services.runAdmissions[admission.HostID] = admission
		}
		if len(services.runAdmissions) != len(services.controlSeeds) {
			_ = services.Close(context.Background())
			return nil, errors.New("vmqual: run declaration omits an initial controller")
		}
	}
	services.backup, err = loadQualificationBackup(config.TerraBaseDeclarationFile)
	if err != nil {
		_ = services.Close(context.Background())
		return nil, err
	}
	cleanupArtifacts = false
	return services, nil
}

// launchEngineBindings excludes the reserved fourth-Region fault network.
func launchEngineBindings(plan vmnet.NetworkPlan) []vmengineconfig.Binding {
	var bindings []vmengineconfig.Binding
	for _, region := range plan.Regions {
		// The full suite reserves IAD networking for a later expansion
		// scenario. It is not part of the initial engine placement.
		if region.Code == vmqual.FourthRegion {
			continue
		}
		for _, guest := range region.Guests {
			bindings = append(bindings, vmengineconfig.Binding{NodeID: guest.ID, Region: string(region.Code), Address: guest.Address})
		}
	}
	return bindings
}

func validateQualificationServicePlan(plan vmnet.NetworkPlan) error {
	ntp, ok := plan.Listener("ntp")
	if !ok || ntp.Protocol != vmnet.UDP || ntp.Port != 18123 || ntp.Address == "" {
		return errors.New("vmqual: required NTP listener is not the canonical UDP/18123 endpoint")
	}
	for name, port := range map[string]uint16{"nats": 4222, "artifacts": 8443, "smoke": 18080, "backup": 19443} {
		listener, ok := plan.Listener(name)
		if !ok || listener.Protocol != vmnet.TCP || listener.Port != port || listener.Address == "" {
			return fmt.Errorf("vmqual: required %s listener is not the canonical TCP/%d endpoint", name, port)
		}
	}
	for _, region := range plan.Regions {
		ntp, ok := plan.Endpoint(region.Code, "ntp")
		if !ok || ntp.Protocol != vmnet.UDP || ntp.GuestPort != 123 || ntp.HostPort != 18123 {
			return fmt.Errorf("vmqual: Region %s lacks the canonical NTP endpoint", region.Code)
		}
		for name, port := range map[string]uint16{"nats": 4222, "artifacts": 8443, "smoke": 18080, "backup": 443} {
			endpoint, ok := plan.Endpoint(region.Code, name)
			hostPort := port
			if name == "backup" {
				hostPort = 19443
			}
			if !ok || endpoint.Protocol != vmnet.TCP || endpoint.GuestPort != port || endpoint.HostPort != hostPort {
				return fmt.Errorf("vmqual: Region %s lacks the canonical %s endpoint", region.Code, name)
			}
		}
		records := plan.RegionDNSRecords(region.Code)
		matched := false
		for _, record := range records {
			if record.Name == artifactReleaseHostname && record.Type == "A" && record.Address == region.Gateway {
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("vmqual: Region %s lacks the artifact release DNS mapping", region.Code)
		}
		matched = false
		for _, record := range records {
			if record.Name == "fly.storage.tigris.dev" && record.Type == "A" && record.Address == region.Gateway {
				matched = true
			}
		}
		if !matched {
			return fmt.Errorf("vmqual: Region %s lacks the backup provider DNS mapping", region.Code)
		}
	}
	return nil
}

func desiredHostManifest(artifacts []guestArtifactInput, port uint16) ([]byte, error) {
	byComponent := make(map[string]guestArtifactInput, len(artifacts))
	for _, artifact := range artifacts {
		byComponent[artifact.manifest.Component] = artifact
	}
	components := make([]hostmanifest.ComponentSpec, 0, 2)
	for _, name := range []string{"orchestrator", "terrabase"} {
		artifact, ok := byComponent[name]
		if !ok {
			return nil, fmt.Errorf("vmqual: signed %s artifact is missing", name)
		}
		artifactPath, signaturePath := vmqualartifact.ReleasePaths(name, artifact.manifest.Version)
		baseURL := "https://" + artifactReleaseHostname + ":" + strconv.Itoa(int(port))
		spec, err := hostmanifest.NewComponentSpec(hostmanifest.ComponentSpec{
			Name: name, Version: artifact.manifest.Version,
			ArtifactURL: baseURL + artifactPath, SignatureURL: baseURL + signaturePath,
			Sha256: artifact.manifest.SHA256, User: "terrascale-" + name,
			DataVolume: "/var/lib/terrascale/" + name,
			CPUWeight:  100, MemoryMaxBytes: 128 << 20, IOWeight: 100,
		})
		if err != nil {
			return nil, fmt.Errorf("vmqual: desired %s component: %w", name, err)
		}
		components = append(components, spec)
	}
	manifest := hostmanifest.HostManifest{Components: components}
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if _, err := hostmanifest.ParseHostManifest(data); err != nil {
		return nil, err
	}
	return data, nil
}

func (services *qualificationRuntimeServices) Bootstrap(guest vmqual.Guest) (vmimage.TSNodeBootstrap, []vmimage.GuestArtifact, error) {
	if services == nil {
		return vmimage.TSNodeBootstrap{}, nil, errors.New("vmqual: qualification services are missing")
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.closed {
		return vmimage.TSNodeBootstrap{}, nil, errors.New("vmqual: qualification services are closed")
	}
	if string(guest.Region) != "GRU" {
		if services.controlAdmission != nil {
			return services.bootstrapCandidate(guest)
		}
		return vmimage.TSNodeBootstrap{}, nil, errors.New("vmqual: non-GRU bootstrap requires admitted allocation and controller configuration")
	}
	controlSeed, ok := services.controlSeeds[guest.ID]
	if !ok {
		return vmimage.TSNodeBootstrap{}, nil, errors.New("vmqual: declared GRU controller configuration missing")
	}
	natsEndpoint, ok := services.plan.Endpoint(guest.Region, "nats")
	if !ok {
		return vmimage.TSNodeBootstrap{}, nil, fmt.Errorf("vmqual: Region %s has no NATS endpoint", guest.Region)
	}
	artifactEndpoint, ok := services.plan.Endpoint(guest.Region, "artifacts")
	if !ok {
		return vmimage.TSNodeBootstrap{}, nil, fmt.Errorf("vmqual: Region %s has no artifact endpoint", guest.Region)
	}
	var tsNode guestArtifactInput
	seedArtifacts := make([]vmimage.GuestArtifact, 0, len(services.artifacts))
	for _, artifact := range services.artifacts {
		seedArtifacts = append(seedArtifacts, artifact.manifest)
		if artifact.manifest.Component == "ts-node" {
			tsNode = artifact
		}
	}
	if len(tsNode.binary) == 0 || len(tsNode.signature) != ed25519.SignatureSize {
		return vmimage.TSNodeBootstrap{}, nil, errors.New("vmqual: signed ts-node bootstrap is missing")
	}
	if services.natsAuthority == nil {
		return vmimage.TSNodeBootstrap{}, nil, errors.New("vmqual: guest NATS authority missing")
	}
	identity := services.natsAuthority.guests[guest.ID]
	if identity == nil {
		return vmimage.TSNodeBootstrap{}, nil, errors.New("vmqual: guest lacks provisioned NATS identity")
	}
	membership := services.natsAuthority.memberships[guest.ID]
	if membership == nil {
		return vmimage.TSNodeBootstrap{}, nil, errors.New("vmqual: membership identity not provisioned")
	}
	pins := make(map[string]string, len(services.natsAuthority.memberships))
	for host := range services.controlSeeds {
		pins[host] = services.natsAuthority.memberships[host].PublicKey
	}
	commandTrust, err := services.natsAuthority.commandTrust(services.plan, guest.Region)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	if services.bootstrapIssuer == nil {
		return vmimage.TSNodeBootstrap{}, nil, errors.New("vmqual: initial grant issuer is missing")
	}
	baseManifest := services.manifest
	engineSeed := services.engineSeeds[guest.ID]
	if engineSeed != nil {
		base, err := hostmanifest.ParseHostManifest(baseManifest)
		if err != nil {
			return vmimage.TSNodeBootstrap{}, nil, err
		}
		base, err = engineSeed.Apply(base)
		if err != nil {
			return vmimage.TSNodeBootstrap{}, nil, err
		}
		baseManifest, err = hostmanifest.CanonicalHostManifestJSON(base)
		if err != nil {
			return vmimage.TSNodeBootstrap{}, nil, err
		}
	}
	desired, err := controlSeed.LaunchManifest(baseManifest)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	runMaterial := services.runMaterials[guest.ID]
	if admission, admitted := services.runAdmissions[guest.ID]; admitted && runMaterial == nil {
		base, err := hostmanifest.ParseHostManifest(baseManifest)
		if err != nil {
			return vmimage.TSNodeBootstrap{}, nil, err
		}
		membershipPins, err := json.Marshal(pins)
		if err != nil {
			return vmimage.TSNodeBootstrap{}, nil, err
		}
		dependencies := map[string][]byte{vmcontrolseed.MembershipKeyPath: bytes.Clone(membership.PrivatePEM), vmcontrolseed.MembershipPinsPath: membershipPins}
		defer func() {
			for _, raw := range dependencies {
				clear(raw)
			}
		}()
		if engineSeed != nil {
			for _, files := range []map[string][]byte{engineSeed.ControlFiles(), engineSeed.DatabaseFiles()} {
				for path, raw := range files {
					if previous, exists := dependencies[path]; exists {
						if !bytes.Equal(previous, raw) {
							return vmimage.TSNodeBootstrap{}, nil, errors.New("vmqual: run admission has conflicting staged dependencies")
						}
						clear(previous)
					}
					dependencies[path] = raw
				}
			}
		}
		runMaterial, err = controlSeed.RunManifest(base, admission, dependencies)
		if err != nil {
			return vmimage.TSNodeBootstrap{}, nil, err
		}
		if services.runMaterials == nil {
			services.runMaterials = make(map[string]*vmcontrolseed.RunMaterial)
		}
		services.runMaterials[guest.ID] = runMaterial
	}
	if runMaterial != nil {
		if err := runMaterial.ValidateStage(controlSeed, desired); err != nil {
			return vmimage.TSNodeBootstrap{}, nil, err
		}
	}
	if engineSeed != nil {
		var stageErr error
		if runMaterial == nil {
			stageErr = engineSeed.ValidateManifest(guest.ID, engineSeed.Address(), desired)
		} else {
			stageErr = engineSeed.ValidateStagedManifest(guest.ID, engineSeed.Address(), desired, runMaterial.Manifest)
		}
		if stageErr != nil {
			return vmimage.TSNodeBootstrap{}, nil, fmt.Errorf("vmqual: initial/run manifest admission: %w", stageErr)
		}
	}
	manifest, err := hostmanifest.CanonicalHostManifestJSON(desired)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	initialGrant, err := services.bootstrapIssuer.Grant(guest.ID, desired)
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	controlSeed = controlSeed.Clone()
	reader, err := controlSeed.AuthorityReader()
	if err != nil {
		return vmimage.TSNodeBootstrap{}, nil, err
	}
	bootstrap := vmimage.TSNodeBootstrap{
		Engine:                       engineSeed.Clone(),
		Controller:                   &controlSeed,
		ControllerRun:                runMaterial.Clone(),
		InitialGrant:                 &vmimage.TSNodeInitialGrant{PublicKeyPEM: initialGrant.PublicKeyPEM, SignedGrant: initialGrant.SignedGrant},
		MembershipIdentityPrivateKey: append([]byte(nil), membership.PrivatePEM...), MembershipPins: pins,
		Version: tsNode.manifest.Version, Binary: append([]byte(nil), tsNode.binary...),
		SHA256: tsNode.manifest.SHA256, Signature: append([]byte(nil), tsNode.signature...),
		ReleasePublicKey: append(ed25519.PublicKey(nil), services.publicKey...),
		Config: vmimage.TSNodeConfig{AuthorityReader: reader,
			AuthorityBucket: "ORCH_LEADERS", CommandTrustKeys: commandTrust,
			NodeID:  guest.ID,
			NATSURL: "tls://" + net.JoinHostPort(natsEndpoint.GuestAddress, strconv.Itoa(int(natsEndpoint.GuestPort))),
			// Match the production ts-node cadences. Reauthenticating complete
			// releases at subsecond intervals distorts idle CPU and status contention.
			HeartbeatInterval: 10 * time.Second, ReconcileInterval: 30 * time.Second,
		},
		DesiredHostManifest:   manifest,
		ArtifactCACertificate: append([]byte(nil), services.caCertificate...),
		ArtifactHostAddress:   artifactEndpoint.GuestAddress,
		NATSIdentity:          &vmimage.TSNodeNATSIdentity{NKeySeed: append([]byte(nil), identity.seed...), TLSCA: append([]byte(nil), services.natsAuthority.ca...), TLSCertificate: append([]byte(nil), identity.certificate...), TLSPrivateKey: append([]byte(nil), identity.privateKey...)},
	}
	return bootstrap, seedArtifacts, nil
}

func (services *qualificationRuntimeServices) Start(ctx context.Context) error {
	if services == nil {
		return errors.New("vmqual: qualification services are missing")
	}
	if ctx == nil {
		return errors.New("vmqual: qualification service context is nil")
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.closed {
		return errors.New("vmqual: qualification services are closed")
	}
	if services.started {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	artifactPlan, _ := services.plan.Listener("artifacts")
	artifactAddress := net.JoinHostPort(artifactPlan.Address, strconv.Itoa(int(artifactPlan.Port)))
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", artifactAddress)
	if err != nil {
		return fmt.Errorf("vmqual: bind artifact listener: %w", err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{services.tlsCertificate}}
	server := &http.Server{
		Handler: vmqualartifact.Handler(artifactReleaseHostname, artifactPlan.Port, services.resources), ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	done := make(chan error, 1)
	tlsListener := tls.NewListener(listener, tlsConfig)
	go func() { done <- server.Serve(tlsListener) }()
	services.httpServer, services.httpListener, services.httpDone = server, listener, done
	if err := services.probeArtifactTLS(ctx, artifactAddress); err != nil {
		_ = listener.Close()
		<-done
		services.httpServer, services.httpListener, services.httpDone = nil, nil, nil
		return err
	}

	natsPlan, _ := services.plan.Listener("nats")
	if services.natsAuthority == nil {
		_ = services.closeHTTPLocked(ctx)
		return errors.New("vmqual: NATS authentication authority missing")
	}
	storeDir, err := services.prepareNATSStore(ctx)
	if err != nil {
		_ = services.closeHTTPLocked(ctx)
		return err
	}
	nats, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "vmqual-" + services.plan.RunID, Host: natsPlan.Address, Port: int(natsPlan.Port),
		NoLog: true, NoSigs: true, MaxConn: 128, MaxPayload: 4 << 20,
		JetStream: true, StoreDir: storeDir, JetStreamMaxMemory: 8 << 20, JetStreamMaxStore: 64 << 20,
		Nkeys:     services.natsAuthority.users,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{services.natsAuthority.server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: services.natsAuthority.roots},
	})
	if err != nil {
		_ = services.closeHTTPLocked(ctx)
		return fmt.Errorf("vmqual: configure embedded NATS: %w", err)
	}
	nats.Start()
	if !nats.ReadyForConnections(5 * time.Second) {
		nats.Shutdown()
		nats.WaitForShutdown()
		_ = services.closeHTTPLocked(ctx)
		return errors.New("vmqual: embedded NATS did not bind the planned listener")
	}
	bound, ok := nats.Addr().(*net.TCPAddr)
	if !ok || bound.IP.String() != natsPlan.Address || bound.Port != int(natsPlan.Port) {
		nats.Shutdown()
		nats.WaitForShutdown()
		_ = services.closeHTTPLocked(ctx)
		return errors.New("vmqual: embedded NATS bound outside the planned listener")
	}
	if err := services.probeNATSController(ctx, nats.ClientURL()); err != nil {
		nats.Shutdown()
		nats.WaitForShutdown()
		_ = services.closeHTTPLocked(ctx)
		return err
	}
	timeService, err := startQualificationTimeService(services.plan)
	if err != nil {
		nats.Shutdown()
		nats.WaitForShutdown()
		_ = services.closeHTTPLocked(ctx)
		return err
	}
	services.timeService = timeService
	if err := services.startBackup(ctx); err != nil {
		_ = timeService.Close()
		services.timeService = nil
		nats.Shutdown()
		nats.WaitForShutdown()
		_ = services.closeHTTPLocked(ctx)
		return err
	}
	services.nats, services.started = nats, true
	return nil
}

func (services *qualificationRuntimeServices) probeArtifactTLS(ctx context.Context, address string) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(services.caCertificate) {
		return errors.New("vmqual: generated artifact CA could not be loaded")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dialer := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: artifactReleaseHostname}}
	connection, err := dialer.DialContext(probeCtx, "tcp4", address)
	if err != nil {
		return fmt.Errorf("vmqual: prove artifact TLS listener: %w", err)
	}
	return connection.Close()
}

func (services *qualificationRuntimeServices) Close(ctx context.Context) error {
	if services == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.closed {
		return services.removeNATSStore()
	}
	services.closed = true
	if services.controlAdmission != nil {
		services.controlAdmission.Clear()
		services.controlAdmission = nil
	}
	for _, seed := range services.controlSeeds {
		seed.Clear()
	}
	services.controlSeeds = nil
	for _, material := range services.runMaterials {
		material.Clear()
	}
	services.runMaterials, services.runAdmissions = nil, nil
	for _, seed := range services.engineSeeds {
		seed.Clear()
	}
	services.engineSeeds = nil
	services.started = false
	if services.bootstrapIssuer != nil {
		_ = services.bootstrapIssuer.Close()
		services.bootstrapIssuer = nil
	}
	var errs []error
	if services.timeService != nil {
		errs = append(errs, services.timeService.Close())
		services.timeService = nil
	}
	for _, connection := range services.controlConnections {
		connection.Close()
	}
	services.controlConnections = nil
	for _, signer := range services.controlSigners {
		errs = append(errs, signer.Close())
	}
	services.controlSigners = nil
	services.controlClients = nil
	if services.nats != nil {
		services.nats.Shutdown()
		services.nats.WaitForShutdown()
		services.nats = nil
	}
	if services.natsAuthority != nil {
		services.natsAuthority.close()
		services.natsAuthority = nil
	}
	errs = append(errs, services.removeNATSStore())
	if err := services.closeHTTPLocked(context.WithoutCancel(ctx)); err != nil {
		errs = append(errs, err)
	}
	if privateKey, ok := services.tlsCertificate.PrivateKey.(ed25519.PrivateKey); ok {
		zeroBytes(privateKey)
	}
	services.tlsCertificate = tls.Certificate{}
	zeroArtifactInputs(services.artifacts)
	zeroBytes(services.publicKey)
	zeroBytes(services.manifest)
	zeroBytes(services.caCertificate)
	services.artifacts, services.publicKey, services.manifest, services.caCertificate = nil, nil, nil, nil
	services.resources = nil
	return errors.Join(errs...)
}

func (services *qualificationRuntimeServices) closeHTTPLocked(ctx context.Context) (result error) {
	defer func() { result = errors.Join(result, services.backup.close(ctx)) }()
	if services.httpServer == nil {
		return nil
	}
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	shutdownErr := services.httpServer.Shutdown(shutdownCtx)
	if shutdownErr != nil && services.httpListener != nil {
		_ = services.httpListener.Close()
	}
	var serveErr error
	if services.httpDone != nil || services.natsStoreParent != nil {
		select {
		case serveErr = <-services.httpDone:
		case <-shutdownCtx.Done():
			serveErr = shutdownCtx.Err()
		}
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	services.httpServer, services.httpListener, services.httpDone = nil, nil, nil
	return errors.Join(shutdownErr, serveErr)
}

func (services *qualificationRuntimeServices) VerifyStopped() error {
	if services == nil {
		return nil
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if (services.backup != nil && (services.backup.server != nil || services.backup.store != nil)) || services.started || services.timeService != nil || services.nats != nil || services.httpServer != nil || services.httpListener != nil || services.httpDone != nil || services.natsStoreParent != nil {
		return errors.New("vmqual: qualification listener remains active")
	}
	return nil
}

var _ qualificationServices = (*qualificationRuntimeServices)(nil)

// prepareNATSStore creates only the current run's private fixture store. An
// existing store requires cleanup rather than silently reusing another run.
func (services *qualificationRuntimeServices) prepareNATSStore(ctx context.Context) (string, error) {
	if !filepath.IsAbs(services.stateRoot) || filepath.Clean(services.stateRoot) != services.stateRoot {
		return "", errors.New("vmqual: NATS store requires owned state root")
	}
	if services.natsStoreRunID != "" || services.natsStoreParent != nil {
		return "", errors.New("vmqual: NATS fixture store already prepared")
	}
	runID, bound := vmqual.RunIDFromContext(ctx)
	if !bound {
		var err error
		runID, err = vmqual.NewRunID()
		if err != nil {
			return "", err
		}
	}
	path, err := vmqual.PrepareNATSFixtureStore(ctx, services.stateRoot, runID)
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(services.stateRoot)
	if err != nil {
		return "", err
	}
	name := filepath.Base(path)
	services.natsStoreParent, services.natsStoreName, services.natsStoreRunID = root, name, runID
	return filepath.Join(services.stateRoot, name), nil
}

func (services *qualificationRuntimeServices) removeNATSStore() error {
	if services.natsStoreParent == nil {
		return nil
	}
	if err := vmqual.RemoveNATSFixtureStore(services.stateRoot, services.natsStoreRunID); err != nil {
		return err
	}
	err := services.natsStoreParent.Close()
	services.natsStoreParent = nil
	services.natsStoreName = ""
	services.natsStoreRunID = ""
	return err
}

// DataDriveBytes declares the seed's full broker capacity before guest boot.
func (services *qualificationRuntimeServices) DataDriveBytes(guest vmqual.Guest) (int64, error) {
	services.mu.Lock()
	defer services.mu.Unlock()
	seed, ok := services.controlSeeds[guest.ID]
	if !ok {
		return 64 << 20, nil
	}
	return seed.DataDriveBytes()
}
