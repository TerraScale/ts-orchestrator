//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmqual"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

const artifactReleaseHostname = "releases.terrascale.tech"

type qualificationRuntimeServices struct {
	mu sync.Mutex

	plan           vmnet.NetworkPlan
	artifacts      []guestArtifactInput
	publicKey      ed25519.PublicKey
	manifest       []byte
	caCertificate  []byte
	tlsCertificate tls.Certificate
	resources      map[string][]byte

	timeService  *qualificationTimeService
	nats         *natsserver.Server
	httpServer   *http.Server
	httpListener net.Listener
	httpDone     chan error
	started      bool
	closed       bool
}

func newQualificationServices(config vmqual.Config, plan vmnet.NetworkPlan, architecture vmimage.Architecture) (qualificationServices, error) {
	if err := plan.Validate(); err != nil {
		return nil, fmt.Errorf("vmqual: qualification service network plan: %w", err)
	}
	if err := validateQualificationServicePlan(plan); err != nil {
		return nil, err
	}
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
		artifactPath, signaturePath := releasePaths(artifacts[index].manifest.Component, artifacts[index].manifest.Version)
		artifacts[index].manifest.Source = "https://" + artifactReleaseHostname + ":" + strconv.Itoa(int(artifactListener.Port)) + artifactPath
		resources[artifactPath] = artifacts[index].binary
		resources[signaturePath] = artifacts[index].signatureFile
	}
	manifest, err := desiredHostManifest(artifacts, artifactListener.Port)
	if err != nil {
		return nil, err
	}
	certificate, caCertificate, err := generateArtifactCertificate(time.Now().UTC())
	if err != nil {
		return nil, err
	}
	services := &qualificationRuntimeServices{
		plan: plan, artifacts: artifacts, publicKey: publicKey, manifest: manifest,
		caCertificate: caCertificate, tlsCertificate: certificate, resources: resources,
	}
	cleanupArtifacts = false
	return services, nil
}

func validateQualificationServicePlan(plan vmnet.NetworkPlan) error {
	ntp, ok := plan.Listener("ntp")
	if !ok || ntp.Protocol != vmnet.UDP || ntp.Port != 18123 || ntp.Address == "" {
		return errors.New("vmqual: required NTP listener is not the canonical UDP/18123 endpoint")
	}
	for name, port := range map[string]uint16{"nats": 4222, "artifacts": 8443, "smoke": 18080} {
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
		for name, port := range map[string]uint16{"nats": 4222, "artifacts": 8443, "smoke": 18080} {
			endpoint, ok := plan.Endpoint(region.Code, name)
			if !ok || endpoint.Protocol != vmnet.TCP || endpoint.GuestPort != port || endpoint.HostPort != port {
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
	}
	return nil
}

func releasePaths(component, version string) (string, string) {
	artifact := "/releases/" + component + "/" + version + "/" + component
	return artifact, artifact + ".sig"
}

func desiredHostManifest(artifacts []guestArtifactInput, port uint16) ([]byte, error) {
	byComponent := make(map[string]guestArtifactInput, len(artifacts))
	for _, artifact := range artifacts {
		byComponent[artifact.manifest.Component] = artifact
	}
	components := make([]hostagent.ComponentSpec, 0, 2)
	for _, name := range []string{"orchestrator", "terrabase"} {
		artifact, ok := byComponent[name]
		if !ok {
			return nil, fmt.Errorf("vmqual: signed %s artifact is missing", name)
		}
		artifactPath, signaturePath := releasePaths(name, artifact.manifest.Version)
		baseURL := "https://" + artifactReleaseHostname + ":" + strconv.Itoa(int(port))
		spec, err := hostagent.NewComponentSpec(hostagent.ComponentSpec{
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
	manifest := hostagent.HostManifest{Components: components}
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if _, err := hostagent.ParseHostManifest(data); err != nil {
		return nil, err
	}
	return data, nil
}

func generateArtifactCertificate(now time.Time) (tls.Certificate, []byte, error) {
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	defer zeroBytes(caPrivate)
	serverPublic, serverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	failed := true
	defer func() {
		if failed {
			zeroBytes(serverPrivate)
		}
	}()
	caSerial, err := certificateSerial()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serverSerial, err := certificateSerial()
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial, Subject: pkix.Name{CommonName: "TerraScale VM qualification artifact CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial, Subject: pkix.Name{CommonName: artifactReleaseHostname},
		DNSNames: []string{artifactReleaseHostname}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, serverPublic, caPrivate)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(serverDER)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if len(caPEM) == 0 {
		return tls.Certificate{}, nil, errors.New("vmqual: encode artifact CA certificate")
	}
	failed = false
	return tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverPrivate, Leaf: leaf}, caPEM, nil
}

func certificateSerial() (*big.Int, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	value[0] &= 0x7f
	value[0] |= 0x01
	return new(big.Int).SetBytes(value), nil
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
	bootstrap := vmimage.TSNodeBootstrap{
		Version: tsNode.manifest.Version, Binary: append([]byte(nil), tsNode.binary...),
		SHA256: tsNode.manifest.SHA256, Signature: append([]byte(nil), tsNode.signature...),
		ReleasePublicKey: append(ed25519.PublicKey(nil), services.publicKey...),
		Config: vmimage.TSNodeConfig{
			NodeID:            guest.ID,
			NATSURL:           "nats://" + net.JoinHostPort(natsEndpoint.GuestAddress, strconv.Itoa(int(natsEndpoint.GuestPort))),
			HeartbeatInterval: 500 * time.Millisecond, ReconcileInterval: 250 * time.Millisecond,
		},
		DesiredHostManifest:   append([]byte(nil), services.manifest...),
		ArtifactCACertificate: append([]byte(nil), services.caCertificate...),
		ArtifactHostAddress:   artifactEndpoint.GuestAddress,
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
		Handler: services.artifactHandler(artifactPlan.Port), ReadHeaderTimeout: 2 * time.Second,
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
	nats, err := natsserver.NewServer(&natsserver.Options{
		ServerName: "vmqual-" + services.plan.RunID, Host: natsPlan.Address, Port: int(natsPlan.Port),
		NoLog: true, NoSigs: true, MaxConn: 128, MaxPayload: 1 << 20,
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
	timeService, err := startQualificationTimeService(services.plan)
	if err != nil {
		nats.Shutdown()
		nats.WaitForShutdown()
		_ = services.closeHTTPLocked(ctx)
		return err
	}
	services.timeService = timeService
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

func (services *qualificationRuntimeServices) artifactHandler(port uint16) http.Handler {
	wantHost := artifactReleaseHostname + ":" + strconv.Itoa(int(port))
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.TLS == nil || request.Method != http.MethodGet || request.Host != wantHost ||
			request.URL.RawQuery != "" || request.URL.Fragment != "" || request.ContentLength > 0 ||
			request.URL.EscapedPath() != request.URL.Path {
			http.Error(response, "not found", http.StatusNotFound)
			return
		}
		data, ok := services.resources[request.URL.Path]
		if !ok {
			http.Error(response, "not found", http.StatusNotFound)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/octet-stream")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Content-Length", strconv.Itoa(len(data)))
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write(data)
	})
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
		return nil
	}
	services.closed = true
	services.started = false
	var errs []error
	if services.timeService != nil {
		errs = append(errs, services.timeService.Close())
		services.timeService = nil
	}
	if services.nats != nil {
		services.nats.Shutdown()
		services.nats.WaitForShutdown()
		services.nats = nil
	}
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

func (services *qualificationRuntimeServices) closeHTTPLocked(ctx context.Context) error {
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
	if services.httpDone != nil {
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
	if services.started || services.timeService != nil || services.nats != nil || services.httpServer != nil || services.httpListener != nil || services.httpDone != nil {
		return errors.New("vmqual: qualification listener remains active")
	}
	return nil
}

var _ qualificationServices = (*qualificationRuntimeServices)(nil)
