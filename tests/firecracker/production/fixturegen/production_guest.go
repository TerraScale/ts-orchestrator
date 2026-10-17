package fixturegen

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

var simulatorDNSNames = []string{
	"auth.sa-saopaulo-1.oraclecloud.com",
	"iaas.sa-saopaulo-1.oraclecloud.com",
	"objectstorage.sa-saopaulo-1.oraclecloud.com",
}

const (
	controllerConfigGuestPath = "/etc/terrascale-orchestrator/controller.json"
	fixtureCAGuestPath        = "/usr/local/share/ca-certificates/ts-fixture-oci.crt"
	serviceSecretsGuestDir    = "/var/lib/terrascale-orchestrator-secrets"
	guestNetworkPath          = "/etc/systemd/network/20-terrascale-production.network"
	guestTimesyncPath         = "/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf"
	guestHostsPath            = "/etc/hosts"
	guestCloudDisabledPath    = "/etc/cloud/cloud-init.disabled"
	guestSSHConfigPath        = "/etc/ssh/sshd_config.d/99-terrascale-production.conf"
	fixtureGateway            = "10.44.0.1"
)

func productionNetworkFiles(privateIP string) (map[string][]byte, error) {
	address, err := netip.ParseAddr(privateIP)
	if err != nil || !address.Is4() || address.String() != privateIP ||
		!netip.MustParsePrefix("10.44.0.0/24").Contains(address) ||
		address.String() == fixtureGateway {
		return nil, errors.New("production fixture address is outside isolated bridge subnet")
	}
	return map[string][]byte{
		guestNetworkPath: []byte("[Match]\nName=eth0\n[Network]\nAddress=" + privateIP +
			"/24\n[Route]\nDestination=169.254.169.254/32\nGateway=" + fixtureGateway + "\n"),
		guestTimesyncPath: []byte("[Time]\nNTP=" + fixtureGateway +
			"\nFallbackNTP=\nRootDistanceMaxSec=1\nPollIntervalMinSec=32\nPollIntervalMaxSec=64\n"),
		guestHostsPath: []byte("127.0.0.1 localhost\n::1 localhost\n" + fixtureGateway +
			" auth.sa-saopaulo-1.oraclecloud.com iaas.sa-saopaulo-1.oraclecloud.com objectstorage.sa-saopaulo-1.oraclecloud.com\n"),
		guestCloudDisabledPath: []byte{},
		guestSSHConfigPath:     []byte("PermitRootLogin prohibit-password\nPasswordAuthentication no\nPubkeyAuthentication yes\n"),
	}, nil
}

func validateFixtureCA(wire []byte, now time.Time) error {
	if len(wire) == 0 || len(wire) > 16<<10 || now.IsZero() {
		return errors.New("fixture OCI CA is absent, oversized, or lacks a trusted clock")
	}
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("fixture OCI trust anchor must be one public certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
		now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return errors.New("fixture OCI trust anchor is not a current CA certificate")
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return fmt.Errorf("fixture OCI trust anchor is not self-signed: %w", err)
	}
	return nil
}

func validateSimulatorTLS(caPEM, certificatePEM, keyPEM []byte, now time.Time) error {
	if err := validateFixtureCA(caPEM, now); err != nil {
		return err
	}
	if len(certificatePEM) == 0 || len(certificatePEM) > 32<<10 ||
		len(keyPEM) == 0 || len(keyPEM) > 16<<10 {
		return errors.New("simulator HTTPS certificate or private key is absent or oversized")
	}
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(pair.Certificate) != 1 {
		return errors.New("simulator HTTPS certificate and private key do not form one leaf pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA {
		return errors.New("simulator HTTPS certificate is not a leaf")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("simulator HTTPS CA cannot be parsed")
	}
	for _, name := range simulatorDNSNames {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
			DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return fmt.Errorf("simulator HTTPS certificate does not cover %q: %w", name, err)
		}
	}
	return nil
}

func validateControllerConfig(wire []byte, slot, instanceOCID, privateIP string,
	observations map[string]GuestObservation, credentials map[string][]byte,
) error {
	if len(wire) == 0 || len(wire) > 1<<20 || len(observations) != 3 || len(credentials) == 0 {
		return errors.New("production controller configuration or material is absent")
	}
	var cfg app.Config
	if err := protocol.DecodeStrict(wire, &cfg, 1<<20); err != nil {
		return fmt.Errorf("decode strict controller configuration: %w", err)
	}
	if cfg.Version != app.ConfigVersion {
		return fmt.Errorf("controller configuration version must be %d, got %d", app.ConfigVersion, cfg.Version)
	}
	canonical, err := protocol.EncodeJSON(cfg)
	if err != nil || !bytes.Equal(canonical, wire) {
		return errors.New("production controller configuration is not canonical")
	}
	host := cfg.Host
	host.Roles = nil
	if !reflect.DeepEqual(host, app.HostConfig{}) || !reflect.DeepEqual(cfg.Operator, app.OperatorConfig{}) ||
		cfg.NATS.Cell != "gru" || cfg.NATS.Instance != slot ||
		cfg.NATS.Replicas != 3 || cfg.NATS.ClientRole != "controller" || cfg.NATS.Embedded == nil ||
		cfg.NATS.NKeySeedFile != "" || cfg.Controller.CandidateID != instanceOCID ||
		cfg.Controller.OciRegionConfig != "" || cfg.Controller.OciRegionIntentFile != "" ||
		cfg.Controller.PlacementConfig != "" || len(cfg.Controller.Workloads) != 0 ||
		len(cfg.Controller.TrustedSigners) != 0 {
		return errors.New("configuration is not a production GRU completed-restart controller")
	}
	address, err := netip.ParseAddr(privateIP)
	if err != nil || !address.Is4() || !address.IsPrivate() || address.String() != privateIP {
		return errors.New("controller VNIC address is not canonical private IPv4")
	}
	embedded := cfg.NATS.Embedded
	if embedded.Host != privateIP || embedded.RouteHost != privateIP ||
		embedded.Port != 4222 || embedded.RoutePort != 6222 ||
		embedded.StoreDir != "/var/lib/terrascale-orchestrator-controller/nats" ||
		embedded.StoreMaxBytes < 2<<30 || embedded.StoreMaxBytes > 8<<30 ||
		cfg.NATS.URL != "" && cfg.NATS.URL != "tls://"+privateIP+":4222" ||
		!slices.Equal(embedded.BrokerIDs, []string{"controller-a", "controller-b", "controller-c"}) ||
		len(embedded.Users) != 0 {
		return errors.New("embedded broker configuration differs from the fixed regional cell")
	}
	var routes []string
	seenAddresses := make(map[string]bool, len(observations))
	for _, peer := range []string{"controller-a", "controller-b", "controller-c"} {
		observation, ok := observations[peer]
		if !ok || observation.PrimaryPrivateIP == "" {
			return fmt.Errorf("peer %q lacks pinned private address", peer)
		}
		peerAddress, err := netip.ParseAddr(observation.PrimaryPrivateIP)
		if err != nil || !peerAddress.Is4() || !peerAddress.IsPrivate() ||
			peerAddress.String() != observation.PrimaryPrivateIP ||
			!netip.PrefixFrom(address, 24).Masked().Contains(peerAddress) {
			return fmt.Errorf("peer %q is outside the private controller subnet", peer)
		}
		if seenAddresses[observation.PrimaryPrivateIP] {
			return errors.New("controller VNIC addresses are duplicated")
		}
		seenAddresses[observation.PrimaryPrivateIP] = true
		if peer != slot {
			routes = append(routes, "nats-route://"+peerAddress.String()+":6222")
		}
	}
	if !slices.Equal(embedded.Routes, routes) {
		return errors.New("embedded broker routes differ from signed peer addresses")
	}
	paths := []string{cfg.NATS.CredentialsFile, cfg.Controller.ResponseKeyFile,
		cfg.Controller.BrokerTicketKeyFile, cfg.NATS.TLS.CAFile,
		cfg.NATS.TLS.CertFile, cfg.NATS.TLS.KeyFile,
		embedded.TLS.CAFile, embedded.TLS.CertFile, embedded.TLS.KeyFile,
		embedded.RouteTLS.CAFile, embedded.RouteTLS.CertFile, embedded.RouteTLS.KeyFile,
		embedded.OperatorJWTFile, embedded.SystemJWTFile, embedded.CellJWTFile,
		embedded.SystemCredentialsFile, embedded.TicketPublicKeyFile, embedded.RoutePasswordFile}
	seen := make(map[string]bool, len(paths))
	for _, name := range paths {
		if name == "" || filepath.Dir(name) != serviceSecretsGuestDir ||
			strings.ContainsAny(filepath.Base(name), "\\/\x00") ||
			len(credentials[filepath.Base(name)]) == 0 {
			return fmt.Errorf("controller credential path is not signed service material: %q", name)
		}
		seen[filepath.Base(name)] = true
	}
	if len(seen) != len(credentials) {
		return errors.New("signed service credential inventory contains unconfigured files")
	}
	return nil
}
