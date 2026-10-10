package app

import (
	"slices"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

// The expiry scan covers every certificate and JWT a controller runs with
// and never opens a private key or seed.
func TestControllerCredentialFilesListOnlyPublicMaterial(t *testing.T) {
	tls := func(prefix string) natscell.TLSFiles {
		return natscell.TLSFiles{CAFile: prefix + "-ca.pem", CertFile: prefix + "-cert.pem", KeyFile: prefix + "-key.pem"}
	}
	cfg := Config{NATS: natscell.Config{TLS: tls("client"), NKeySeedFile: "client.seed", CredentialsFile: "client.creds",
		Embedded: &natscell.Embedded{TLS: tls("server"), RouteTLS: tls("route"), OperatorJWTFile: "operator.jwt",
			SystemJWTFile: "system.jwt", CellJWTFile: "cell.jwt", SystemCredentialsFile: "system.creds",
			MembershipCredentialsFile: "membership.creds", RoutePasswordFile: "route-password",
			InterRegion: &natscell.InterRegion{AccountJWTFile: "interregion.jwt",
				Listen:  &natscell.LeafListen{TLS: tls("leaf")},
				Remotes: []natscell.LeafRemote{{Peer: "iad", CredentialsFile: "iad.creds", TLS: tls("iad")}}}}},
		Controller: ControllerConfig{HostTLSIssuerCertFile: "host-issuer-cert.pem", HostTLSIssuerKeyFile: "host-issuer-key.pem",
			HostNATSIssuerSeedFile: "host-issuer.seed", TerraBaseCACertFile: "terrabase-ca.pem", TerraBaseCAKeyFile: "terrabase-ca.key",
			ResponseKeyFile: "response.key"}}
	var paths []string
	for _, file := range controllerCredentialFiles(cfg) {
		paths = append(paths, file.Path)
	}
	for _, want := range []string{"client-cert.pem", "client-ca.pem", "client.creds", "server-cert.pem", "route-ca.pem",
		"operator.jwt", "system.jwt", "cell.jwt", "system.creds", "membership.creds", "interregion.jwt", "leaf-cert.pem",
		"iad-cert.pem", "iad.creds", "host-issuer-cert.pem", "terrabase-ca.pem"} {
		if !slices.Contains(paths, want) {
			t.Errorf("scan misses %s", want)
		}
	}
	for _, path := range paths {
		if strings.Contains(path, "key") || strings.Contains(path, "0000000000SF1REEJJX6TC691V") || strings.Contains(path, "password") {
			t.Errorf("scan opens secret %s", path)
		}
	}
}
