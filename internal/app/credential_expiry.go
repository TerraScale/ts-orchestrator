package app

import (
	"github.com/TerraScale/ts-orchestrator/internal/maintenance"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// controllerCredentialFiles lists every expiring credential file a
// controller is configured with: its NATS client and server TLS, the
// operator, account and user JWTs, the interregion or region link, and the host and
// TerraBase issuer certificates. Private keys and seeds are not listed.
func controllerCredentialFiles(cfg Config) []maintenance.CredentialFile {
	files := tlsFiles("nats client", cfg.NATS.TLS)
	files = append(files, maintenance.CredentialFile{Name: "nats client credentials", Path: cfg.NATS.CredentialsFile})
	if embedded := cfg.NATS.Embedded; embedded != nil {
		files = append(files, tlsFiles("nats server", embedded.TLS)...)
		files = append(files, tlsFiles("nats route", embedded.RouteTLS)...)
		files = append(files,
			maintenance.CredentialFile{Name: "nats operator jwt", Path: embedded.OperatorJWTFile},
			maintenance.CredentialFile{Name: "nats system account jwt", Path: embedded.SystemJWTFile},
			maintenance.CredentialFile{Name: "nats cell account jwt", Path: embedded.CellJWTFile},
			maintenance.CredentialFile{Name: "nats system credentials", Path: embedded.SystemCredentialsFile},
			maintenance.CredentialFile{Name: "nats membership credentials", Path: embedded.MembershipCredentialsFile})
		if link := embedded.InterRegion; link != nil {
			files = append(files, maintenance.CredentialFile{Name: "interregion account jwt", Path: link.AccountJWTFile})
			if link.Listen != nil {
				files = append(files, tlsFiles("interregion listen", link.Listen.TLS)...)
			}
			for _, remote := range link.Remotes {
				files = append(files, tlsFiles("interregion "+remote.Peer, remote.TLS)...)
				files = append(files, maintenance.CredentialFile{Name: "interregion " + remote.Peer + " credentials",
					Path: remote.CredentialsFile})
			}
		}
		if link := embedded.Link; link != nil {
			files = append(files, tlsFiles("region link", link.TLS)...)
			if link.CredentialsFile != "" {
				files = append(files, maintenance.CredentialFile{Name: "region link credentials", Path: link.CredentialsFile})
			}
		}
	}
	return append(files,
		maintenance.CredentialFile{Name: "host tls issuer", Path: cfg.Controller.HostTLSIssuerCertFile},
		maintenance.CredentialFile{Name: "terrabase member ca", Path: cfg.Controller.TerraBaseCACertFile})
}

func tlsFiles(name string, files natscell.TLSFiles) []maintenance.CredentialFile {
	return []maintenance.CredentialFile{{Name: name + " tls", Path: files.CertFile}, {Name: name + " ca", Path: files.CAFile}}
}
