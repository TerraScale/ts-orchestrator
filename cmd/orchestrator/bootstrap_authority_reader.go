package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

func validateBootstrapAuthorityReader(seed bootstrapControlHostSeed, activation loadedControlActivation) error {
	reader := seed.AuthorityReader
	if err := reader.Validate(); err != nil {
		return err
	}
	const root = "/etc/terrascale/ts-node-authority/"
	if reader.NKeySeedFile != root+"user.seed" || reader.CAFile != root+"ca.pem" || reader.CertificateFile != root+"client.pem" || reader.KeyFile != root+"client.key" {
		return errors.New("control: authority reader paths differ from protected host contract")
	}
	for _, component := range activation.grant.Manifest.Components {
		cfg, initial, err := initialgrant.ComponentConfig(component)
		if err != nil {
			return err
		}
		if initial && cfg.AuthorityReader != reader {
			return errors.New("control: authority reader differs from owner-granted initial scope")
		}
	}
	material := map[string][]byte{}
	defer func() {
		for _, data := range material {
			clear(data)
		}
	}()
	for _, file := range seed.Files {
		private := file.Path == reader.NKeySeedFile || file.Path == reader.KeyFile
		if !private && file.Path != reader.CAFile && file.Path != reader.CertificateFile {
			continue
		}
		if _, exists := material[file.Path]; exists || file.Private != private {
			return errors.New("control: duplicate authority material or incorrect secrecy")
		}
		data, err := bootstrapcredentials.ReadFile(file.SourceFile, private, 32<<10)
		if err != nil {
			return err
		}
		material[file.Path] = data
	}
	if len(material) != 4 {
		return errors.New("control: complete distinct authority reader files are required")
	}
	for _, pin := range []struct{ path, hash string }{{reader.CAFile, reader.CASHA256}, {reader.CertificateFile, reader.CertificateSHA256}} {
		sum := sha256.Sum256(material[pin.path])
		if hex.EncodeToString(sum[:]) != pin.hash {
			return errors.New("control: authority TLS pin differs")
		}
	}
	readerTLS, err := tls.X509KeyPair(material[reader.CertificateFile], material[reader.KeyFile])
	if err != nil {
		return err
	}
	pair, err := nkeys.FromSeed(material[reader.NKeySeedFile])
	if err != nil {
		return err
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || public != reader.PublicNKey {
		return errors.New("control: authority NKey pin differs")
	}
	transport, err := bootstrapcredentials.ReadFile(seed.NATS.NKeySeedFile, true, 4096)
	if err != nil {
		return err
	}
	defer clear(transport)
	tlsTransport, err := bootstrapcredentials.ReadFile(seed.NATS.CertificateFile, false, 32<<10)
	if err != nil {
		return err
	}
	transportPair, err := nkeys.FromSeed(bytes.TrimSpace(transport))
	if err != nil {
		return errors.New("control: transport NKey is invalid")
	}
	defer transportPair.Wipe()
	transportPublic, err := transportPair.PublicKey()
	if err != nil {
		return errors.New("control: transport NKey is invalid")
	}
	block, _ := pem.Decode(tlsTransport)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("control: transport TLS certificate is invalid")
	}
	transportCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("control: transport TLS certificate is invalid")
	}
	readerCert, err := x509.ParseCertificate(readerTLS.Certificate[0])
	if err != nil {
		return errors.New("control: reader TLS certificate is invalid")
	}
	if public == transportPublic || bytes.Equal(readerCert.RawSubjectPublicKeyInfo, transportCert.RawSubjectPublicKeyInfo) {
		return errors.New("control: authority identity must differ from transport")
	}
	return nil
}
