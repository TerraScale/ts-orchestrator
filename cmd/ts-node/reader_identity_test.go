package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/nats-io/nkeys"
	"math/big"
	"os"
	"path/filepath"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"testing"
	"time"
)

func TestConfigurationSeparatesActualReaderIdentities(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "reader-test"}, IsCA: true, BasicConstraintsValid: true, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	issue := func(key *ecdsa.PrivateKey, serial int64) []byte {
		template := *root
		template.SerialNumber = big.NewInt(serial)
		der, err := x509.CreateCertificate(rand.Reader, &template, root, &key.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	cert := issue(rootKey, 1)
	reissued := issue(rootKey, 2)
	otherCert := issue(otherKey, 3)
	private := func(key *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	transportPair, _ := nkeys.CreateUser()
	defer transportPair.Wipe()
	readerPair, _ := nkeys.CreateUser()
	defer readerPair.Wipe()
	transportSeed, _ := transportPair.Seed()
	defer clear(transportSeed)
	readerSeed, _ := readerPair.Seed()
	defer clear(readerSeed)
	transportPublic, _ := transportPair.PublicKey()
	readerPublic, _ := readerPair.PublicKey()
	for _, name := range []string{"distinct", "copied NKey", "copied TLS", "reissued TLS same key"} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			write := func(name string, data []byte) string {
				path := filepath.Join(directory, name)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			hash := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
			selectedSeed, selectedPublic, selectedCert, selectedKey := readerSeed, readerPublic, otherCert, private(otherKey)
			switch name {
			case "copied NKey":
				selectedSeed, selectedPublic = transportSeed, transportPublic
			case "copied TLS":
				selectedCert, selectedKey = cert, private(rootKey)
			case "reissued TLS same key":
				selectedCert, selectedKey = reissued, private(rootKey)
			}
			defer clear(selectedKey)
			reader := nodeauthority.ReaderConfig{Endpoint: "tls://reader:4222", ServerName: "reader", Account: "GRU_REGIONAL", NKeySeedFile: write("reader.seed", selectedSeed), PublicNKey: selectedPublic, CAFile: write("reader-ca.pem", cert), CASHA256: hash(cert), CertificateFile: write("reader.pem", selectedCert), CertificateSHA256: hash(selectedCert), KeyFile: write("reader.key", selectedKey)}
			var config map[string]any
			if err := json.Unmarshal([]byte(minimalConfig), &config); err != nil {
				t.Fatal(err)
			}
			config["authorityReader"] = reader
			config["natsUrl"] = "tls://transport:4222"
			config["natsNkeyFile"] = write("transport.seed", transportSeed)
			config["natsTlsCaFile"] = write("transport-ca.pem", cert)
			config["natsTlsCertFile"] = write("transport.pem", cert)
			config["natsTlsKeyFile"] = write("transport.key", private(rootKey))
			raw, _ := json.Marshal(config)
			_, err := loadTsNodeConfiguration(writeConfig(t, string(raw)))
			if name == "distinct" && err != nil {
				t.Fatalf("distinct identities refused: %v", err)
			}
			if name != "distinct" && err == nil {
				t.Fatal("same public identity accepted under different paths")
			}
		})
	}
}
