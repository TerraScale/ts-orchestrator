package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func validProductionObjectFile(t *testing.T) productionDeliveryObjectStoreFile {
	t.Helper()
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(dir, "identity")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(identity, []byte("ST$instance-identity"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	return productionDeliveryObjectStoreFile{JournalBucket: "DELIVERY_PROVIDER", JournalReplicas: 3, Regions: []productionDeliveryObjectRegionFile{{Region: "gru", OCIRegion: "sa-saopaulo-1", CompartmentID: "ocid1.compartment.oc1.test", Namespace: "estate", Bucket: "releases", Endpoint: "https://objectstorage.sa-saopaulo-1.oraclecloud.com", SigningKeyIDFile: identity, SigningKeyPEMFile: keyPath}}}
}

func TestProductionDeliveryObjectAdmission(t *testing.T) {
	if err := validProductionObjectFile(t).Admit(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*productionDeliveryObjectStoreFile){
		"replica":               func(f *productionDeliveryObjectStoreFile) { f.JournalReplicas = 1 },
		"foreign endpoint":      func(f *productionDeliveryObjectStoreFile) { f.Regions[0].Endpoint = "https://attacker.example" },
		"cross region endpoint": func(f *productionDeliveryObjectStoreFile) { f.Regions[0].OCIRegion = "eu-frankfurt-1" },
		"relative key":          func(f *productionDeliveryObjectStoreFile) { f.Regions[0].SigningKeyPEMFile = "key.pem" },
		"duplicate":             func(f *productionDeliveryObjectStoreFile) { f.Regions = append(f.Regions, f.Regions[0]) },
		"bucket escape":         func(f *productionDeliveryObjectStoreFile) { f.Regions[0].Bucket = "../foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			f := validProductionObjectFile(t)
			mutate(&f)
			if f.Admit() == nil {
				t.Fatal("accepted unsafe object store configuration")
			}
		})
	}
}

func TestProductionDeliveryObjectRequiresRuntimeConnection(t *testing.T) {
	if _, err := validProductionObjectFile(t).Construct(t.Context(), nil); err == nil {
		t.Fatal("accepted missing runtime connection")
	}
}

func TestProductionDeliveryObjectRejectsStaticCredentials(t *testing.T) {
	for _, name := range []string{"missing identity", "missing key", "malformed key", "malformed identity", "symlink identity", "public key permissions"} {
		t.Run(name, func(t *testing.T) {
			f := validProductionObjectFile(t)
			r := &f.Regions[0]
			var err error
			switch name {
			case "missing identity":
				err = os.Remove(r.SigningKeyIDFile)
			case "missing key":
				err = os.Remove(r.SigningKeyPEMFile)
			case "malformed key":
				err = os.WriteFile(r.SigningKeyPEMFile, []byte("invalid"), 0600)
			case "malformed identity":
				err = os.WriteFile(r.SigningKeyIDFile, []byte("id\"bad"), 0600)
			case "symlink identity":
				p := r.SigningKeyIDFile + ".link"
				err = os.Symlink(r.SigningKeyIDFile, p)
				r.SigningKeyIDFile = p
			case "public key permissions":
				err = os.Chmod(r.SigningKeyPEMFile, 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			if f.Admit() == nil {
				t.Fatal("accepted invalid credentials during static admission")
			}
		})
	}
}
