package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

func validProductionRecoveryFile(t *testing.T) productionRecoveryFile {
	t.Helper()
	object := validProductionObjectFile(t).Regions[0]
	object.Bucket = "control-snapshots"
	policyKey := filepath.Join(t.TempDir(), "policy.key")
	if err := os.WriteFile(policyKey, []byte(strings.Repeat("p", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	return productionRecoveryFile{PolicyEndpoint: "https://dashboard.example.com/api/internal/lifecycle/evaluate", PolicyServiceKeyFile: policyKey, Environment: "production",
		Mail:            productionRecoveryMailFile{OCIRegion: object.OCIRegion, Endpoint: "https://cell0.submit.email.sa-saopaulo-1.oci.oraclecloud.com", CompartmentID: object.CompartmentID, Sender: "orchestrator@example.com", OperatorRecipient: "operator@example.com", SigningKeyIDFile: object.SigningKeyIDFile, SigningKeyPEMFile: object.SigningKeyPEMFile},
		SnapshotRegions: []productionRecoverySnapshotRegionFile{{productionDeliveryObjectRegionFile: object, BucketResourceID: "ocid1.bucket.oc1.test", OwnershipGeneration: 1}},
		SourceRegion:    "gru", SnapshotStream: "KV_ORCH_LEADERS", SnapshotPrefix: "jetstream/control/", SnapshotMaxBytes: 64 << 20, SnapshotTimeoutSeconds: 60, ControlPlaneID: "gru-control", SampleSize: 1,
	}
}

func TestProductionRecoveryAdmission(t *testing.T) {
	if err := validProductionRecoveryFile(t).Admit(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*productionRecoveryFile){
		"missing policy key": func(f *productionRecoveryFile) { f.PolicyServiceKeyFile = "" },
		"insecure policy": func(f *productionRecoveryFile) {
			f.PolicyEndpoint = "http://dashboard.example.com/api/internal/lifecycle/evaluate"
		},
		"missing environment":    func(f *productionRecoveryFile) { f.Environment = "" },
		"foreign email endpoint": func(f *productionRecoveryFile) { f.Mail.Endpoint = "https://attacker.example" },
		"cross region email":     func(f *productionRecoveryFile) { f.Mail.OCIRegion = "eu-frankfurt-1" },
		"missing operator":       func(f *productionRecoveryFile) { f.Mail.OperatorRecipient = "" },
		"display recipient":      func(f *productionRecoveryFile) { f.Mail.OperatorRecipient = "Operator <operator@example.com>" },
		"relative key":           func(f *productionRecoveryFile) { f.Mail.SigningKeyPEMFile = "key.pem" },
		"missing source":         func(f *productionRecoveryFile) { f.SnapshotRegions = nil },
		"duplicate region":       func(f *productionRecoveryFile) { f.SnapshotRegions = append(f.SnapshotRegions, f.SnapshotRegions[0]) },
		"foreign source":         func(f *productionRecoveryFile) { f.SourceRegion = "fra" },
		"missing receipt":        func(f *productionRecoveryFile) { f.SnapshotRegions[0].OwnershipGeneration = 0 },
		"missing bucket id":      func(f *productionRecoveryFile) { f.SnapshotRegions[0].BucketResourceID = "" },
		"prefix traversal":       func(f *productionRecoveryFile) { f.SnapshotPrefix = "jetstream/../control/" },
		"wildcard stream":        func(f *productionRecoveryFile) { f.SnapshotStream = "KV_*" },
		"unbounded snapshot":     func(f *productionRecoveryFile) { f.SnapshotMaxBytes = 1 << 31 },
		"unbounded timeout":      func(f *productionRecoveryFile) { f.SnapshotTimeoutSeconds = 601 },
		"missing sample":         func(f *productionRecoveryFile) { f.SampleSize = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			f := validProductionRecoveryFile(t)
			mutate(&f)
			if f.Admit() == nil {
				t.Fatal("accepted unsafe recovery configuration")
			}
		})
	}
}

func TestProductionRecoveryAdmissionReadsActualPrivateCredentials(t *testing.T) {
	f := validProductionRecoveryFile(t)
	if err := os.WriteFile(f.Mail.SigningKeyPEMFile, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if f.Admit() == nil {
		t.Fatal("accepted malformed credential file")
	}
	f = validProductionRecoveryFile(t)
	if err := os.Chmod(f.Mail.SigningKeyPEMFile, 0644); err != nil {
		t.Fatal(err)
	}
	if f.Admit() == nil {
		t.Fatal("accepted publicly readable credential")
	}
}

func TestProductionRecoveryRequiresLiveGlobalSession(t *testing.T) {
	if _, err := validProductionRecoveryFile(t).Construct(t.Context(), globalWorkerSession{}, provider.DeliveryRegionStoreConfig{}, nil); err == nil {
		t.Fatal("accepted absent global authority")
	}
}
