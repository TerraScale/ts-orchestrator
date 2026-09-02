package provider

import (
	"context"
	"net/http"
	"os"
	"testing"
)

type fakeEstateReader map[string]string

type deadlineCheckingEstateReader struct {
	Reader fakeEstateReader
	Seen   bool
}

func (r *deadlineCheckingEstateReader) Read(ctx context.Context, service OCIService, path string) ([]byte, int, error) {
	if _, ok := ctx.Deadline(); ok {
		r.Seen = true
	}
	return r.Reader.Read(ctx, service, path)
}

func (f fakeEstateReader) Read(_ context.Context, service OCIService, path string) ([]byte, int, error) {
	body, ok := f[string(service)+"|"+path]
	if !ok {
		return nil, http.StatusNotFound, nil
	}
	return []byte(body), http.StatusOK, nil
}

func cloneFakeEstateReader(source fakeEstateReader) fakeEstateReader {
	cloned := make(fakeEstateReader, len(source))
	for path, body := range source {
		cloned[path] = body
	}
	return cloned
}

func TestEstateVerifierRejectsMalformedManualEstate(t *testing.T) {
	control := "ocid1.compartment.oc1.control"
	network := "ocid1.compartment.oc1.network"
	workload := "ocid1.compartment.oc1.workload"
	vcn := "ocid1.vcn.oc1.x"
	subnets := []string{"ocid1.subnet.oc1.a", "ocid1.subnet.oc1.b", "ocid1.subnet.oc1.c"}
	nsgs := []string{"ocid1.networksecuritygroup.oc1.a", "ocid1.networksecuritygroup.oc1.b", "ocid1.networksecuritygroup.oc1.c"}
	vault := "ocid1.vault.oc1.x"
	key := "ocid1.key.oc1.x"
	policy := "ocid1.policy.oc1.x"
	statement := "Allow dynamic-group terrascale-orchestrator to manage instances in compartment terrascale-workload"
	spec := OCIEstateSpec{
		Region: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1.x",
		ControlCompartmentID: control, NetworkCompartmentID: network, WorkloadCompartmentID: workload,
		VCNID: vcn, SubnetIDs: subnets, NetworkSecurityGroupIDs: nsgs,
		IAMPolicyCompartmentID: control, IAMPolicies: []OCIEstatePolicy{{ID: policy, Statements: []string{statement}}},
		VaultID: vault, KeyID: key, KeyManagementEndpoint: "https://ocid1.vault.oc1.sa-saopaulo-1.x.management.kms.sa-saopaulo-1.oci.oraclecloud.com",
		ObjectNamespace: "namespace", LedgerBucket: "terrascale-ledger", BackupBucket: "terrascale-backups",
	}
	reader := fakeEstateReader{}
	for _, compartment := range []string{control, network, workload} {
		reader[string(OCIServiceIdentity)+"|/20160918/compartments/"+compartment] = `{"id":"` + compartment + `","compartmentId":"` + spec.TenancyID + `","lifecycleState":"ACTIVE"}`
	}
	reader[string(OCIServiceCore)+"|/20160918/vcns/"+vcn] = `{"id":"` + vcn + `","compartmentId":"` + network + `","lifecycleState":"AVAILABLE"}`
	for _, subnet := range subnets {
		reader[string(OCIServiceCore)+"|/20160918/subnets/"+subnet] = `{"id":"` + subnet + `","compartmentId":"` + network + `","vcnId":"` + vcn + `","lifecycleState":"AVAILABLE","prohibitPublicIpOnVnic":true}`
	}
	for _, nsg := range nsgs {
		reader[string(OCIServiceCore)+"|/20160918/networkSecurityGroups/"+nsg] = `{"id":"` + nsg + `","compartmentId":"` + network + `","vcnId":"` + vcn + `","lifecycleState":"AVAILABLE"}`
	}
	reader[string(OCIServiceIdentity)+"|/20160918/policies/"+policy] = `{"id":"` + policy + `","compartmentId":"` + control + `","lifecycleState":"ACTIVE","statements":["` + statement + `"]}`
	reader[string(OCIServiceVault)+"|/20180608/vaults/"+vault] = `{"id":"` + vault + `","compartmentId":"` + control + `","lifecycleState":"ACTIVE"}`
	reader[string(OCIServiceVaultManagement)+"|/20180608/keys/"+key] = `{"id":"` + key + `","compartmentId":"` + control + `","lifecycleState":"ENABLED"}`
	bucketMetadata := `,"publicAccessType":"NoPublicAccess","versioning":"Enabled","kmsKeyId":"` + key + `","retentionRules":[{"duration":{"timeAmount":30,"timeUnit":"DAYS"},"timeRuleLocked":"2026-08-30T12:00:00Z"}]`
	reader[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-ledger"] = `{"name":"terrascale-ledger","compartmentId":"` + control + `"` + bucketMetadata + `}`
	reader[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-backups"] = `{"name":"terrascale-backups","compartmentId":"` + control + `"` + bucketMetadata + `}`
	checkedReader := &deadlineCheckingEstateReader{Reader: reader}
	if err := VerifyOCIEstate(context.Background(), spec, checkedReader); err != nil {
		t.Fatalf("valid estate rejected: %v", err)
	}
	if !checkedReader.Seen {
		t.Fatal("estate verification did not install a startup-wide deadline")
	}
	duplicateCompartmentSpec := spec
	duplicateCompartmentSpec.NetworkCompartmentID = duplicateCompartmentSpec.ControlCompartmentID
	if validateOCIEstateSpec(duplicateCompartmentSpec) == nil {
		t.Fatal("estate accepted duplicate control and network compartments")
	}

	tests := []struct {
		name   string
		mutate func(fakeEstateReader)
	}{
		{"wrong compartment parent", func(broken fakeEstateReader) {
			broken[string(OCIServiceIdentity)+"|/20160918/compartments/"+control] = `{"id":"` + control + `","compartmentId":"ocid1.tenancy.oc1.wrong","lifecycleState":"ACTIVE"}`
		}},
		{"wrong subnet VCN", func(broken fakeEstateReader) {
			broken[string(OCIServiceCore)+"|/20160918/subnets/"+subnets[0]] = `{"id":"` + subnets[0] + `","compartmentId":"` + network + `","vcnId":"ocid1.vcn.oc1.wrong","lifecycleState":"AVAILABLE","prohibitPublicIpOnVnic":true}`
		}},
		{"wrong NSG VCN", func(broken fakeEstateReader) {
			broken[string(OCIServiceCore)+"|/20160918/networkSecurityGroups/"+nsgs[0]] = `{"id":"` + nsgs[0] + `","compartmentId":"` + network + `","vcnId":"ocid1.vcn.oc1.wrong","lifecycleState":"AVAILABLE"}`
		}},
		{"public subnet", func(broken fakeEstateReader) {
			broken[string(OCIServiceCore)+"|/20160918/subnets/"+subnets[0]] = `{"id":"` + subnets[0] + `","compartmentId":"` + network + `","vcnId":"` + vcn + `","lifecycleState":"AVAILABLE","prohibitPublicIpOnVnic":false}`
		}},
		{"policy drift", func(broken fakeEstateReader) {
			broken[string(OCIServiceIdentity)+"|/20160918/policies/"+policy] = `{"id":"` + policy + `","compartmentId":"` + control + `","lifecycleState":"ACTIVE","statements":["Allow any-user to manage all-resources in tenancy"]}`
		}},
		{"wrong Vault compartment", func(broken fakeEstateReader) {
			broken[string(OCIServiceVault)+"|/20180608/vaults/"+vault] = `{"id":"` + vault + `","compartmentId":"` + workload + `","lifecycleState":"ACTIVE"}`
		}},
		{"missing bucket", func(broken fakeEstateReader) {
			delete(broken, string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-backups")
		}},
		{"wrong bucket", func(broken fakeEstateReader) {
			broken[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-ledger"] = `{"name":"another-bucket","compartmentId":"` + control + `"` + bucketMetadata + `}`
		}},
		{"public bucket", func(broken fakeEstateReader) {
			broken[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-ledger"] = `{"name":"terrascale-ledger","compartmentId":"` + control + `","publicAccessType":"ObjectRead","versioning":"Enabled","kmsKeyId":"` + key + `","retentionRules":[{"duration":{"timeAmount":30,"timeUnit":"DAYS"},"timeRuleLocked":"2026-08-30T12:00:00Z"}]}`
		}},
		{"unencrypted bucket", func(broken fakeEstateReader) {
			broken[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-ledger"] = `{"name":"terrascale-ledger","compartmentId":"` + control + `","publicAccessType":"NoPublicAccess","versioning":"Enabled","retentionRules":[{"duration":{"timeAmount":30,"timeUnit":"DAYS"},"timeRuleLocked":"2026-08-30T12:00:00Z"}]}`
		}},
		{"unversioned bucket", func(broken fakeEstateReader) {
			broken[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-ledger"] = `{"name":"terrascale-ledger","compartmentId":"` + control + `","publicAccessType":"NoPublicAccess","versioning":"Disabled","kmsKeyId":"` + key + `","retentionRules":[{"duration":{"timeAmount":30,"timeUnit":"DAYS"},"timeRuleLocked":"2026-08-30T12:00:00Z"}]}`
		}},
		{"missing retention", func(broken fakeEstateReader) {
			broken[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-ledger"] = `{"name":"terrascale-ledger","compartmentId":"` + control + `","publicAccessType":"NoPublicAccess","versioning":"Enabled","kmsKeyId":"` + key + `","retentionRules":[]}`
		}},
		{"unlocked retention", func(broken fakeEstateReader) {
			broken[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-ledger"] = `{"name":"terrascale-ledger","compartmentId":"` + control + `","publicAccessType":"NoPublicAccess","versioning":"Enabled","kmsKeyId":"` + key + `","retentionRules":[{"duration":{"timeAmount":30,"timeUnit":"DAYS"}}]}`
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broken := cloneFakeEstateReader(reader)
			test.mutate(broken)
			if err := VerifyOCIEstate(context.Background(), spec, broken); err == nil {
				t.Fatal("malformed estate passed startup verification")
			}
		})
	}
}

func TestLoadOCIEstateSpecRejectsBroadFilePermissions(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "estate-*.json")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if _, err := file.WriteString(`{}`); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOCIEstateSpec(path); err == nil {
		t.Fatal("world-readable estate file was accepted")
	}
}

var _ OCIEstateReader = fakeEstateReader{}
