package provider

import (
	"context"
	"net/http"
	"testing"
)

type fakeEstateReader map[string]string

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
		VaultID: vault, KeyID: key, KeyManagementEndpoint: "https://vault-management.kms.sa-saopaulo-1.oraclecloud.com",
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
	reader[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-ledger"] = `{"name":"terrascale-ledger","compartmentId":"` + control + `"}`
	reader[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-backups"] = `{"name":"terrascale-backups","compartmentId":"` + control + `"}`
	if err := VerifyOCIEstate(context.Background(), spec, reader); err != nil {
		t.Fatalf("valid estate rejected: %v", err)
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
			broken[string(OCIServiceObjectStorage)+"|/n/namespace/b/terrascale-ledger"] = `{"name":"another-bucket","compartmentId":"` + control + `"}`
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

var _ OCIEstateReader = fakeEstateReader{}
