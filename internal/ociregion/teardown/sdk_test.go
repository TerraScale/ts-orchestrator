package teardown

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

func sdkProvider(t *testing.T, server *httptest.Server) *SDKProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	config := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..t", "ocid1.user.oc1..u", "sa-saopaulo-1", "fp",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(config, ociclient.Options{Region: "sa-saopaulo-1"})
	if err != nil {
		t.Fatal(err)
	}
	p := &SDKProvider{factory: factory}
	if p.vaults, err = keymanagement.NewKmsVaultClientWithConfigurationProvider(config); err != nil {
		t.Fatal(err)
	}
	if p.secrets, err = vault.NewVaultsClientWithConfigurationProvider(config); err != nil {
		t.Fatal(err)
	}
	if p.identity, err = factory.Identity(); err != nil {
		t.Fatal(err)
	}
	p.vaults.Host, p.secrets.Host, p.identity.Host = server.URL, server.URL, server.URL
	return p
}
