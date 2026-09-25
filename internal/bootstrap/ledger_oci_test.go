package bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

func TestInstancePrincipalLedgerPinsCanonicalRegionAndBoundsSDKHTTP(t *testing.T) {
	privateKeyPEM := testLedgerSDKPrivateKey(t)
	tests := []struct {
		region oci.Region
		oci    string
		host   string
	}{
		{region: oci.RegionGRU, oci: "sa-saopaulo-1", host: "https://objectstorage.sa-saopaulo-1.{dualStack?ds.oci.:}oraclecloud.com"},
		{region: oci.RegionSFO, oci: "us-sanjose-1", host: "https://objectstorage.us-sanjose-1.{dualStack?ds.oci.:}oraclecloud.com"},
		{region: oci.RegionFRA, oci: "eu-frankfurt-1", host: "https://objectstorage.eu-frankfurt-1.{dualStack?ds.oci.:}oraclecloud.com"},
	}
	for _, test := range tests {
		t.Run(string(test.region), func(t *testing.T) {
			fixture := newLedgerFixture(t)
			providerCalls := 0
			providerFactory := func(region common.Region, modify func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error)) (common.ConfigurationProvider, error) {
				providerCalls++
				if region != common.Region(test.oci) {
					t.Fatalf("provider region = %q, want %q", region, test.oci)
				}
				dispatcher := &http.Client{}
				modified, err := modify(dispatcher)
				if err != nil {
					return nil, err
				}
				if modified != dispatcher || dispatcher.Timeout != instancePrincipalRequestTimeout {
					t.Fatalf("Instance Principal dispatcher was not bounded: returned=%T timeout=%s", modified, dispatcher.Timeout)
				}
				return common.NewRawConfigurationProvider(
					"ocid1.tenancy.oc1..test",
					"ocid1.user.oc1..test",
					string(region),
					"00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
					privateKeyPEM,
					nil,
				), nil
			}

			ledger, err := newInstancePrincipalLedger(test.region, fixture.ledger.config, providerFactory)
			if err != nil {
				t.Fatalf("newInstancePrincipalLedger() error = %v", err)
			}
			if providerCalls != 1 {
				t.Fatalf("provider calls = %d, want 1", providerCalls)
			}
			client, ok := ledger.client.(*objectstorage.ObjectStorageClient)
			if !ok {
				t.Fatalf("ledger client has type %T, want *objectstorage.ObjectStorageClient", ledger.client)
			}
			if client.Host != test.host {
				t.Fatalf("Object Storage host = %q, want %q", client.Host, test.host)
			}
		})
	}
}

func testLedgerSDKPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(data)
}

func TestInstancePrincipalLedgerRejectsInvalidInputBeforeProvider(t *testing.T) {
	fixture := newLedgerFixture(t)
	tests := []struct {
		name   string
		region oci.Region
		config LedgerConfig
	}{
		{name: "unsupported region", region: oci.Region("LAX"), config: fixture.ledger.config},
		{name: "invalid prefix", region: oci.RegionGRU, config: invalidLedgerPrefixConfig(fixture.ledger.config)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			providerCalled := false
			providerFactory := func(common.Region, func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error)) (common.ConfigurationProvider, error) {
				providerCalled = true
				return nil, nil
			}
			if _, err := newInstancePrincipalLedger(test.region, test.config, providerFactory); err == nil {
				t.Fatal("newInstancePrincipalLedger() succeeded with invalid input")
			}
			if providerCalled {
				t.Fatal("Instance Principal provider was created for invalid input")
			}
		})
	}
}

func invalidLedgerPrefixConfig(config LedgerConfig) LedgerConfig {
	config.Prefix = "../invalid"
	return config
}
