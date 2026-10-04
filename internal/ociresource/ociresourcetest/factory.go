// Package ociresourcetest serves reconciler SDK tests: a signed-request
// factory and a loopback server standing in for one OCI service. No
// production binary links it.
package ociresourcetest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
)

// Region is the catalog region the test factory is pinned to.
const Region = "sa-saopaulo-1"

// Server starts handler on loopback and returns a factory and its URL. Every
// request the handler sees must be signed.
func Server(t *testing.T, handler http.HandlerFunc) (*ociclient.Factory, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..t", "ocid1.user.oc1..u", Region, "fp",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: Region})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("unsigned %s %s", r.Method, r.URL.Path)
			http.Error(w, "unsigned", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return factory, server.URL
}
