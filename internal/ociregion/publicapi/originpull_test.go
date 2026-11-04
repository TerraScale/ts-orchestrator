package publicapi

import (
	"os"
	"testing"
)

func originPullFixture(t *testing.T, name string) string {
	t.Helper()
	wire, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func testOriginPull(t *testing.T) OriginPull {
	t.Helper()
	return OriginPull{CACertificate: originPullFixture(t, "origin-pull-test-ca.pem"), CertificateID: "test-origin-pull"}
}

// The fixture keys are fixed, public test data. These cannot be deployment CAs.
