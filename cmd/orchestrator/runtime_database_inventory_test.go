package main

import "testing"

func TestDatabaseInventoryRequiresExplicitHTTPSConfiguration(t *testing.T) {
	valid := databaseInventoryFileConfig{Address: "127.0.0.1:9443", CertificateFile: "/run/inventory/cert.pem", KeyFile: "/run/inventory/key.pem", ServiceKeyFile: "/run/inventory/service-key"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"", ":9443", "127.0.0.1:0", "127.0.0.1:https", "127.0.0.1:65536"} {
		config := valid
		config.Address = address
		if config.Validate() == nil {
			t.Errorf("accepted address %q", address)
		}
	}
	config := valid
	config.ServiceKeyFile = "relative-key"
	if config.Validate() == nil {
		t.Fatal("accepted relative service credential")
	}
}
