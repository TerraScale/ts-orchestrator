package runmaterial

import "testing"

func TestSupportedReferencesRequireExactInventoryClosure(t *testing.T) {
	settings := map[string]string{"TS_ORCH_PRODUCTION_RUNTIME_FILE": "/etc/terrascale/runtime.json"}
	files := map[string][]byte{"/etc/terrascale/runtime.json": []byte(`{"global":{"serviceKeyFile":"/etc/terrascale/identity.key"},"host_files":{"/future/guest/file":"inline payload"}}`)}
	if ValidateReferences(settings, files) == nil {
		t.Fatal("nested runtime credential outside signed inventory accepted")
	}
	files["/etc/terrascale/identity.key"] = []byte("admitted-key")
	if err := ValidateReferences(settings, files); err != nil {
		t.Fatal(err)
	}
	files["/etc/terrascale/broker.json"] = []byte(`{"tls":{"cert_file":"/etc/terrascale/absent.pem"}}`)
	if ValidateReferences(settings, files) == nil {
		t.Fatal("nested broker TLS file outside signed inventory accepted")
	}
	delete(files, "/etc/terrascale/broker.json")
	settings["TS_ORCH_COMMAND_TRUST_KEY_FILES"] = "/etc/terrascale/identity.key:/etc/terrascale/absent.pem"
	if ValidateReferences(settings, files) == nil {
		t.Fatal("trust key list escaped signed inventory")
	}
}
