package delivery

import "testing"

func TestParseDescriptorVersions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{name: "current", content: `{"apiVersion":"terrascale.ci/v3","repository":"TerraScale/current"}`},
		{name: "unknown member", content: `{"apiVersion":"terrascale.ci/v3","schemaVersion":9,"repository":"TerraScale/current"}`, wantErr: true},
		{name: "unknown API", content: `{"apiVersion":"terrascale.ci/v4","repository":"TerraScale/current"}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := parseDescriptor([]byte(test.content))
			if (err != nil) != test.wantErr {
				t.Fatalf("parseDescriptor() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
