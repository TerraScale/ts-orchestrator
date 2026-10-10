package ocicost

import (
	"bytes"
	"strings"
	"testing"
)

// The CLI's network path needs an OCI tenancy, so these tests cover only the
// arguments, which fail before any call leaves the process.
func TestCostCLIArguments(t *testing.T) {
	for _, test := range []struct {
		args      []string
		want      string
		wantError bool
	}{
		{args: nil, want: "Usage: ts-orch cost report --region <cell>"},
		{args: []string{"--help"}, want: "Usage: ts-orch cost report"},
		{args: []string{"help"}, want: "Usage: ts-orch cost report"},
		{args: []string{"help"}, want: "ts-orch cost tag --region <cell> --compartment <ocid>"},
		{args: []string{"report", "--help"}, want: "cell token"},
		{args: []string{"report"}, want: "needs --region", wantError: true},
		{args: []string{"report", "--region", "gru", "extra"}, want: "no positional arguments", wantError: true},
		{args: []string{"report", "--region", "nowhere"}, want: "unsupported TerraScale region", wantError: true},
		{args: []string{"forecast"}, want: "unknown cost command", wantError: true},
		{args: []string{"tag", "--help"}, want: "compartment OCID to tag"},
		{args: []string{"tag"}, want: "needs --region", wantError: true},
		{args: []string{"tag", "--region", "gru"}, want: "needs at least one --compartment", wantError: true},
		{args: []string{"tag", "--region", "gru", "--compartment", "ocid1.compartment.oc1..aaa' || 1 = 1"},
			want: "not a compartment OCID", wantError: true},
		{args: []string{"tag", "--region", "gru", "--compartment", testCompartmentA, "extra"},
			want: "no positional arguments", wantError: true},
		{args: []string{"tag", "--region", "nowhere", "--compartment", testCompartmentA},
			want: "unsupported TerraScale region", wantError: true},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			var output bytes.Buffer
			err := Run(t.Context(), test.args, &output)
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("error = %v, want %q", err, test.want)
				}
				if output.Len() != 0 {
					t.Fatalf("failed command wrote data: %q", output.String())
				}
			} else if err != nil || !strings.Contains(output.String(), test.want) {
				t.Fatalf("output = %q, error = %v", output.String(), err)
			}
		})
	}
}
