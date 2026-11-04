package protocol

import (
	"testing"
)

// The builders must reproduce the pre-existing wire subjects byte for byte;
// changing any of these strings is a protocol change that breaks running
// controllers, issued credentials, and the durable control log.
func TestSubjectFamiliesKeepWireFormat(t *testing.T) {
	t.Parallel()

	const key = "UDXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4"
	cases := map[string]string{
		HostRegisterSubject("gru"): "ts.orch.v1.gru.host.register",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("subject = %q, want %q", got, want)
		}
	}
	if legacy, err := GlobalControlSubject("directory-put"); err != nil || legacy != GlobalControlRequest("directory-put") {
		t.Fatalf("GlobalControlSubject = %q, %v", legacy, err)
	}
}
