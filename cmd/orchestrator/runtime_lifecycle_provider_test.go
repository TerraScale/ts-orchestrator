package main

import (
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
)

func TestLifecycleEndpointAdmissionRequiresLoopback(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "loopback", value: "127.0.0.1:8421", want: true},
		{name: "ipv6 loopback", value: "[::1]:8421", want: true},
		{name: "private member", value: "10.42.0.17:8421", want: true},
		{name: "public", value: "198.51.100.1:8421"},
		{name: "missing port", value: "127.0.0.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validLifecycleEndpoint(test.value); got != test.want {
				t.Fatalf("validLifecycleEndpoint(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestLifecycleTLSAdmissionRequiresDistinctAbsoluteFiles(t *testing.T) {
	valid := placementpublisher.TLSFiles{CertificateFile: "/etc/ts/cert.pem", PrivateKeyFile: "/etc/ts/key.pem", TrustBundleFile: "/etc/ts/ca.pem"}
	if !validLifecycleTLS(valid) {
		t.Fatal("valid lifecycle TLS files rejected")
	}
	for _, mutate := range []func(*placementpublisher.TLSFiles){
		func(files *placementpublisher.TLSFiles) { files.CertificateFile = "relative.pem" },
		func(files *placementpublisher.TLSFiles) { files.PrivateKeyFile = files.CertificateFile },
		func(files *placementpublisher.TLSFiles) { files.TrustBundleFile = "/etc/ts/../ts/ca.pem" },
	} {
		candidate := valid
		mutate(&candidate)
		if validLifecycleTLS(candidate) {
			t.Fatalf("invalid lifecycle TLS files accepted: %#v", candidate)
		}
	}
}

func TestLifecycleIdentityAdmissionBindsEnvironmentAndCluster(t *testing.T) {
	want := "spiffe://terrascale.tech/production/terrabase-member/01ARZ3NDEKTSV4RRFFQ69G5FAX/01ARZ3NDEKTSV4RRFFQ69G5FAY"
	if !validLifecycleIdentity(want, "production", "01ARZ3NDEKTSV4RRFFQ69G5FAX") {
		t.Fatal("admitted lifecycle identity rejected")
	}
	if validLifecycleIdentity(want, "staging", "01ARZ3NDEKTSV4RRFFQ69G5FAX") || validLifecycleIdentity(want, "production", "foreign") {
		t.Fatal("lifecycle identity escaped deployment scope")
	}
}
