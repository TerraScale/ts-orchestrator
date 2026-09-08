//go:build linux

package serviceidentityrotation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

func TestRemoteMembersRejectsRosterOutsideTrustedInventoryBeforeSending(t *testing.T) {
	trusted := []RemoteMemberEndpoint{{NodeID: "trusted", URL: "https://trusted.internal"}}
	endpointCalls, authorityCalls := 0, 0
	members, err := NewRemoteMembers(RemoteMembersConfig{
		TLS: &tls.Config{RootCAs: x509.NewCertPool(), Certificates: []tls.Certificate{{}}},
		Endpoints: func(context.Context) ([]RemoteMemberEndpoint, error) {
			endpointCalls++
			return trusted, nil
		},
		Authority: func(context.Context) (uint64, string, error) {
			authorityCalls++
			return 1, "lease", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := hostsecrets.IdentitySecretReference{SecretID: "ocid1.vaultsecret.test", VersionNumber: 1, Generation: 1}
	requested := []RemoteMemberEndpoint{{NodeID: "untrusted", URL: "https://untrusted.internal"}}
	if err := members.DeliverTo(t.Context(), requested, ref, 2, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")); err == nil {
		t.Fatal("untrusted roster was delivered")
	}
	if endpointCalls != 1 || authorityCalls != 0 {
		t.Fatalf("preflight calls: endpoints=%d authority=%d", endpointCalls, authorityCalls)
	}
}

func TestRemoteMembersRejectsIncompleteAdmittedRosterBeforeSending(t *testing.T) {
	trusted := []RemoteMemberEndpoint{
		{NodeID: "first", URL: "https://first.internal"},
		{NodeID: "second", URL: "https://second.internal"},
	}
	endpointCalls, authorityCalls := 0, 0
	members, err := NewRemoteMembers(RemoteMembersConfig{
		TLS: &tls.Config{RootCAs: x509.NewCertPool(), Certificates: []tls.Certificate{{}}},
		Endpoints: func(context.Context) ([]RemoteMemberEndpoint, error) {
			endpointCalls++
			return trusted, nil
		},
		Authority: func(context.Context) (uint64, string, error) {
			authorityCalls++
			return 1, "lease", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref := hostsecrets.IdentitySecretReference{SecretID: "ocid1.vaultsecret.test", VersionNumber: 1, Generation: 1}
	requested := []RemoteMemberEndpoint{trusted[0]}
	if err := members.DeliverTo(t.Context(), requested, ref, 2, []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")); err == nil {
		t.Fatal("incomplete admitted roster was delivered")
	}
	if endpointCalls != 1 || authorityCalls != 0 {
		t.Fatalf("preflight calls: endpoints=%d authority=%d", endpointCalls, authorityCalls)
	}
}
