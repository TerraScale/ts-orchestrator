package vmimage

import (
	"bytes"
	"strings"
	"testing"
)

func TestNoCloudMembershipIdentityPrivateAndOwned(t *testing.T) {
	spec := validNoCloudSpec(t)
	seed, err := BuildNoCloudSeed(spec)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(seed.UserData, spec.TSNode.MembershipIdentityPrivateKey) || bytes.Contains(seed.UserData, []byte("BEGIN PRIVATE KEY")) {
		t.Fatal("membership private key leaked into UserData")
	}
	var found bool
	for _, file := range seed.RootFiles {
		if file.Path != MembershipIdentityPath {
			continue
		}
		found = true
		if file.Owner != membershipServiceUser || file.Mode != 0400 || !bytes.Equal(file.Content, spec.TSNode.MembershipIdentityPrivateKey) {
			t.Fatal("membership key has incorrect ownership, mode or content")
		}
		if err := file.Validate(); err != nil {
			t.Fatal(err)
		}
		file.Owner = "root"
		if file.Validate() == nil {
			t.Fatal("unexpected final membership key owner accepted")
		}
	}
	if !found {
		t.Fatal("membership key missing")
	}
	script := membershipOwnershipBootstrap()
	if !strings.Contains(script, "--uid 62010 --gid 62010 --no-user-group") || !strings.Contains(script, "stat -c %U:%G:%a") || !strings.Contains(script, ":400") {
		t.Fatal("bootstrap does not create and verify service ownership")
	}
}

func TestNoCloudMembershipRejectsUnboundPins(t *testing.T) {
	for _, mutation := range []func(*TSNodeBootstrap){
		func(b *TSNodeBootstrap) { b.MembershipIdentityPrivateKey = nil },
		func(b *TSNodeBootstrap) { delete(b.MembershipPins, b.Config.NodeID) },
		func(b *TSNodeBootstrap) { b.MembershipPins[b.Config.NodeID] = "invalid" },
		func(b *TSNodeBootstrap) { b.MembershipPins["peer"] = "invalid" },
	} {
		spec := validNoCloudSpec(t)
		mutation(&spec.TSNode)
		if _, err := BuildNoCloudSeed(spec); err == nil {
			t.Fatal("unbound membership identity accepted")
		}
	}
}
