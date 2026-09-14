package netplan

import (
	"errors"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func TestNetworkIdentityValidationRejectsUnsafeValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		limit int
		want  bool
	}{
		{name: "ordinary", value: "gru-node-1", limit: 32, want: true},
		{name: "exact bound", value: "abcd", limit: 4, want: true},
		{name: "empty", value: "", limit: 32, want: false},
		{name: "zero bound", value: "a", limit: 0, want: false},
		{name: "over bound", value: "abcde", limit: 4, want: false},
		{name: "space", value: "gru node", limit: 32, want: false},
		{name: "unicode space", value: "gru\u2003node", limit: 32, want: false},
		{name: "control", value: "gru\x7fnode", limit: 32, want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := networkValueRulesValid(test.value, test.limit); got != test.want {
				t.Fatalf("networkValueRulesValid(%q, %d) = %v, want %v", test.value, test.limit, got, test.want)
			}
		})
	}
}

func TestEveryNetworkIdentityConstructorSharesValidation(t *testing.T) {
	t.Parallel()

	constructors := []struct {
		name string
		make func(string, int) bool
	}{
		{name: "cell", make: func(v string, m int) bool { _, ok := NetworkCellIdTryCreate(v, m); return ok }},
		{name: "network", make: func(v string, m int) bool { _, ok := NetworkIdTryCreate(v, m); return ok }},
		{name: "subnet", make: func(v string, m int) bool { _, ok := NetworkSubnetIdTryCreate(v, m); return ok }},
		{name: "node", make: func(v string, m int) bool { _, ok := NetworkNodeIdTryCreate(v, m); return ok }},
		{name: "workload", make: func(v string, m int) bool { _, ok := NetworkWorkloadIdTryCreate(v, m); return ok }},
		{name: "service", make: func(v string, m int) bool { _, ok := NetworkServiceIdTryCreate(v, m); return ok }},
		{name: "endpoint", make: func(v string, m int) bool { _, ok := NetworkEndpointIdTryCreate(v, m); return ok }},
		{name: "route", make: func(v string, m int) bool { _, ok := NetworkRouteIdTryCreate(v, m); return ok }},
		{name: "peer", make: func(v string, m int) bool { _, ok := NetworkPeerIdTryCreate(v, m); return ok }},
		{name: "tunnel", make: func(v string, m int) bool { _, ok := NetworkTunnelIdTryCreate(v, m); return ok }},
		{name: "dns", make: func(v string, m int) bool { _, ok := NetworkDnsIdTryCreate(v, m); return ok }},
		{name: "load balancer", make: func(v string, m int) bool { _, ok := NetworkLoadBalancerIdTryCreate(v, m); return ok }},
		{name: "backend", make: func(v string, m int) bool { _, ok := NetworkBackendIdTryCreate(v, m); return ok }},
		{name: "certificate", make: func(v string, m int) bool { _, ok := NetworkCertificateRefTryCreate(v, m); return ok }},
		{name: "operation", make: func(v string, m int) bool { _, ok := NetworkOperationIdTryCreate(v, m); return ok }},
	}
	for _, constructor := range constructors {
		constructor := constructor
		t.Run(constructor.name, func(t *testing.T) {
			t.Parallel()
			if !constructor.make("valid-id", 32) {
				t.Fatal("valid identity rejected")
			}
			if constructor.make("invalid id", 32) {
				t.Fatal("identity containing whitespace accepted")
			}
			if constructor.make("too-long", 3) {
				t.Fatal("identity beyond maximum accepted")
			}
		})
	}
}

func TestNetworkAddressOwnsItsBytes(t *testing.T) {
	t.Parallel()

	source := []byte{10, 20, 30, 40}
	address, ok := NetworkAddressTryCreate(source)
	if !ok {
		t.Fatal("valid IPv4 address rejected")
	}
	source[0] = 99
	if got := address.Bytes()[0]; got != 10 {
		t.Fatalf("constructor retained caller storage: first byte = %d", got)
	}

	exposed := address.Bytes()
	exposed[1] = 88
	if got := address.Bytes()[1]; got != 20 {
		t.Fatalf("Bytes exposed mutable internal storage: second byte = %d", got)
	}

	if _, ok := NetworkAddressTryCreate([]byte{1, 2, 3}); ok {
		t.Fatal("three-byte address accepted")
	}
	if ipv6, ok := NetworkAddressTryCreate(make([]byte, 16)); !ok || ipv6.BitLength() != 128 {
		t.Fatalf("valid IPv6 address rejected or wrong bit length: ok=%v bits=%d", ok, ipv6.BitLength())
	}
}

func TestNetworkPrefixValidationAndRelations(t *testing.T) {
	t.Parallel()

	address, _ := NetworkAddressTryCreate([]byte{10, 0, 0, 0})
	parent, ok := NetworkPrefixTryCreate(address, 8)
	if !ok {
		t.Fatal("canonical /8 rejected")
	}
	childAddress, _ := NetworkAddressTryCreate([]byte{10, 20, 0, 0})
	child, ok := NetworkPrefixTryCreate(childAddress, 16)
	if !ok {
		t.Fatal("canonical /16 rejected")
	}
	otherAddress, _ := NetworkAddressTryCreate([]byte{11, 0, 0, 0})
	other, _ := NetworkPrefixTryCreate(otherAddress, 8)

	if !parent.Contains(child) || !parent.Overlaps(child) || child.Contains(parent) {
		t.Fatal("parent/child prefix relationship is incorrect")
	}
	if parent.Overlaps(other) || parent.Equal(other) {
		t.Fatal("disjoint prefixes reported as overlapping or equal")
	}
	hostBits, _ := NetworkAddressTryCreate([]byte{10, 0, 0, 1})
	if _, ok := NetworkPrefixTryCreate(hostBits, 24); ok {
		t.Fatal("prefix with set host bits accepted")
	}
	if _, ok := NetworkPrefixTryCreate(address, 33); ok {
		t.Fatal("IPv4 prefix longer than 32 bits accepted")
	}
}

func TestNetworkDecisionMutationClassification(t *testing.T) {
	t.Parallel()

	mutations := []NetworkAction{
		NetworkActionConfigureRoute,
		NetworkActionConfigureTunnel,
		NetworkActionRegister,
		NetworkActionDeregister,
		NetworkActionPromote,
		NetworkActionDnsUpdate,
		NetworkActionRollback,
	}
	for _, action := range mutations {
		if !((NetworkDecision{Action: action}).IsMutationAuthorized()) {
			t.Fatalf("mutation action %d was not classified as authorized", action)
		}
	}
	for _, action := range []NetworkAction{NetworkActionUninitialized, NetworkActionObserve, NetworkActionHold, NetworkActionVerify} {
		if (NetworkDecision{Action: action}).IsMutationAuthorized() {
			t.Fatalf("non-mutation action %d was classified as authorized", action)
		}
	}
}

func TestNetworkInputSnapshotCopyOwnsItsSlice(t *testing.T) {
	t.Parallel()

	if _, err := networkInputSnapshotCopy[int](nil, 2, "items"); err == nil {
		t.Fatal("nil snapshot accepted")
	} else {
		var argument *errs.Argument
		if !errors.As(err, &argument) {
			t.Fatalf("nil snapshot error type = %T, want *errs.Argument", err)
		}
		if argument.Param != "items" || argument.Error() != "Value cannot be null. (Parameter 'items')" {
			t.Fatalf("nil snapshot error = %#v", argument)
		}
	}
	if _, err := networkInputSnapshotCopy([]int{1, 2, 3}, 2, "items"); err == nil {
		t.Fatal("oversized snapshot accepted")
	} else {
		var argument *errs.Argument
		if !errors.As(err, &argument) {
			t.Fatalf("oversized snapshot error type = %T, want *errs.Argument", err)
		}
		if argument.Param != "items" || argument.Error() != "Network input exceeds the technical item limit." {
			t.Fatalf("oversized snapshot error = %#v", argument)
		}
	}
	source := []int{1, 2}
	copied, err := networkInputSnapshotCopy(source, 2, "items")
	if err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}
	source[0] = 9
	if copied[0] != 1 {
		t.Fatal("snapshot retained caller slice")
	}
}
