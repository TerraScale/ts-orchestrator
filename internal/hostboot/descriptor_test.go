package hostboot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDescriptorCanonicalBytesAndDigestAreExact(t *testing.T) {
	descriptor := testDescriptor()
	wire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes() error = %v", err)
	}
	secondWire, err := descriptor.CanonicalBytes()
	if err != nil {
		t.Fatalf("second CanonicalBytes() error = %v", err)
	}
	if !bytes.Equal(wire, secondWire) {
		t.Fatal("canonical descriptor bytes changed between calls")
	}
	wantWire := []byte(`{"schema_version":1,"cell":"gru","region":"GRU","node":"host-0123456789abcdef01234567","owner":"terrascale","fleet_generation":7,"create_key":"th-0123456789abcdef0123456789abcdef0123456789abcdef","image_id":"ocid1.image.oc1.sa-saopaulo-1.image-a","database_id":"database-a","partition_id":"partition-a","seat_id":"permanent-a","host_attempt":2,"intent_generation":9,"intent_payload_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","canonical_roster_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","managed_host_profile_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","runtime_manifest_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`)
	if !bytes.Equal(wire, wantWire) {
		t.Fatalf("CanonicalBytes() = %s, want %s", wire, wantWire)
	}
	parsed, err := Parse(wire)
	if err != nil || parsed != descriptor {
		t.Fatalf("Parse(CanonicalBytes()) = %+v, %v; want %+v", parsed, err, descriptor)
	}
	digest, err := descriptor.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	wantDigest := sha256.Sum256(wire)
	if digest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("Digest() = %q, want SHA-256 %x", digest, wantDigest)
	}
}

func TestParseRejectsUnknownSecretSmugglingFields(t *testing.T) {
	wire, err := testDescriptor().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	base := strings.TrimSuffix(string(wire), "}")
	for _, field := range []string{"instance_id", "service_url", "trust_root", "private_key", "jwt", "secret"} {
		t.Run(field, func(t *testing.T) {
			candidate := []byte(base + `,"` + field + `":"smuggled-value"}`)
			if _, err := Parse(candidate); err == nil {
				t.Fatalf("Parse() accepted unknown %q field", field)
			}
		})
	}
}

func TestDescriptorDigestChangesWithBoundAttemptAndImage(t *testing.T) {
	base := testDescriptor()
	baseDigest, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Descriptor)
	}{
		{name: "member attempt", mutate: func(descriptor *Descriptor) { descriptor.HostAttempt++ }},
		{name: "admitted intent", mutate: func(descriptor *Descriptor) { descriptor.IntentGeneration++ }},
		{name: "profile", mutate: func(descriptor *Descriptor) { descriptor.ManagedHostProfileDigest = strings.Repeat("e", 64) }},
		{name: "runtime manifest", mutate: func(descriptor *Descriptor) { descriptor.RuntimeManifestDigest = strings.Repeat("f", 64) }},
		{name: "create key", mutate: func(descriptor *Descriptor) { descriptor.CreateKey = "th-different" }},
		{name: "fleet generation", mutate: func(descriptor *Descriptor) { descriptor.FleetGeneration++ }},
		{name: "image identity", mutate: func(descriptor *Descriptor) { descriptor.ImageID = "ocid1.image.oc1.sa-saopaulo-1.image-b" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor := base
			test.mutate(&descriptor)
			got, err := descriptor.Digest()
			if err != nil {
				t.Fatalf("Digest() error = %v", err)
			}
			if got == baseDigest {
				t.Fatal("descriptor digest did not change with a bound field")
			}
		})
	}
}

func TestParseRequiresBoundedExactCanonicalV1(t *testing.T) {
	wire, err := testDescriptor().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		wire []byte
	}{
		{name: "leading whitespace", wire: append([]byte{' '}, wire...)},
		{name: "trailing newline", wire: append(bytes.Clone(wire), '\n')},
		{name: "duplicate member", wire: bytes.Replace(wire,
			[]byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)},
		{name: "oversized", wire: bytes.Repeat([]byte{'x'}, MaxDescriptorBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(test.wire); err == nil {
				t.Fatal("Parse() accepted noncanonical or out-of-bounds input")
			}
		})
	}
}

func TestDescriptorRejectsInvalidBindingsAndSecretLikeValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Descriptor)
	}{
		{name: "schema", mutate: func(descriptor *Descriptor) { descriptor.SchemaVersion++ }},
		{name: "cell region mismatch", mutate: func(descriptor *Descriptor) { descriptor.Cell = "sfo" }},
		{name: "unknown region", mutate: func(descriptor *Descriptor) { descriptor.Region = "IAD" }},
		{name: "node", mutate: func(descriptor *Descriptor) { descriptor.Node = "https://host.invalid" }},
		{name: "owner", mutate: func(descriptor *Descriptor) { descriptor.Owner = "private key" }},
		{name: "create key whitespace", mutate: func(descriptor *Descriptor) { descriptor.CreateKey = "host key" }},
		{name: "image ID", mutate: func(descriptor *Descriptor) { descriptor.ImageID = "ocid1.image.oc1..image secret" }},
		{name: "fleet generation", mutate: func(descriptor *Descriptor) { descriptor.FleetGeneration = 0 }},
		{name: "host attempt", mutate: func(descriptor *Descriptor) { descriptor.HostAttempt = 0 }},
		{name: "intent generation", mutate: func(descriptor *Descriptor) { descriptor.IntentGeneration = 0 }},
		{name: "database ID", mutate: func(descriptor *Descriptor) { descriptor.DatabaseID = "../database" }},
		{name: "partition ID", mutate: func(descriptor *Descriptor) { descriptor.PartitionID = "partition id" }},
		{name: "seat ID", mutate: func(descriptor *Descriptor) { descriptor.SeatID = "" }},
		{name: "intent digest", mutate: func(descriptor *Descriptor) { descriptor.IntentPayloadDigest = "not-a-digest" }},
		{name: "roster digest", mutate: func(descriptor *Descriptor) { descriptor.CanonicalRosterDigest = "" }},
		{name: "profile digest", mutate: func(descriptor *Descriptor) { descriptor.ManagedHostProfileDigest = strings.Repeat("A", 64) }},
		{name: "runtime manifest digest", mutate: func(descriptor *Descriptor) { descriptor.RuntimeManifestDigest = strings.Repeat("0", 63) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor := testDescriptor()
			test.mutate(&descriptor)
			if err := descriptor.Validate(); err == nil {
				t.Fatal("Validate() accepted an invalid descriptor")
			}
			if _, err := descriptor.CanonicalBytes(); err == nil {
				t.Fatal("CanonicalBytes() serialized an invalid descriptor")
			}
		})
	}
}

func testDescriptor() Descriptor {
	return Descriptor{
		SchemaVersion: SchemaVersion, Cell: "gru", Region: "GRU",
		Node: "host-0123456789abcdef01234567", Owner: "terrascale",
		CreateKey: "th-0123456789abcdef0123456789abcdef0123456789abcdef",
		ImageID:   "ocid1.image.oc1.sa-saopaulo-1.image-a", FleetGeneration: 7,
		HostAttempt: 2, IntentGeneration: 9,
		DatabaseID: "database-a", PartitionID: "partition-a", SeatID: "permanent-a",
		IntentPayloadDigest:      strings.Repeat("a", 64),
		CanonicalRosterDigest:    strings.Repeat("b", 64),
		ManagedHostProfileDigest: strings.Repeat("c", 64),
		RuntimeManifestDigest:    strings.Repeat("d", 64),
	}
}

func TestStaticDescriptorNamesOnlyACellDatabaseOrControllerServer(t *testing.T) {
	static := Static("gru", "GRU", "gru-1-db-2")
	wire, err := static.CanonicalBytes()
	if err != nil || string(wire) != `{"schema_version":2,"cell":"gru","region":"GRU","node":"gru-1-db-2"}` {
		t.Fatalf("CanonicalBytes() = %s, %v", wire, err)
	}
	if parsed, err := ParseHost(wire); err != nil || parsed != static || !parsed.IsStatic() {
		t.Fatalf("ParseHost() = %+v, %v", parsed, err)
	}
	if _, err := Parse(wire); err == nil {
		t.Fatal("managed Parse accepted a static host")
	}
	managed, err := testDescriptor().CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseHost(managed); err != nil || parsed.IsStatic() {
		t.Fatalf("ParseHost(managed) = %+v, %v", parsed, err)
	}
	if static.IsController() {
		t.Fatal("a database server descriptor names a controller")
	}
	if controller := Static("gru", "GRU", "gru-1-ctl-1"); controller.Validate() != nil || !controller.IsController() {
		t.Fatalf("controller descriptor %+v is refused or not a controller", controller)
	}
	withOwner := static
	withOwner.Owner = "terrascale"
	for _, candidate := range []Descriptor{
		Static("gru", "GRU", "gru-1-ctl-1-data"), Static("gru", "GRU", "gru-1-gw-1"), Static("gru", "GRU", "gru-1-db-1-data"),
		Static("gru", "GRU", "sfo-1-db-1"), Static("gru", "GRU", "gru-2-db-1"),
		Static("sfo", "GRU", "gru-1-db-1"), Static("gru", "GRU", "host-0123456789abcdef01234567"), withOwner,
	} {
		if err := candidate.Validate(); err == nil {
			t.Fatalf("accepted static descriptor %+v", candidate)
		}
	}
	if _, err := ParseHost([]byte(`{"schema_version":2,"cell":"gru","region":"GRU","node":"gru-1-db-2","owner":""}`)); err == nil {
		t.Fatal("ParseHost accepted a noncanonical static descriptor")
	}
}
