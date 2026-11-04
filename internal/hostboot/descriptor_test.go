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
	wantWire := []byte(`{"schema_version":1,"cell":"gru","region":"GRU","node":"host-0123456789abcdef01234567","owner":"terrascale","fleet_generation":7,"create_key":"0000000000AVXGCP7NEZ0TK93A","image_id":"ocid1.image.oc1.sa-saopaulo-1.image-a","database_id":"0000000000WVSMBJNMAWCDJBSK","partition_id":"0000000000Z3WK359G2W66CVT8","seat_id":"000000000082AXF7GZQT1D126Y","host_attempt":2,"intent_generation":9,"intent_payload_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","canonical_roster_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","managed_host_profile_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","runtime_manifest_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`)
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
	for _, field := range []string{"private_key"} {
		t.Run(field, func(t *testing.T) {
			candidate := []byte(base + `,"` + field + `":"smuggled-value"}`)
			if _, err := Parse(candidate); err == nil {
				t.Fatalf("Parse() accepted unknown %q field", field)
			}
		})
	}
}

func testDescriptor() Descriptor {
	return Descriptor{
		SchemaVersion: SchemaVersion, Cell: "gru", Region: "GRU",
		Node: "host-0123456789abcdef01234567", Owner: "terrascale",
		CreateKey: "0000000000AVXGCP7NEZ0TK93A",
		ImageID:   "ocid1.image.oc1.sa-saopaulo-1.image-a", FleetGeneration: 7,
		HostAttempt: 2, IntentGeneration: 9,
		DatabaseID: "0000000000WVSMBJNMAWCDJBSK", PartitionID: "0000000000Z3WK359G2W66CVT8", SeatID: "000000000082AXF7GZQT1D126Y",
		IntentPayloadDigest:      strings.Repeat("a", 64),
		CanonicalRosterDigest:    strings.Repeat("b", 64),
		ManagedHostProfileDigest: strings.Repeat("c", 64),
		RuntimeManifestDigest:    strings.Repeat("d", 64),
	}
}
