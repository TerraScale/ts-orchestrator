package protocol

import (
	"strings"
	"testing"
)

func TestCommandEnvelopeWireStrictRoundtrip(t *testing.T) {
	original := validEnvelope()
	wire, err := EncodeCommandEnvelope(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCommandEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := CommandSignedMaterialCodec.Hash(&original.SignedMaterial)
	after, _ := CommandSignedMaterialCodec.Hash(&decoded.SignedMaterial)
	if before != after {
		t.Fatal("codec changed signed material")
	}
	for _, bad := range []string{strings.Replace(string(wire), `"attempt":1`, `"attempt":1,"attempt":1`, 1), strings.Replace(string(wire), `"attempt":1`, `"attempt":null`, 1), strings.Replace(string(wire), `"attempt":1`, `"Attempt":1`, 1), string(wire) + `{}`} {
		if _, err := DecodeCommandEnvelope([]byte(bad)); err == nil {
			t.Fatalf("accepted ambiguous envelope: %s", bad)
		}
	}
}
