package protocol

import (
	"bytes"
	"testing"
)

func TestOpaqueValuesCopyInputAndDoNotRenderContents(t *testing.T) {
	source := []byte("not-for-logs")
	expected := append([]byte(nil), source...)
	payload := OpaquePayloadCopyFrom(source)
	digest, digestOk := PayloadDigestTryCopyFrom(source)
	signature, signatureOk := OpaqueSignatureTryCopyFrom(source)
	if !digestOk || !signatureOk {
		t.Fatal("digest and signature must copy from nonempty input")
	}

	for index := range source {
		source[index] = 0
	}

	exportedCopy := append([]byte(nil), payload.Bytes()...)
	for index := range exportedCopy {
		exportedCopy[index] = 255
	}
	digestBytes := digest.Bytes()
	digestBytes[0] = 255
	signatureBytes := signature.Bytes()
	signatureBytes[0] = 255

	if !bytes.Equal(payload.Bytes(), expected) {
		t.Fatal("payload must be an independent copy")
	}

	if !bytes.Equal(digest.Bytes(), expected) {
		t.Fatal("digest must be an independent copy")
	}

	if !bytes.Equal(signature.Bytes(), expected) {
		t.Fatal("signature must be an independent copy")
	}

	for _, rendered := range []string{payload.String(), digest.String(), signature.String()} {
		if rendered == "not-for-logs" {
			t.Fatal("opaque values must not render their contents")
		}
	}
}

func TestEmptyPayloadIsRepresentableButDigestAndSignatureAreNot(t *testing.T) {
	payload := OpaquePayloadCopyFrom(nil)
	if payload.Length() != 0 {
		t.Fatalf("length = %d", payload.Length())
	}

	if digest, ok := PayloadDigestTryCopyFrom(nil); ok || digest.IsValid() {
		t.Fatal("empty digest must be rejected")
	}

	if signature, ok := OpaqueSignatureTryCopyFrom(nil); ok || signature.IsValid() {
		t.Fatal("empty signature must be rejected")
	}
}

func TestEqualityIsContentBased(t *testing.T) {
	payloadA := OpaquePayloadCopyFrom([]byte{1, 2, 3})
	payloadB := OpaquePayloadCopyFrom([]byte{1, 2, 3})
	payloadC := OpaquePayloadCopyFrom([]byte{1, 2, 4})

	if !payloadA.Equal(payloadB) {
		t.Fatal("equal content must compare equal")
	}

	if payloadA.Equal(payloadC) {
		t.Fatal("different content must compare unequal")
	}
}
