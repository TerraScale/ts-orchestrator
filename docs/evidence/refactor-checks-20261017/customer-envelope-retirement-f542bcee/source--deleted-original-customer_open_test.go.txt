package managedmaterial

import (
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestOpenCustomerEnvelopeUsesProducerWireAndRecipient(t *testing.T) {
	spec, signer, recipient := initialFixture(t)
	bundle, err := GenerateInitial(spec, signer, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	material, err := OpenCustomerEnvelope(spec, bundle.Customer, recipient)
	if err != nil || material.Version != 1 || !strings.HasPrefix(material.Token, "tbk1.") ||
		!strings.Contains(material.HTTPSCAPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("producer customer envelope did not open: %v", err)
	}
	wrong, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCustomerEnvelope(spec, bundle.Customer, wrong); err == nil {
		t.Fatal("different recipient key opened customer envelope")
	}
	tampered := bundle.Customer
	first := "A"
	if strings.HasPrefix(tampered.Ciphertext, first) {
		first = "B"
	}
	tampered.Ciphertext = first + tampered.Ciphertext[1:]
	if _, err := OpenCustomerEnvelope(spec, tampered, recipient); err == nil {
		t.Fatal("tampered customer ciphertext opened")
	}
	otherSpec := spec
	otherSpec.PartitionID = "00000000001WFHC56Q8NB0X6T8"
	if _, err := OpenCustomerEnvelope(otherSpec, bundle.Customer, recipient); err == nil {
		t.Fatal("different preparation context opened customer envelope")
	}
}
