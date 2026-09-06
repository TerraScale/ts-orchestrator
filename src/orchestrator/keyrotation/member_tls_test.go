package keyrotation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func receiverIdentity(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "member"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	k, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	trust := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	combined := append(append([]byte{}, trust...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})...)
	return combined, trust
}
func TestDynamicTLSStageActivateRollback(t *testing.T) {
	initial, trust := receiverIdentity(t)
	d, e := NewDynamicTLS(initial, trust)
	if e != nil {
		t.Fatal(e)
	}
	next, ca := receiverIdentity(t)
	q := MemberRotationRequest{OperationID: "stage", Generation: 1, Consumer: "member", Action: "stage", WorkloadTLS: next, TrustBundle: ca, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	if _, e = d.apply(q); e != nil {
		t.Fatal(e)
	}
	q.OperationID = "verify"
	q.Action = "verify"
	if _, e = d.apply(q); e != nil {
		t.Fatal(e)
	}
	before, _ := d.TLSConfig().GetConfigForClient(&tls.ClientHelloInfo{})
	q.Action = "activate"
	q.OperationID = "activate"
	if _, e = d.apply(q); e != nil {
		t.Fatal(e)
	}
	after, _ := d.TLSConfig().GetConfigForClient(&tls.ClientHelloInfo{})
	if before == after {
		t.Fatal("activation did not replace TLS configuration")
	}
	q.Action = "rollback"
	q.OperationID = "rollback"
	if _, e = d.apply(q); e != nil {
		t.Fatal(e)
	}
	restored, _ := d.TLSConfig().GetConfigForClient(&tls.ClientHelloInfo{})
	if restored != before {
		t.Fatal("rollback failed")
	}
	q.Action = "fence"
	q.OperationID = "fence"
	if _, e = d.apply(q); e != nil {
		t.Fatal(e)
	}
	if _, e = d.TLSConfig().GetConfigForClient(&tls.ClientHelloInfo{}); e == nil {
		t.Fatal("fenced TLS accepted handshake")
	}
}
func TestDynamicTLSRejectsSameGenerationDifferentMaterial(t *testing.T) {
	cert, ca := receiverIdentity(t)
	d, e := NewDynamicTLS(cert, ca)
	if e != nil {
		t.Fatal(e)
	}
	q := MemberRotationRequest{OperationID: "reload", Consumer: "control", Action: "reload", Generation: 1, ControlTLS: cert, TrustBundle: ca}
	if _, e = d.apply(q); e != nil {
		t.Fatal(e)
	}
	q.ControlTLS, q.TrustBundle = receiverIdentity(t)
	if _, e = d.apply(q); e == nil {
		t.Fatal("generation material changed")
	}
}
