package hostenroll

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nkeys"
)

const MaxRequestBytes = 16 << 10
const MaxResponseBytes = 32 << 10

var requestDomain = []byte("TS-HOST-ENROLL-REQUEST-V1\x00")
var responseDomain = []byte("TS-HOST-ENROLL-RESPONSE-V1\x00")

type Request struct {
	SchemaVersion     int       `json:"schema_version"`
	Operation         string    `json:"operation"`
	InstanceID        string    `json:"instance_id"`
	Descriptor        string    `json:"descriptor"`
	IdentityPublicKey string    `json:"identity_public_key"`
	NATSUserPublicKey string    `json:"nats_user_public_key"`
	CSRPEM            string    `json:"csr_pem"`
	Nonce             string    `json:"nonce"`
	IssuedAt          time.Time `json:"issued_at"`
	Signature         string    `json:"signature"`
}

func (request Request) unsignedWire() ([]byte, error) {
	request.Signature = ""
	return protocol.EncodeJSON(request)
}

func (request *Request) Sign(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("host enrollment identity key is invalid")
	}
	wire, err := request.unsignedWire()
	if err != nil {
		return err
	}
	request.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append(bytes.Clone(requestDomain), wire...)))
	return nil
}

func ParseRequest(wire []byte, now time.Time) (Request, hostboot.Descriptor, error) {
	if len(wire) == 0 || len(wire) > MaxRequestBytes {
		return Request{}, hostboot.Descriptor{}, errors.New("host enrollment request is missing or too large")
	}
	var request Request
	if err := json.Unmarshal(wire, &request, json.RejectUnknownMembers(true)); err != nil {
		return Request{}, hostboot.Descriptor{}, err
	}
	canonical, err := protocol.EncodeJSON(request)
	if err != nil || !bytes.Equal(wire, canonical) {
		return Request{}, hostboot.Descriptor{}, errors.New("host enrollment request is not canonical")
	}
	if request.SchemaVersion != 1 || request.Operation != "enroll" && request.Operation != "renew" ||
		request.InstanceID == "" || len(request.InstanceID) > 255 ||
		request.IssuedAt.IsZero() || request.IssuedAt.After(now.Add(30*time.Second)) ||
		now.Sub(request.IssuedAt) > 48*time.Hour {
		return Request{}, hostboot.Descriptor{}, errors.New("host enrollment request identity or time is invalid")
	}
	descriptor, err := hostboot.Parse([]byte(request.Descriptor))
	if err != nil {
		return Request{}, hostboot.Descriptor{}, err
	}
	identity, err := base64.StdEncoding.DecodeString(request.IdentityPublicKey)
	if err != nil || len(identity) != ed25519.PublicKeySize || !nkeys.IsValidPublicUserKey(request.NATSUserPublicKey) {
		return Request{}, hostboot.Descriptor{}, errors.New("host enrollment public keys are invalid")
	}
	nonce, err := base64.StdEncoding.DecodeString(request.Nonce)
	if err != nil || len(nonce) != 32 || len(request.CSRPEM) == 0 || len(request.CSRPEM) > 8192 {
		return Request{}, hostboot.Descriptor{}, errors.New("host enrollment nonce or CSR is invalid")
	}
	signature, err := base64.StdEncoding.DecodeString(request.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Request{}, hostboot.Descriptor{}, errors.New("host enrollment signature is invalid")
	}
	unsigned, err := request.unsignedWire()
	if err != nil || !ed25519.Verify(identity, append(bytes.Clone(requestDomain), unsigned...), signature) {
		return Request{}, hostboot.Descriptor{}, errors.New("host enrollment identity signature is invalid")
	}
	if _, err := ParseCSR(request.CSRPEM); err != nil {
		return Request{}, hostboot.Descriptor{}, err
	}
	return request, descriptor, nil
}

// ParseCSR accepts only an empty-scope P-256 CSR. The controller, not the
// requester, supplies the host DNS name and instance URI in the issued leaf.
func ParseCSR(raw string) (*x509.CertificateRequest, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return nil, errors.New("host enrollment CSR is missing or too large")
	}
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("host enrollment CSR format is invalid")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("host enrollment CSR signature is invalid")
	}
	key, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || csr.PublicKeyAlgorithm != x509.ECDSA ||
		csr.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		len(csr.Subject.Names) != 0 || csr.Subject.CommonName != "" ||
		len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 ||
		len(csr.URIs) != 0 || len(csr.EmailAddresses) != 0 ||
		len(csr.Extensions) != 0 || len(csr.ExtraExtensions) != 0 || len(csr.Attributes) != 0 {
		return nil, errors.New("host enrollment CSR requests an unsupported key or identity scope")
	}
	return csr, nil
}

func RequestSHA256(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}

type Response struct {
	SchemaVersion       int          `json:"schema_version"`
	Operation           string       `json:"operation"`
	InstanceID          string       `json:"instance_id"`
	Node                string       `json:"node"`
	DescriptorSHA256    string       `json:"descriptor_sha256"`
	RequestSHA256       string       `json:"request_sha256"`
	Nonce               string       `json:"nonce"`
	RegistrationReceipt host.Receipt `json:"registration_receipt"`
	NATSUserJWT         string       `json:"nats_user_jwt"`
	TLSCertificatePEM   string       `json:"tls_certificate_pem"`
	ExpiresAt           time.Time    `json:"expires_at"`
	Signature           string       `json:"signature"`
}

func (response Response) unsignedWire() ([]byte, error) {
	response.Signature = ""
	return protocol.EncodeJSON(response)
}

func (response *Response) Sign(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return errors.New("host enrollment response signer is invalid")
	}
	wire, err := response.unsignedWire()
	if err != nil {
		return err
	}
	response.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, append(bytes.Clone(responseDomain), wire...)))
	return nil
}

func VerifyResponse(wire []byte, public ed25519.PublicKey, request Request, requestWire []byte, descriptor hostboot.Descriptor) (Response, error) {
	if len(wire) == 0 || len(wire) > MaxResponseBytes || len(public) != ed25519.PublicKeySize {
		return Response{}, errors.New("host enrollment response is missing or too large")
	}
	var response Response
	if err := json.Unmarshal(wire, &response, json.RejectUnknownMembers(true)); err != nil {
		return Response{}, err
	}
	canonical, err := protocol.EncodeJSON(response)
	if err != nil || !bytes.Equal(canonical, wire) {
		return Response{}, errors.New("host enrollment response is not canonical")
	}
	digest, err := descriptor.Digest()
	if err != nil {
		return Response{}, err
	}
	if response.SchemaVersion != 1 || response.Operation != request.Operation || response.InstanceID != request.InstanceID ||
		response.Node != descriptor.Node || response.DescriptorSHA256 != digest ||
		response.RequestSHA256 != RequestSHA256(requestWire) || response.Nonce != request.Nonce ||
		response.RegistrationReceipt.Generation == 0 || response.RegistrationReceipt.Revision == 0 ||
		response.NATSUserJWT == "" || response.TLSCertificatePEM == "" || !time.Now().Before(response.ExpiresAt) {
		return Response{}, errors.New("host enrollment response does not bind the request or has expired")
	}
	signature, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Response{}, errors.New("host enrollment response signature is invalid")
	}
	unsigned, err := response.unsignedWire()
	if err != nil || !ed25519.Verify(public, append(bytes.Clone(responseDomain), unsigned...), signature) {
		return Response{}, fmt.Errorf("host enrollment response signature verification failed: %w", errors.New("untrusted response"))
	}
	return response, nil
}
