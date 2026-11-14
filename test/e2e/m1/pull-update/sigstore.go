package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/url"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/tlog"
)

const inTotoPayload = "application/vnd.in-toto+json"

type testSigstore struct {
	virtual         *ca.VirtualSigstore
	root            *x509.Certificate
	intermediate    *x509.Certificate
	intermediateKey *ecdsa.PrivateKey
}

type identity struct {
	workflow string
	ref      string
	trigger  string
}

var mainIdentity = identity{workflow: "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main", ref: "refs/heads/main", trigger: "push"}

func newSigstore() *testSigstore {
	virtual, err := ca.NewVirtualSigstore()
	must(err)
	rootCert, rootKey, err := ca.GenerateRootCa()
	must(err)
	intermediate, intermediateKey, err := ca.GenerateFulcioIntermediate(rootCert, rootKey)
	must(err)
	return &testSigstore{virtual: virtual, root: rootCert, intermediate: intermediate, intermediateKey: intermediateKey}
}

func (s *testSigstore) trustedRoot() []byte {
	fulcio := &root.FulcioCertificateAuthority{Root: s.root, Intermediates: []*x509.Certificate{s.intermediate},
		ValidityPeriodStart: time.Now().Add(-time.Hour), ValidityPeriodEnd: time.Now().Add(time.Hour), URI: "https://fulcio.e2e.invalid"}
	trusted, err := root.NewTrustedRoot(root.TrustedRootMediaType01, []root.CertificateAuthority{fulcio},
		rawLogIDs(s.virtual.CTLogs()), s.virtual.TimestampingAuthorities(), rawLogIDs(s.virtual.RekorLogs()))
	must(err)
	data, err := trusted.MarshalJSON()
	must(err)
	return data
}

func rawLogIDs(logs map[string]*root.TransparencyLog) map[string]*root.TransparencyLog {
	raw := map[string]*root.TransparencyLog{}
	for id, log := range logs {
		decoded, err := hex.DecodeString(id)
		must(err)
		copied := *log
		copied.ID = decoded
		raw[id] = &copied
	}
	return raw
}

func extension(oid int, value string) pkix.Extension {
	encoded, err := asn1.MarshalWithParams(value, "utf8")
	must(err)
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, oid}, Value: encoded}
}

func (s *testSigstore) leaf(key *ecdsa.PrivateKey, who identity, sha, run string, now time.Time) *x509.Certificate {
	signer, err := url.Parse("https://github.com/" + who.workflow)
	must(err)
	repository := "https://github.com/TerraScale/ts-orchestrator"
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:         []*url.URL{signer},
		ExtraExtensions: []pkix.Extension{
			extension(8, "https://token.actions.githubusercontent.com"),
			extension(9, signer.String()),
			extension(12, repository),
			extension(13, sha),
			extension(14, who.ref),
			extension(18, signer.String()),
			extension(20, who.trigger),
			extension(21, repository+"/actions/runs/"+run+"/attempts/1"),
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, s.intermediate, key.Public(), s.intermediateKey)
	must(err)
	certificate, err := x509.ParseCertificate(der)
	must(err)
	return certificate
}

func (s *testSigstore) bundle(who identity, sha, run string, subjects map[string][]byte) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	now := time.Now()
	leaf := s.leaf(key, who, sha, run, now)
	type subject struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	}
	statement := struct {
		Type          string    `json:"_type"`
		Subject       []subject `json:"subject"`
		PredicateType string    `json:"predicateType"`
		Predicate     any       `json:"predicate"`
	}{Type: "https://in-toto.io/Statement/v1", PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: map[string]any{"buildDefinition": map[string]any{"buildType": "https://actions.github.io/buildtypes/workflow/v1"}}}
	for name, data := range subjects {
		sum := sha256.Sum256(data)
		statement.Subject = append(statement.Subject, subject{Name: name, Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])}})
	}
	payload, err := json.Marshal(statement)
	must(err)
	digest := sha256.Sum256(dsse.PAE(inTotoPayload, payload))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	must(err)
	envelope := &dsse.Envelope{PayloadType: inTotoPayload, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(signature)}}}
	entry, err := s.virtual.GenerateTlogEntry(leaf, envelope, signature, now.Unix(), true)
	must(err)
	logID, err := s.virtual.RekorLogID()
	must(err)
	logEntry := entry.TransparencyLogEntry()
	set, err := s.virtual.RekorSignPayload(tlog.RekorPayload{Body: base64.StdEncoding.EncodeToString(logEntry.CanonicalizedBody),
		IntegratedTime: now.Unix(), LogIndex: logEntry.LogIndex, LogID: logID})
	must(err)
	logEntry.InclusionPromise = &protorekor.InclusionPromise{SignedEntryTimestamp: set}
	logEntry.KindVersion = &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"}
	timestamp, err := s.virtual.TimestampResponse(signature)
	must(err)
	built, err := bundle.NewBundle(&protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content:     &protobundle.VerificationMaterial_Certificate{Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw}},
			TlogEntries: []*protorekor.TransparencyLogEntry{logEntry},
			TimestampVerificationData: &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: timestamp}}},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{Payload: payload, PayloadType: inTotoPayload,
			Signatures: []*protodsse.Signature{{Sig: signature}}}},
	})
	must(err)
	data, err := built.MarshalJSON()
	must(err)
	return data
}
