package main

import (
	"context"
	"crypto"
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
	"encoding/pem"
	"math/big"
	"net/url"
	"slices"
	"time"

	"github.com/digitorus/timestamp"
	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/types"
	rekordsse "github.com/sigstore/rekor/pkg/types/dsse"
	dssev001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const inTotoPayload = "application/vnd.in-toto+json"

type testSigstore struct {
	fulcioRoot      *x509.Certificate
	intermediate    *x509.Certificate
	intermediateKey *ecdsa.PrivateKey
	tsaRoot         *x509.Certificate
	tsaLeaf         *x509.Certificate
	tsaKey          *ecdsa.PrivateKey
	rekorKey        *ecdsa.PrivateKey
	logID           []byte
	ctKey           *ecdsa.PrivateKey
	ctLogID         []byte
}

type identity struct {
	workflow string
	ref      string
	trigger  string
	unlogged bool
}

var mainIdentity = identity{workflow: "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main", ref: "refs/heads/main", trigger: "push"}

func key() *ecdsa.PrivateKey {
	generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	return generated
}

func certificate(template, parent *x509.Certificate, public *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	if parent == nil {
		parent = template
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	must(err)
	parsed, err := x509.ParseCertificate(der)
	must(err)
	return parsed
}

func authority(name string, serial int64) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name, Organization: []string{"e2e"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true, IsCA: true}
}

func newSigstore() *testSigstore {
	s := &testSigstore{intermediateKey: key(), tsaKey: key(), rekorKey: key(), ctKey: key()}
	rootKey, tsaRootKey := key(), key()
	s.fulcioRoot = certificate(authority("e2e fulcio root", 1), nil, &rootKey.PublicKey, rootKey)
	intermediate := authority("e2e fulcio intermediate", 2)
	intermediate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	s.intermediate = certificate(intermediate, s.fulcioRoot, &s.intermediateKey.PublicKey, rootKey)
	s.tsaRoot = certificate(authority("e2e tsa root", 3), nil, &tsaRootKey.PublicKey, tsaRootKey)
	usage, err := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	must(err)
	s.tsaLeaf = certificate(&x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "e2e tsa"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: usage}}},
		s.tsaRoot, &s.tsaKey.PublicKey, tsaRootKey)
	public, err := x509.MarshalPKIXPublicKey(&s.rekorKey.PublicKey)
	must(err)
	sum := sha256.Sum256(public)
	s.logID = sum[:]
	public, err = x509.MarshalPKIXPublicKey(&s.ctKey.PublicKey)
	must(err)
	sum = sha256.Sum256(public)
	s.ctLogID = sum[:]
	return s
}

func (s *testSigstore) trustedRoot() []byte {
	start, end := time.Now().Add(-time.Hour), time.Now().Add(2*time.Hour)
	fulcio := &root.FulcioCertificateAuthority{Root: s.fulcioRoot, Intermediates: []*x509.Certificate{s.intermediate},
		ValidityPeriodStart: start, ValidityPeriodEnd: end, URI: "https://fulcio.e2e.invalid"}
	tsa := &root.SigstoreTimestampingAuthority{Root: s.tsaRoot, Leaf: s.tsaLeaf, URI: "https://tsa.e2e.invalid",
		ValidityPeriodStart: start, ValidityPeriodEnd: end}
	logs := map[string]*root.TransparencyLog{hex.EncodeToString(s.logID): {BaseURL: "https://rekor.e2e.invalid", ID: s.logID,
		ValidityPeriodStart: start, ValidityPeriodEnd: end, HashFunc: crypto.SHA256, PublicKey: &s.rekorKey.PublicKey, SignatureHashFunc: crypto.SHA256}}
	ctlogs := map[string]*root.TransparencyLog{hex.EncodeToString(s.ctLogID): {BaseURL: "https://ctfe.e2e.invalid", ID: s.ctLogID,
		ValidityPeriodStart: start, ValidityPeriodEnd: end, HashFunc: crypto.SHA256, PublicKey: &s.ctKey.PublicKey, SignatureHashFunc: crypto.SHA256}}
	trusted, err := root.NewTrustedRoot(root.TrustedRootMediaType01, []root.CertificateAuthority{fulcio},
		ctlogs, []root.TimestampingAuthority{tsa}, logs)
	must(err)
	data, err := trusted.MarshalJSON()
	must(err)
	return data
}

func extension(oid int, value string) pkix.Extension {
	encoded, err := asn1.MarshalWithParams(value, "utf8")
	must(err)
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, oid}, Value: encoded}
}

func (s *testSigstore) leaf(signing *ecdsa.PrivateKey, who identity, sha, run string, now time.Time) *x509.Certificate {
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
	if who.unlogged {
		return certificate(template, s.intermediate, &signing.PublicKey, s.intermediateKey)
	}
	logged := template.ExtraExtensions
	template.ExtraExtensions = append(slices.Clone(logged), pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, Critical: true, Value: asn1.NullBytes})
	precertificate := certificate(template, s.intermediate, &signing.PublicKey, s.intermediateKey)
	template.ExtraExtensions = append(logged, s.timestampList(precertificate, now))
	return certificate(template, s.intermediate, &signing.PublicKey, s.intermediateKey)
}

func (s *testSigstore) timestampList(precertificate *x509.Certificate, now time.Time) pkix.Extension {
	tbs, err := ctx509.BuildPrecertTBS(precertificate.RawTBSCertificate, nil)
	must(err)
	sct := ct.SignedCertificateTimestamp{SCTVersion: ct.V1, LogID: ct.LogID{KeyID: [32]byte(s.ctLogID)}, Timestamp: uint64(now.UnixMilli())}
	leaf := ct.MerkleTreeLeaf{Version: ct.V1, LeafType: ct.TimestampedEntryLeafType, TimestampedEntry: &ct.TimestampedEntry{
		Timestamp: sct.Timestamp, EntryType: ct.PrecertLogEntryType,
		PrecertEntry: &ct.PreCert{IssuerKeyHash: sha256.Sum256(s.intermediate.RawSubjectPublicKeyInfo), TBSCertificate: tbs}}}
	input, err := ct.SerializeSCTSignatureInput(sct, ct.LogEntry{Leaf: leaf})
	must(err)
	digest := sha256.Sum256(input)
	signature, err := ecdsa.SignASN1(rand.Reader, s.ctKey, digest[:])
	must(err)
	sct.Signature = ct.DigitallySigned{Algorithm: cttls.SignatureAndHashAlgorithm{Hash: cttls.SHA256, Signature: cttls.ECDSA}, Signature: signature}
	serialized, err := cttls.Marshal(sct)
	must(err)
	list, err := cttls.Marshal(ctx509.SignedCertificateTimestampList{SCTList: []ctx509.SerializedSCT{{Val: serialized}}})
	must(err)
	value, err := asn1.Marshal(list)
	must(err)
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: value}
}

func (s *testSigstore) bundle(who identity, sha, run string, subjects map[string][]byte) []byte {
	signing := key()
	now := time.Now()
	leaf := s.leaf(signing, who, sha, run, now)
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
	signature, err := ecdsa.SignASN1(rand.Reader, signing, digest[:])
	must(err)
	envelope, err := json.Marshal(dsse.Envelope{PayloadType: inTotoPayload, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(signature)}}})
	must(err)
	body := s.rekorBody(envelope, leaf)
	set := s.signedEntryTimestamp(body, now.Unix())
	built, err := bundle.NewBundle(&protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{X509CertificateChain: &protocommon.X509CertificateChain{
				Certificates: []*protocommon.X509Certificate{{RawBytes: leaf.Raw}}}},
			TlogEntries: []*protorekor.TransparencyLogEntry{{
				LogIndex: 0, LogId: &protocommon.LogId{KeyId: s.logID}, KindVersion: &protorekor.KindVersion{Kind: "dsse", Version: "0.0.1"},
				IntegratedTime: now.Unix(), InclusionPromise: &protorekor.InclusionPromise{SignedEntryTimestamp: set}, CanonicalizedBody: body,
			}},
			TimestampVerificationData: &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{{SignedTimestamp: s.timestamp(signature, now)}}},
		},
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{Payload: payload, PayloadType: inTotoPayload,
			Signatures: []*protodsse.Signature{{Sig: signature}}}},
	})
	must(err)
	data, err := built.MarshalJSON()
	must(err)
	return data
}

func (s *testSigstore) rekorBody(envelope []byte, leaf *x509.Certificate) []byte {
	ctx := context.Background()
	proposed, err := types.NewProposedEntry(ctx, rekordsse.KIND, dssev001.APIVERSION, types.ArtifactProperties{
		ArtifactBytes: envelope, PublicKeyBytes: [][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})}, PKIFormat: "x509"})
	must(err)
	entry, err := types.CreateVersionedEntry(proposed)
	must(err)
	body, err := types.CanonicalizeEntry(ctx, entry)
	must(err)
	return body
}

func (s *testSigstore) signedEntryTimestamp(body []byte, integrated int64) []byte {
	payload, err := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{base64.StdEncoding.EncodeToString(body), integrated, hex.EncodeToString(s.logID), 0})
	must(err)
	digest := sha256.Sum256(payload)
	set, err := ecdsa.SignASN1(rand.Reader, s.rekorKey, digest[:])
	must(err)
	return set
}

func (s *testSigstore) timestamp(signature []byte, now time.Time) []byte {
	digest := sha256.Sum256(signature)
	response, err := (&timestamp.Timestamp{HashAlgorithm: crypto.SHA256, HashedMessage: digest[:], Time: now,
		Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2}}).CreateResponseWithOpts(s.tsaLeaf, s.tsaKey, crypto.SHA256)
	must(err)
	return response
}
