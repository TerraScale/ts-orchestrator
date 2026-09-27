package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"net"
	"time"
	"uuid"
)

const (
	clusterID    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tenantID     = "018f0000-0000-7000-8000-000000000001"
	databaseID   = tenantID
	collectionID = "21212121-2121-2121-2121-212121212121"
	documentID   = "018f0000-0000-7000-8000-000000000021"
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

type memberCertificate struct {
	chain []byte
	key   []byte
	leaf  []byte
}

func newCertificateAuthority(name string) (*x509.Certificate, ed25519.PrivateKey, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return parsed, private, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func newLeaf(ca *x509.Certificate, caKey ed25519.PrivateKey, caPEM []byte, name string, ip net.IP, peer bool) (memberCertificate, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return memberCertificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return memberCertificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if peer {
		template.DNSNames = []string{name}
		template.ExtKeyUsage = append(template.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	} else {
		template.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	if err != nil {
		return memberCertificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return memberCertificate{}, err
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, caPEM...)
	return memberCertificate{chain: chain, key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), leaf: der}, nil
}

func parseUUID(value string) ([16]byte, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value || parsed == uuid.Nil() {
		return [16]byte{}, fmt.Errorf("invalid canonical UUID %q", value)
	}
	return [16]byte(parsed), nil
}

func appendU16(out []byte, value uint16) []byte { return binary.LittleEndian.AppendUint16(out, value) }
func appendU32(out []byte, value uint32) []byte { return binary.LittleEndian.AppendUint32(out, value) }
func appendU64(out []byte, value uint64) []byte { return binary.LittleEndian.AppendUint64(out, value) }

func emptyCatalog() ([]byte, [32]byte, error) {
	collection, err := parseUUID(collectionID)
	if err != nil {
		return nil, [32]byte{}, err
	}
	schema := append([]byte("TBSCH001"), 0, 0, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(schema[8:12], 18)
	schema = appendU32(schema, crc32.Checksum(schema, crcTable))
	digest := sha256.Sum256(schema)
	catalog := append([]byte("TBCAT001"), 0, 0, 0, 0)
	catalog = append(catalog, collection[:]...)
	catalog = appendU64(catalog, 1)
	catalog = appendU64(catalog, 0)
	catalog = append(catalog, digest[:]...)
	catalog = appendU32(catalog, uint32(len(schema)))
	catalog = append(catalog, schema...)
	catalog = appendU32(catalog, crc32.Checksum(catalog, crcTable))
	binary.LittleEndian.PutUint32(catalog[8:12], uint32(len(catalog)))
	// The checksum covers the complete record header, including its final length.
	binary.LittleEndian.PutUint32(catalog[len(catalog)-4:], crc32.Checksum(catalog[:len(catalog)-4], crcTable))
	return catalog, digest, nil
}

func signedAuthority(signingKey ed25519.PrivateKey, members [2]memberCertificate) ([]byte, string, string, error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, "", "", errors.New("authority signer has invalid length")
	}
	cluster, err := hex.DecodeString(clusterID)
	if err != nil {
		return nil, "", "", err
	}
	tenant, err := parseUUID(tenantID)
	if err != nil {
		return nil, "", "", err
	}
	database, err := parseUUID(databaseID)
	if err != nil {
		return nil, "", "", err
	}
	collection, err := parseUUID(collectionID)
	if err != nil {
		return nil, "", "", err
	}
	catalog, schemaDigest, err := emptyCatalog()
	if err != nil {
		return nil, "", "", err
	}
	payload := append([]byte("TBCAU002"), 0, 0, 0, 0)
	payload = appendU16(payload, 2)
	payload = appendU16(payload, 1)
	payload = append(payload, cluster...)
	payload = append(payload, tenant[:]...)
	payload = append(payload, database[:]...)
	payload = appendU64(payload, 1)
	payload = appendU64(payload, 1)
	payload = appendU16(payload, 2)
	payload = appendU16(payload, 1)
	payload = appendU16(payload, 1)
	for index, member := range members {
		id, err := parseUUID(memberIDs[index])
		if err != nil {
			return nil, "", "", err
		}
		incarnation, err := hex.DecodeString(memberIncarnations[index])
		if err != nil || len(incarnation) != 16 {
			return nil, "", "", errors.New("invalid member incarnation")
		}
		payload = append(payload, id[:]...)
		payload = append(payload, incarnation...)
		leafHash := sha256.Sum256(member.leaf)
		payload = append(payload, leafHash[:]...)
		name := []byte(memberDNSNames[index])
		domain := []byte(failureDomains[index])
		payload = append(payload, byte(len(name)))
		payload = append(payload, name...)
		payload = append(payload, byte(len(domain)))
		payload = append(payload, domain...)
	}
	payload = append(payload, collection[:]...)
	payload = appendU64(payload, 1)
	payload = append(payload, schemaDigest[:]...)
	payload = appendU32(payload, uint32(len(catalog)))
	payload = append(payload, catalog...)
	payload = append(payload, collection[:]...)
	payload = appendU64(payload, 1)
	payload = append(payload, schemaDigest[:]...)
	binary.LittleEndian.PutUint32(payload[8:12], uint32(len(payload)))
	configured := sha256.Sum256(append([]byte("TB-CONFIG-FIXED-V2\x00"), payload...))
	signature := ed25519.Sign(signingKey, append([]byte("TB-AUTHORITY-FIXED-V2\x00"), payload...))
	certificate := append(payload, signature...)
	return certificate, hex.EncodeToString(configured[:]), hex.EncodeToString(schemaDigest[:]), nil
}
