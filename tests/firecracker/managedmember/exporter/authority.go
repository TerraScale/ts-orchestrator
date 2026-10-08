package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
)

const (
	clusterID    = "5ANANANANANANANANANANANANA"
	tenantID     = "01HW000000E008000000000001"
	databaseID   = tenantID
	collectionID = "1144GJ289144GJ289144GJ2891"
	documentID   = "01HW000000E008000000000011"
)

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

func signedAuthority(signingKey ed25519.PrivateKey, members [2]memberCertificate) ([]byte, string, string, error) {
	catalog, err := managedmaterial.InitialCatalog(collectionID, nil)
	if err != nil {
		return nil, "", "", err
	}
	var roster [2]managedmaterial.AuthorityMember
	for index, member := range members {
		roster[index] = managedmaterial.AuthorityMember{
			MemberID: memberIDs[index], Incarnation: memberIncarnations[index],
			ServerName: memberDNSNames[index], FailureDomain: failureDomains[index], LeafDER: member.leaf,
		}
	}
	signed, err := managedmaterial.SignInitialAuthorityV2(managedmaterial.AuthorityScope{
		ClusterID: clusterID, TenantID: tenantID, DatabaseID: databaseID, ShardID: 1, Epoch: 1,
	}, roster, []managedmaterial.AuthorityCatalog{catalog}, signingKey)
	if err != nil {
		return nil, "", "", err
	}
	return signed.Certificate, signed.ConfigurationID, catalog.SchemaDigest, nil
}
