package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

const successorCatalogSetDomain = "TB-D11-DOCUMENT-CATALOGS-V1\x00"

// SuccessorRequest identifies the two fresh certified origins in predecessor
// seat order. Their exact replication TLS leaves must already be staged with
// their private keys in the successor's confidential material.
type SuccessorRequest struct {
	Epoch   uint64
	Members [2]AuthorityMember
}

// SuccessorMaterial contains the exact public artifacts and pins for a D11
// Prepare. Attestation keys and SuccessorLeafPinsBySeat retain predecessor
// seat order even when the successor certificate sorts its member IDs in the
// opposite order. An absent SQL bundle is represented by SQLPresent=false and
// zero SQL digests. Its bytes must be durably pinned before Prepare dispatch.
type SuccessorMaterial struct {
	PredecessorScope           AuthorityScope
	SuccessorScope             AuthorityScope
	PredecessorConfigurationID string
	PredecessorAuthoritySHA256 [sha256.Size]byte
	SuccessorAuthority         SignedAuthority
	SuccessorAuthoritySHA256   [sha256.Size]byte
	TrustedKeySHA256           [sha256.Size]byte
	PredecessorSQLBundleSHA256 [sha256.Size]byte
	SuccessorSQLBundle         []byte
	SuccessorSQLBundleSHA256   [sha256.Size]byte
	SQLPresent                 bool
	DocumentCatalogSetSHA256   [sha256.Size]byte
	PredecessorAttestationKeys [2]ed25519.PublicKey
	SuccessorAttestationKeys   [2]ed25519.PublicKey
	SuccessorLeafPinsBySeat    [2]string
}

// ProduceSuccessor reads the current R3 receipt and exact OCI object before
// using its retained authority signer. It signs only the next certificate and
// SQL bundle; the D11 journal must pin these returned bytes on first use and
// reuse them on every retry.
func (service PreparationService) ProduceSuccessor(ctx context.Context, database, partition string,
	request SuccessorRequest, now time.Time,
) (SuccessorMaterial, error) {
	receipt, current, err := service.CurrentBundle(ctx, database, partition)
	if err != nil {
		return SuccessorMaterial{}, err
	}
	if now.IsZero() || request.Epoch <= receipt.Spec.Scope.Epoch ||
		len(current.Retained.AuthoritySigner) != ed25519.PrivateKeySize ||
		!bytes.Equal(current.Retained.AuthoritySigner.Public().(ed25519.PublicKey), current.Authority.TrustedKey) {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	var oldIncarnations, newIncarnations [2][16]byte
	for index, oldMember := range receipt.Spec.Members {
		decoded, decodeErr := entityid.Parse(oldMember.Incarnation)
		if decodeErr != nil || len(decoded) != len(oldIncarnations[index]) || allZero(decoded[:]) {
			return SuccessorMaterial{}, ErrMaterialConflict
		}
		copy(oldIncarnations[index][:], decoded[:])
	}
	for index, newMember := range request.Members {
		decoded, decodeErr := entityid.Parse(newMember.Incarnation)
		if decodeErr != nil || len(decoded) != len(newIncarnations[index]) || allZero(decoded[:]) {
			return SuccessorMaterial{}, ErrMaterialConflict
		}
		copy(newIncarnations[index][:], decoded[:])
		for _, oldIncarnation := range oldIncarnations {
			if newIncarnations[index] == oldIncarnation {
				return SuccessorMaterial{}, ErrMaterialConflict
			}
		}
	}
	if newIncarnations[0] == newIncarnations[1] {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	if err := validateSQLTables(receipt.Spec.SQLTables, receipt.Spec.Catalogs); err != nil {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	catalogs, err := initialCatalogs(receipt.Spec.Catalogs)
	if err != nil {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	caPEM := current.Members[0].Files["server-ca.pem"].Contents
	caBlock, rest := pem.Decode(caPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(rest) != 0 {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	var oldKeys, newKeys [2]ed25519.PublicKey
	var successorLeafPinsBySeat [2]string
	for index, member := range request.Members {
		if len(member.LeafDER) == 0 || len(member.LeafDER) > maxCatalogBytes {
			return SuccessorMaterial{}, ErrMaterialConflict
		}
		oldBlock, _ := pem.Decode(current.Members[index].Files["server.crt"].Contents)
		if oldBlock == nil || oldBlock.Type != "CERTIFICATE" {
			return SuccessorMaterial{}, ErrMaterialConflict
		}
		oldLeaf, parseErr := x509.ParseCertificate(oldBlock.Bytes)
		if parseErr != nil {
			return SuccessorMaterial{}, ErrMaterialConflict
		}
		oldKey, oldOK := oldLeaf.PublicKey.(ed25519.PublicKey)
		newLeaf, parseErr := x509.ParseCertificate(member.LeafDER)
		if parseErr != nil {
			return SuccessorMaterial{}, ErrMaterialConflict
		}
		newKey, newOK := newLeaf.PublicKey.(ed25519.PublicKey)
		if !oldOK || !newOK || newLeaf.IsCA ||
			newLeaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
			!bytes.Equal(newLeaf.RawIssuer, ca.RawSubject) {
			return SuccessorMaterial{}, ErrMaterialConflict
		}
		for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
			if _, err := newLeaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: member.ServerName,
				CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
				return SuccessorMaterial{}, ErrMaterialConflict
			}
		}
		oldKeys[index] = bytes.Clone(oldKey)
		newKeys[index] = bytes.Clone(newKey)
		leafSHA := sha256.Sum256(member.LeafDER)
		successorLeafPinsBySeat[index] = hex.EncodeToString(leafSHA[:])
		if bytes.Equal(oldKeys[index], newKeys[index]) {
			return SuccessorMaterial{}, ErrMaterialConflict
		}
	}
	if bytes.Equal(newKeys[0], newKeys[1]) ||
		bytes.Equal(newKeys[0], oldKeys[1]) || bytes.Equal(newKeys[1], oldKeys[0]) {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	scope := receipt.Spec.Scope
	scope.Epoch = request.Epoch
	certMembers := request.Members
	leftID, leftErr := canonicalID(certMembers[0].MemberID)
	rightID, rightErr := canonicalID(certMembers[1].MemberID)
	if leftErr != nil || rightErr != nil || leftID == rightID {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	if bytes.Compare(leftID[:], rightID[:]) > 0 {
		certMembers[0], certMembers[1] = certMembers[1], certMembers[0]
	}
	authority, err := SignInitialAuthorityV2(scope, certMembers, catalogs, current.Retained.AuthoritySigner)
	if err != nil || authority.ConfigurationID == current.Authority.ConfigurationID ||
		!bytes.Equal(authority.TrustedKey, current.Authority.TrustedKey) ||
		bytes.Equal(authority.Certificate, current.Authority.Certificate) {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	result := SuccessorMaterial{
		PredecessorScope:           receipt.Spec.Scope,
		SuccessorScope:             scope,
		PredecessorConfigurationID: current.Authority.ConfigurationID,
		PredecessorAuthoritySHA256: sha256.Sum256(current.Authority.Certificate),
		SuccessorAuthority:         authority,
		SuccessorAuthoritySHA256:   sha256.Sum256(authority.Certificate),
		TrustedKeySHA256:           sha256.Sum256(authority.TrustedKey),
		PredecessorAttestationKeys: oldKeys,
		SuccessorAttestationKeys:   newKeys,
		SuccessorLeafPinsBySeat:    successorLeafPinsBySeat,
	}
	result.DocumentCatalogSetSHA256, err = successorCatalogSetDigest(catalogs)
	if err != nil {
		return SuccessorMaterial{}, err
	}
	if len(receipt.Spec.SQLTables) == 0 {
		return result, nil
	}
	oldBundle := current.Members[0].Files[sqlSchemaBundleFileName].Contents
	if len(oldBundle) == 0 {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	result.SQLPresent = true
	result.PredecessorSQLBundleSHA256 = sha256.Sum256(oldBundle)
	result.SuccessorSQLBundle, err = encodeSQLSchemaBundle(scope, authority.ConfigurationID,
		receipt.Spec.SQLTables, current.Retained.AuthoritySigner)
	if err != nil {
		return SuccessorMaterial{}, err
	}
	result.SuccessorSQLBundleSHA256 = sha256.Sum256(result.SuccessorSQLBundle)
	if result.PredecessorSQLBundleSHA256 == result.SuccessorSQLBundleSHA256 {
		return SuccessorMaterial{}, ErrMaterialConflict
	}
	return result, nil
}

func successorCatalogSetDigest(catalogs []AuthorityCatalog) ([sha256.Size]byte, error) {
	if len(catalogs) == 0 || len(catalogs) > 1024 {
		return [sha256.Size]byte{}, ErrMaterialConflict
	}
	material := make([]byte, 0, len(successorCatalogSetDomain)+2+len(catalogs)*56)
	material = append(material, successorCatalogSetDomain...)
	material = binary.LittleEndian.AppendUint16(material, uint16(len(catalogs)))
	for _, catalog := range catalogs {
		collection, err := canonicalID(catalog.CollectionID)
		if err != nil {
			return [sha256.Size]byte{}, ErrMaterialConflict
		}
		material = append(material, collection[:]...)
		material = binary.LittleEndian.AppendUint64(material, catalog.SchemaGeneration)
		sum := sha256.Sum256(catalog.Bytes)
		material = append(material, sum[:]...)
	}
	return sha256.Sum256(material), nil
}
