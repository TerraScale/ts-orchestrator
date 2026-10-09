// Package nativerootoci confines the managed member's native root operations
// to one signed OCI Object Storage target and one derived publication key.
package nativerootoci

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/oklog/ulid/v2"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	RootPrefix   = "tb-roots/v2/"
	ProbePrefix  = "tb-object-probes/v1/native-oci-update/"
	targetDomain = "terrabase-oci-native-root-target-v1\x00"
)

var (
	namespacePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	bucketPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,254}$`)
	opaqueIdentity   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	lowerDigest      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Target is constructed only from the accepted signed member desired and its
// hash-verified material. No IPC request can change its OCI location or key.
type Target struct {
	Region            string
	Namespace         string
	Bucket            string
	Endpoint          string
	PublicationDigest string
	Digest            string
}

// NewTarget independently checks the target that the controller signed and
// TerraBase's native target digest, including both fixed object prefixes.
func NewTarget(region, namespace, bucket, endpoint, publicationDigest, expectedDigest string) (Target, error) {
	target := Target{Region: region, Namespace: namespace, Bucket: bucket, Endpoint: endpoint,
		PublicationDigest: publicationDigest, Digest: expectedDigest}
	if !target.valid() || target.digest() != expectedDigest {
		return Target{}, errors.New("signed native OCI root target is invalid")
	}
	return target, nil
}

func (target Target) valid() bool {
	if !namespacePattern.MatchString(target.Namespace) || !bucketPattern.MatchString(target.Bucket) ||
		!lowerDigest.MatchString(target.PublicationDigest) || !lowerDigest.MatchString(target.Digest) {
		return false
	}
	if !catalog.IsOCIRegion(target.Region) {
		return false
	}
	return target.Endpoint == "https://"+target.Namespace+".compat.objectstorage."+
		target.Region+".oci.customer-oci.com"
}

func (target Target) digest() string {
	hash := sha256.New()
	hash.Write([]byte(targetDomain))
	for _, part := range []string{target.Region, target.Namespace, target.Bucket,
		target.Endpoint, RootPrefix, ProbePrefix} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		hash.Write(size[:])
		hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func (target Target) rootKey() string  { return RootPrefix + target.PublicationDigest }
func (target Target) probeKey() string { return ProbePrefix + target.PublicationDigest }

// PublicationDigest mirrors tb-storage's distributed native-v2 publication
// namespace. Every input is an accepted, signed member identity, never an IPC
// locator. The caller compares the result with TerraBase's request value.
func PublicationDigest(clusterID, tenantID, databaseID, memberID, incarnation string, shard uint64) (string, error) {
	cluster, err := hex.DecodeString(clusterID)
	if err != nil || len(cluster) != 16 || !opaqueIdentity.MatchString(clusterID) || strings.Trim(clusterID, "0") == "" || shard == 0 {
		return "", errors.New("signed native cluster or shard is invalid")
	}
	incarnationBytes, err := hex.DecodeString(incarnation)
	if err != nil || len(incarnationBytes) != 16 || !opaqueIdentity.MatchString(incarnation) || strings.Trim(incarnation, "0") == "" {
		return "", errors.New("signed native member incarnation is invalid")
	}
	tenant, err := canonicalID(tenantID)
	if err != nil {
		return "", err
	}
	database, err := canonicalID(databaseID)
	if err != nil {
		return "", err
	}
	member, err := canonicalID(memberID)
	if err != nil {
		return "", err
	}
	var shardBytes [8]byte
	binary.LittleEndian.PutUint64(shardBytes[:], shard)
	scope := sha256.New()
	scope.Write([]byte("TBLOGS01"))
	scope.Write(tenant[:])
	scope.Write(database[:])
	scope.Write(shardBytes[:])
	publication := sha256.New()
	publication.Write([]byte("TBPUBS01"))
	publication.Write(scope.Sum(nil))
	publication.Write([]byte{2})
	publication.Write(cluster[:])
	publication.Write(member[:])
	publication.Write(incarnationBytes[:])
	return hex.EncodeToString(publication.Sum(nil)), nil
}

func canonicalID(value string) (ulid.ULID, error) { return entityid.Parse(value) }
