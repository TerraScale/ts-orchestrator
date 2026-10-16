package managedmaterial

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"net/url"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/oci"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
)

const (
	s3TargetDomain            = "terrabase-s3-target-v1\x00"
	nativeOCIRootTargetDomain = "terrabase-oci-native-root-target-v1\x00"
	nativeOCIRootPrefix       = "tb-roots/v2/"
	nativeOCIProbePrefix      = "tb-object-probes/v1/native-oci-update/"
)

// NativeOCIRoot selects native OCI Object Storage CAS for authoritative roots.
// S3 still stores immutable data in the same signed bucket and region.
type NativeOCIRoot struct {
	Namespace string `json:"namespace"`
}

// LiveS3Target binds the nonsecret ObjectDurable root location and the exact
// Vault version that can authenticate to it. Credentials are never encoded in
// the TerraBase config, preparation receipt, placement, or NATS desired state.
type LiveS3Target struct {
	Bucket        string                     `json:"bucket"`
	Region        string                     `json:"region"`
	Endpoint      string                     `json:"endpoint,omitempty"`
	Credential    oci.SecretVersionReference `json:"credential"`
	NativeOCIRoot *NativeOCIRoot             `json:"native_oci_root,omitempty"`
}

func (target LiveS3Target) Validate() error {
	if target.Credential.Validate() != nil || len(target.Bucket) == 0 || len(target.Bucket) > 255 ||
		len(target.Region) == 0 || len(target.Region) > 64 {
		return errors.New("live S3 target or credential version is invalid")
	}
	for _, value := range []string{target.Bucket, target.Region} {
		for _, char := range value {
			if char > 127 || !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
				char >= '0' && char <= '9' || char == '-' || char == '.' || char == '_') {
				return errors.New("live S3 target contains an invalid name")
			}
		}
	}
	if strings.ContainsAny(target.Region, "._") {
		return errors.New("live S3 region contains an invalid character")
	}
	if target.Endpoint != "" {
		parsed, err := url.Parse(target.Endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil ||
			parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" ||
			parsed.Host != strings.ToLower(parsed.Host) || strings.HasSuffix(parsed.Host, ":443") ||
			target.Endpoint != "https://"+parsed.Host {
			return errors.New("live S3 endpoint is not canonical HTTPS")
		}
	}
	if root := target.NativeOCIRoot; root != nil {
		namespace := root.Namespace
		if len(namespace) == 0 || len(namespace) > 64 || namespace[0] == '-' || namespace[len(namespace)-1] == '-' {
			return errors.New("native OCI root namespace is invalid")
		}
		for _, char := range namespace {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return errors.New("native OCI root namespace is invalid")
			}
		}
		first := target.Bucket[0]
		if !(first >= 'a' && first <= 'z' || first >= '0' && first <= '9') {
			return errors.New("native OCI root bucket is invalid")
		}
		for _, char := range target.Bucket {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' ||
				char == '-' || char == '.' || char == '_') {
				return errors.New("native OCI root bucket is invalid")
			}
		}
		if !catalog.IsOCIRegion(target.Region) {
			return errors.New("native OCI root region is unsupported")
		}
		if target.Endpoint != "https://"+namespace+".compat.objectstorage."+target.Region+".oci.customer-oci.com" {
			return errors.New("native OCI root requires its canonical regional S3 compatibility endpoint")
		}
	}
	return nil
}

// ConfigJSON is the exact nonsecret JSON consumed by TerraBase's signed-v2
// ObjectDurable parser. The OCI Vault reference stays outside these bytes.
func (target LiveS3Target) ConfigJSON() ([]byte, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(struct {
		Version       uint64         `json:"version"`
		AckProfile    string         `json:"ack_profile"`
		Bucket        string         `json:"bucket"`
		Region        string         `json:"region"`
		Endpoint      string         `json:"endpoint,omitempty"`
		NativeOCIRoot *NativeOCIRoot `json:"native_oci_root,omitempty"`
	}{Version: 1, AckProfile: "object_durable", Bucket: target.Bucket,
		Region: target.Region, Endpoint: target.Endpoint, NativeOCIRoot: target.NativeOCIRoot})
	if err != nil || len(data) > 16<<10 {
		return nil, errors.New("live S3 config exceeds its native bound")
	}
	return data, nil
}

// Digest mirrors TerraBase's target_digest: credentials and config JSON
// formatting cannot change the persistent ObjectDurable root identity.
func (target LiveS3Target) Digest() (string, error) {
	if err := target.Validate(); err != nil {
		return "", err
	}
	hash := sha256.New()
	domain := s3TargetDomain
	parts := []string{target.Region, target.Bucket, target.Endpoint}
	if root := target.NativeOCIRoot; root != nil {
		domain = nativeOCIRootTargetDomain
		parts = []string{target.Region, root.Namespace, target.Bucket, target.Endpoint,
			nativeOCIRootPrefix, nativeOCIProbePrefix}
	}
	hash.Write([]byte(domain))
	for _, part := range parts {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		hash.Write(length[:])
		hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func verifyStoredLiveS3(spec InitialSpec, member MemberBundle) bool {
	config, err := spec.LiveS3.ConfigJSON()
	if err != nil {
		return false
	}
	return bytes.Equal(member.Files["signed-v2-s3-config.json"].Contents, config)
}
