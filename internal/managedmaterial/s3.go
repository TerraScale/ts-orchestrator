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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
)

const s3TargetDomain = "terrabase-s3-target-v1\x00"

// LiveS3Target binds the nonsecret ObjectDurable root location and the exact
// Vault version that can authenticate to it. Credentials are never encoded in
// the TerraBase config, preparation receipt, placement, or NATS desired state.
type LiveS3Target struct {
	Bucket     string                     `json:"bucket"`
	Region     string                     `json:"region"`
	Endpoint   string                     `json:"endpoint,omitempty"`
	Credential oci.SecretVersionReference `json:"credential"`
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
	return nil
}

// ConfigJSON is the exact nonsecret JSON consumed by TerraBase's signed-v2
// ObjectDurable parser. The OCI Vault reference stays outside these bytes.
func (target LiveS3Target) ConfigJSON() ([]byte, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(struct {
		Version    uint64 `json:"version"`
		AckProfile string `json:"ack_profile"`
		Bucket     string `json:"bucket"`
		Region     string `json:"region"`
		Endpoint   string `json:"endpoint,omitempty"`
	}{Version: 1, AckProfile: "object_durable", Bucket: target.Bucket,
		Region: target.Region, Endpoint: target.Endpoint})
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
	hash.Write([]byte(s3TargetDomain))
	for _, part := range []string{target.Region, target.Bucket, target.Endpoint} {
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
