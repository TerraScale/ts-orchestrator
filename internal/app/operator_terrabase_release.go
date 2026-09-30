package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/delivery"
)

const (
	terrabaseQualificationSchema = "terrascale.terrabase.qualification.v2"
	terrabaseSourceDigestSchema  = "terrascale.terrabase.source-digest-candidate.v1"
	terrabaseServerArtifact      = "tb-server-linux-arm64"
	terrabaseServerTarget        = "aarch64-unknown-linux-musl"
)

var gitCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// terrabaseReleaseFiles names one retained TerraBase CI release: its
// qualification manifest, the ARM64 server executable, and the accepted
// prepared-source digest record for the same revision.
type terrabaseReleaseFiles struct {
	Qualification string `json:"qualification"`
	Binary        string `json:"binary"`
	SourceDigest  string `json:"source_digest"`
}

// terrabaseRelease is a verified release: the executable bytes match the
// successful CI qualification, and the source claim binds the same revision,
// qualification and executable.
type terrabaseRelease struct {
	Binary              string
	Digest              string
	Size                int64
	Source              delivery.ArtifactSource
	QualificationSHA256 string
	CIRunID             uint64
}

type terrabaseQualification struct {
	Schema         string `json:"schema"`
	SourceRevision string `json:"source_revision"`
	Artifacts      []struct {
		Name   string `json:"name"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
		Target string `json:"target"`
	} `json:"artifacts"`
	Verification struct {
		Conclusion string `json:"conclusion"`
		RunID      uint64 `json:"run_id"`
		Workflow   string `json:"workflow"`
	} `json:"verification"`
}

type terrabaseSourceDigest struct {
	Schema              string `json:"schema"`
	Repository          string `json:"repository"`
	SourceRevision      string `json:"source_revision"`
	SourceDigestSHA256  string `json:"source_digest_sha256"`
	QualificationSHA256 string `json:"qualification_sha256"`
	ServerSHA256        string `json:"server_linux_arm64_sha256"`
}

func loadTerraBaseRelease(files terrabaseReleaseFiles) (terrabaseRelease, error) {
	qualificationWire, err := readBoundedConfigFile(files.Qualification)
	if err != nil {
		return terrabaseRelease{}, fmt.Errorf("read TerraBase qualification: %w", err)
	}
	var qualification terrabaseQualification
	if err := json.Unmarshal(qualificationWire, &qualification); err != nil {
		return terrabaseRelease{}, fmt.Errorf("decode TerraBase qualification: %w", err)
	}
	if qualification.Schema != terrabaseQualificationSchema || !gitCommitPattern.MatchString(qualification.SourceRevision) ||
		qualification.Verification.Conclusion != "success" || qualification.Verification.RunID == 0 {
		return terrabaseRelease{}, errors.New("TerraBase qualification is not a successful v2 CI record")
	}
	qualificationSum := sha256.Sum256(qualificationWire)
	digestWire, err := readBoundedConfigFile(files.SourceDigest)
	if err != nil {
		return terrabaseRelease{}, fmt.Errorf("read TerraBase source digest: %w", err)
	}
	var source terrabaseSourceDigest
	if err := json.Unmarshal(digestWire, &source); err != nil {
		return terrabaseRelease{}, fmt.Errorf("decode TerraBase source digest: %w", err)
	}
	digest, size, err := digestReleaseBinary(files.Binary)
	if err != nil {
		return terrabaseRelease{}, err
	}
	matches := 0
	for _, artifact := range qualification.Artifacts {
		if artifact.Name != terrabaseServerArtifact {
			continue
		}
		matches++
		if artifact.Target != terrabaseServerTarget || artifact.Bytes != size || artifact.SHA256 != digest {
			return terrabaseRelease{}, errors.New("TerraBase server bytes differ from the qualification manifest")
		}
	}
	if matches != 1 {
		return terrabaseRelease{}, errors.New("TerraBase qualification lacks exactly one ARM64 server artifact")
	}
	release := terrabaseRelease{Binary: files.Binary, Digest: digest, Size: size,
		Source: delivery.ArtifactSource{Repository: source.Repository, Commit: qualification.SourceRevision,
			TreeDigest: source.SourceDigestSHA256},
		QualificationSHA256: hex.EncodeToString(qualificationSum[:]), CIRunID: qualification.Verification.RunID}
	if source.Schema != terrabaseSourceDigestSchema || source.SourceRevision != qualification.SourceRevision ||
		source.QualificationSHA256 != release.QualificationSHA256 || source.ServerSHA256 != digest ||
		!fingerprintPattern.MatchString(source.SourceDigestSHA256) {
		return terrabaseRelease{}, errors.New("TerraBase source digest does not bind this qualification and server")
	}
	return release, nil
}

func digestReleaseBinary(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open TerraBase server: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > delivery.MaxArtifactBytes {
		return "", 0, errors.New("TerraBase server must be a bounded regular file")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, delivery.MaxArtifactBytes+1))
	if err != nil || size != info.Size() {
		return "", 0, errors.New("TerraBase server changed while it was hashed")
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}
