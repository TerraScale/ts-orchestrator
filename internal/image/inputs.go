// Package image builds and promotes deployment-neutral, qualified OCI host images.
package image

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

var gitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var token = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var kernelRelease = regexp.MustCompile(`^[0-9][A-Za-z0-9._+-]{0,127}$`)

type Asset struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type BaseInputs struct {
	ReleaseTag        string `json:"release_tag"`
	SourceURL         string `json:"source_url"`
	ChecksumName      string `json:"checksum_name"`
	SignerFingerprint string `json:"signer_fingerprint"`
	OCIImageOCID      string `json:"oci_image_ocid"`
	KernelRelease     string `json:"kernel_release"`
	Assets            struct {
		Base      Asset `json:"base-image.qcow2"`
		Sums      Asset `json:"ubuntu-SHA256SUMS"`
		Signature Asset `json:"ubuntu-SHA256SUMS.gpg"`
		Keyring   Asset `json:"ubuntu-cloud-image-keyring.gpg"`
	} `json:"assets"`
}
type PriorityInputs struct {
	ProfileID     string `json:"profile_id"`
	SystemReserve int64  `json:"system_reserve_bytes"`
	HostMin       int64  `json:"host_memory_min_bytes"`
	HostLow       int64  `json:"host_memory_low_bytes"`
	ControllerMin int64  `json:"controller_memory_min_bytes"`
	ControllerLow int64  `json:"controller_memory_low_bytes"`
	SystemMin     int64  `json:"system_slice_memory_min_bytes"`
	SystemLow     int64  `json:"system_slice_memory_low_bytes"`
}
type TerraBasePin struct {
	SourceRevision      string           `json:"source_revision"`
	SourceTree          string           `json:"source_tree"`
	RunID               int64            `json:"run_id"`
	RunNumber           int64            `json:"run_number"`
	QualificationSHA256 string           `json:"qualification_sha256"`
	BinarySHA256        string           `json:"binary_sha256"`
	Archive             *VerifierArchive `json:"archive,omitempty"`
}
type VerifierArchive struct {
	ReleaseTag          string `json:"release_tag"`
	QualificationSHA256 string `json:"qualification_sha256"`
}
type Inputs struct {
	raw        jsontext.Value
	Schema     string           `json:"schema"`
	Region     string           `json:"region"`
	Base       BaseInputs       `json:"base"`
	TrustRoots []client.FilePin `json:"trust_roots"`
	Timesyncd  client.FilePin   `json:"timesyncd_config"`
	Priority   PriorityInputs   `json:"priority"`
	TerraBase  TerraBasePin     `json:"terrabase"`
	NetBird    client.Pin       `json:"netbird"`
}

func canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v, jsontext.WithIndent("  "), json.Deterministic(true))
	return append(b, '\n'), e
}
func ValidateTerraBase(p TerraBasePin) error {
	if !gitSHA.MatchString(p.SourceRevision) {
		return errors.New("terrabase.source_revision must be a full SHA")
	}
	if !gitSHA.MatchString(p.SourceTree) {
		return errors.New("terrabase.source_tree must be a full SHA")
	}
	if p.RunID <= 0 || p.RunNumber <= 0 {
		return errors.New("terrabase run identity is invalid")
	}
	if !client.SHA256Pattern.MatchString(p.QualificationSHA256) {
		return errors.New("terrabase.qualification_sha256 must be a SHA-256")
	}
	if !client.SHA256Pattern.MatchString(p.BinarySHA256) {
		return errors.New("terrabase.binary_sha256 must be a SHA-256")
	}
	if p.Archive != nil && (p.Archive.ReleaseTag != "native-verifier-alpha-"+p.BinarySHA256 || !client.SHA256Pattern.MatchString(p.Archive.QualificationSHA256)) {
		return errors.New("native verifier archive needs its digest-named release and pinned image qualification")
	}
	return nil
}

// VerifyTerraBaseArchive admits the same verifier bytes from a retained image,
// whose original TerraBase qualification and source identity remain pinned.
func VerifyTerraBaseArchive(pin TerraBasePin, qualificationPath, binaryPath string) error {
	if err := ValidateTerraBase(pin); err != nil {
		return err
	}
	if pin.Archive == nil || qualificationPath == "" || binaryPath == "" {
		return errors.New("native verifier archive needs qualification and binary files")
	}
	for _, p := range []struct{ path, digest string }{{qualificationPath, pin.Archive.QualificationSHA256}, {binaryPath, pin.BinarySHA256}} {
		digest, err := client.SHA256(p.path)
		if err != nil {
			return err
		}
		if digest != p.digest {
			return errors.New("native verifier archive bytes differ from their pin")
		}
	}
	var q struct {
		Schema string
		Inputs struct {
			Manifest struct{ TerraBase TerraBasePin }
		}
	}
	if err := readJSON(qualificationPath, &q); err != nil {
		return err
	}
	pin.Archive = nil
	if q.Schema != "terrascale.image.qualification.v2" || q.Inputs.Manifest.TerraBase != pin {
		return errors.New("archived image qualification differs from the TerraBase verifier pin")
	}
	return nil
}
func LoadInputs(root, path string) (Inputs, error) {
	var v Inputs
	b, e := os.ReadFile(path)
	if e != nil {
		return v, e
	}
	if e = json.Unmarshal(b, &v, json.RejectUnknownMembers(true)); e != nil {
		return v, e
	}
	expected, e := canonical(jsontext.Value(b))
	if e != nil {
		return v, e
	}
	if !bytes.Equal(b, expected) {
		return v, errors.New("image-inputs.json is not canonically formatted (json indent 2)")
	}
	var fields map[string]jsontext.Value
	if e = json.Unmarshal(b, &fields); e != nil {
		return v, e
	}
	if e = requireKeys(b, []string{"schema", "region", "base", "trust_roots", "timesyncd_config", "priority", "terrabase", "netbird"}, "image-inputs.json has unexpected or reordered top-level fields"); e != nil {
		return v, e
	}
	for _, item := range []struct {
		key     string
		keys    []string
		message string
	}{{"base", []string{"release_tag", "source_url", "checksum_name", "signer_fingerprint", "oci_image_ocid", "kernel_release", "assets"}, "base has unexpected fields"}, {"priority", []string{"profile_id", "system_reserve_bytes", "host_memory_min_bytes", "host_memory_low_bytes", "controller_memory_min_bytes", "controller_memory_low_bytes", "system_slice_memory_min_bytes", "system_slice_memory_low_bytes"}, "priority has unexpected fields"}, {"terrabase", []string{"source_revision", "source_tree", "run_id", "run_number", "qualification_sha256", "binary_sha256"}, "terrabase has unexpected fields"}} {
		if item.key == "terrabase" && v.TerraBase.Archive != nil {
			item.keys = append(item.keys, "archive")
		}
		if e = requireKeys(fields[item.key], item.keys, item.message); e != nil {
			return v, e
		}
	}
	if _, e = client.ValidatePinJSON(fields["netbird"]); e != nil {
		return v, e
	}
	var roots []jsontext.Value
	if e = json.Unmarshal(fields["trust_roots"], &roots); e != nil {
		return v, e
	}
	var bird map[string]jsontext.Value
	if e = json.Unmarshal(fields["netbird"], &bird); e != nil {
		return v, e
	}
	for _, raw := range append(append([]jsontext.Value{}, roots...), fields["timesyncd_config"], bird["enrollment_config"]) {
		if e = requireKeys(raw, []string{"path", "sha256"}, "checked-in input pins need exactly path and sha256"); e != nil {
			return v, e
		}
	}
	v.raw = jsontext.Value(b).Clone()
	if v.Schema != "terrascale.image.inputs.v2" {
		return v, errors.New("schema must be terrascale.image.inputs.v2")
	}
	if v.Region != "GRU" {
		return v, errors.New("region must be GRU")
	}
	base := v.Base
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(base.ReleaseTag) {
		return v, errors.New("base.release_tag is invalid")
	}
	if !strings.HasPrefix(base.SourceURL, "https://cloud-images.ubuntu.com/") || !strings.HasSuffix(base.SourceURL, "/"+base.ChecksumName) {
		return v, errors.New("base.source_url must be the Ubuntu image")
	}
	if !regexp.MustCompile(`^[0-9A-F]{40}$`).MatchString(base.SignerFingerprint) {
		return v, errors.New("base.signer_fingerprint is invalid")
	}
	if !strings.HasPrefix(base.OCIImageOCID, "ocid1.image.oc1.sa-saopaulo-1.") {
		return v, errors.New("base OCID must be a GRU image")
	}
	if !kernelRelease.MatchString(base.KernelRelease) {
		return v, errors.New("base.kernel_release is invalid")
	}
	for _, a := range []Asset{base.Assets.Base, base.Assets.Sums, base.Assets.Signature, base.Assets.Keyring} {
		if a.Bytes <= 0 || !client.SHA256Pattern.MatchString(a.SHA256) {
			return v, errors.New("base asset pin is invalid")
		}
	}
	if e = client.ValidatePin(v.NetBird); e != nil {
		return v, e
	}
	entries := append(append([]client.FilePin{}, v.TrustRoots...), v.Timesyncd, v.NetBird.EnrollmentConfig)
	for _, entry := range entries {
		if !client.SHA256Pattern.MatchString(entry.SHA256) {
			return v, errors.New("checked-in input pins need exactly path and sha256")
		}
		path := filepath.Join(root, entry.Path)
		resolved, e := filepath.EvalSymlinks(path)
		if e != nil {
			return v, fmt.Errorf("checked-in input must be a file under deploy/image/inputs: %s", entry.Path)
		}
		allowed := filepath.Join(root, "deploy/image/inputs")
		rel, e := filepath.Rel(allowed, resolved)
		s, se := os.Stat(resolved)
		if e != nil || rel == ".." || strings.HasPrefix(rel, "../") || se != nil || !s.Mode().IsRegular() {
			return v, fmt.Errorf("checked-in input must be a file under deploy/image/inputs: %s", entry.Path)
		}
		d, e := client.SHA256(resolved)
		if e != nil {
			return v, e
		}
		if d != entry.SHA256 {
			return v, fmt.Errorf("checked-in input differs from its pin: %s", entry.Path)
		}
	}
	if _, e = client.ValidateConfig(filepath.Join(root, v.NetBird.EnrollmentConfig.Path)); e != nil {
		return v, e
	}
	if len(v.TrustRoots) < 1 || len(v.TrustRoots) > 16 {
		return v, errors.New("trust_roots must list 1 to 16 roots")
	}
	p := v.Priority
	if !token.MatchString(p.ProfileID) {
		return v, errors.New("priority.profile_id is invalid")
	}
	for _, n := range []int64{p.SystemReserve, p.HostMin, p.HostLow, p.ControllerMin, p.ControllerLow, p.SystemMin, p.SystemLow} {
		if n <= 0 {
			return v, errors.New("priority byte counts must be positive")
		}
	}
	return v, ValidateTerraBase(v.TerraBase)
}
func TerraBaseQualification(qualificationPath, detailPath string) (TerraBasePin, error) {
	var q struct {
		Schema, Repository string
		SourceRevision     string `json:"source_revision"`
		SourceTree         string `json:"source_tree"`
		Verification       struct {
			Workflow, Job, Conclusion string
			RunID                     int64 `json:"run_id"`
			RunNumber                 int64 `json:"run_number"`
		}
		Artifacts []struct{ Name, Target, SHA256 string }
	}
	if e := readJSON(qualificationPath, &q); e != nil {
		return TerraBasePin{}, e
	}
	if q.Schema != "terrascale.terrabase.qualification.v2" || q.Repository != "TerraScale/TerraBase" {
		return TerraBasePin{}, errors.New("not a TerraBase v2 qualification")
	}
	v := q.Verification
	if v.Workflow != "fast.yml" || v.Job != "fast" || v.Conclusion != "success" {
		return TerraBasePin{}, errors.New("TerraBase qualification is not a successful Fast run")
	}
	artifact := ""
	count := 0
	for _, a := range q.Artifacts {
		if a.Name == "tb-server-linux-arm64" && a.Target == "aarch64-unknown-linux-musl" {
			artifact = a.SHA256
			count++
		}
	}
	if count != 1 {
		return TerraBasePin{}, errors.New("TerraBase qualification must list one tb-server-linux-arm64")
	}
	var detail struct {
		RunID            int64  `json:"run_id"`
		RunNumber        int64  `json:"run_number"`
		HeadSHA          string `json:"head_sha"`
		Workflow, Status string
		Jobs             []struct {
			Name, Status string
			RunID        int64 `json:"run_id"`
		}
	}
	if e := readJSON(detailPath, &detail); e != nil {
		return TerraBasePin{}, e
	}
	if detail.RunID != v.RunID || detail.RunNumber != v.RunNumber || detail.HeadSHA != q.SourceRevision || detail.Workflow != "fast.yml" || (detail.Status != "success" && detail.Status != "running") {
		return TerraBasePin{}, errors.New("TerraBase run detail differs from its qualification or did not succeed")
	}
	count = 0
	for _, job := range detail.Jobs {
		if job.Name == "fast" && job.Status == "success" && job.RunID == detail.RunID {
			count++
		}
	}
	if count != 1 {
		return TerraBasePin{}, errors.New("TerraBase Fast job did not succeed")
	}
	digest, e := client.SHA256(qualificationPath)
	if e != nil {
		return TerraBasePin{}, e
	}
	p := TerraBasePin{SourceRevision: q.SourceRevision, SourceTree: q.SourceTree, RunID: v.RunID, RunNumber: v.RunNumber, QualificationSHA256: digest, BinarySHA256: artifact}
	return p, ValidateTerraBase(p)
}
func readJSON(path string, v any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v, json.MatchCaseInsensitiveNames(true))
}

func requireKeys(raw []byte, expected []string, message string) error {
	decoder := jsontext.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.ReadToken()
	if err != nil || first.Kind() != '{' {
		return errors.New(message)
	}
	keys := []string{}
	for decoder.PeekKind() != '}' {
		key, err := decoder.ReadToken()
		if err != nil {
			return err
		}
		keys = append(keys, key.String())
		if _, err = decoder.ReadValue(); err != nil {
			return err
		}
	}
	if _, err = decoder.ReadToken(); err != nil {
		return err
	}
	if !slices.Equal(keys, expected) {
		return errors.New(message)
	}
	return nil
}
func pinManifest(raw []byte, pin TerraBasePin) ([]byte, error) {
	decoder := jsontext.NewDecoder(bytes.NewReader(raw))
	var out bytes.Buffer
	encoder := jsontext.NewEncoder(&out, jsontext.WithIndent("  "))
	if _, err := decoder.ReadToken(); err != nil {
		return nil, err
	}
	if err := encoder.WriteToken(jsontext.BeginObject); err != nil {
		return nil, err
	}
	for decoder.PeekKind() != '}' {
		key, err := decoder.ReadToken()
		if err != nil {
			return nil, err
		}
		name := key.String()
		value, err := decoder.ReadValue()
		if err != nil {
			return nil, err
		}
		if name == "terrabase" {
			value, err = json.Marshal(pin)
			if err != nil {
				return nil, err
			}
		}
		if err = encoder.WriteToken(jsontext.String(name)); err != nil {
			return nil, err
		}
		if err = encoder.WriteValue(value); err != nil {
			return nil, err
		}
	}
	if err := encoder.WriteToken(jsontext.EndObject); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
