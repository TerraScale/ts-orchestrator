package firecracker

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"golang.org/x/sys/unix"
)

const ManagedMemberProfile = "managed-member-serving-v1"
const ManagedMemberGoTest = "TestManagedMemberFirecrackerSignedServing"
const S3Region = "sa-saopaulo-1"
const S3Host = "rustfs.terrabase.test"
const S3Endpoint = "https://rustfs.terrabase.test:9000"
const S3SecretOCID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const RustFSImage = "docker.io/rustfs/rustfs@sha256:ba0a1b53e36f321c0d46f3867104abef169f7bc59c467c664ddac87e7ddc9a8b"

var ManagedGuestIPs = map[string]string{"a": "10.77.39.11", "b": "10.77.39.12"}
var ManagedGuestMACs = map[string]string{"a": "02:fc:77:39:00:01", "b": "02:fc:77:39:00:02"}
var ManagedVolumeUUIDs = map[string]string{"a": "76f1b43d-7d79-4f41-9a6e-cc1f4aaab102", "b": "76f1b43d-7d79-4f41-9a6e-cc1f4aaab103"}
var ManagedMemberIDs = map[string]string{"a": "01HW000000E008000000000001", "b": "01HW000000E008000000000002"}
var ManagedMemberDirs = map[string]string{"a": "/srv/ts-managed/68982c69d15bbe68a9b7825b65d309f7", "b": "/srv/ts-managed/330d4aaac50138dd4a8cc8a4046894fc"}
var ManagedMaterials = [][2]string{{"authority_tbca", "authority.tbca"}, {"trusted_public_key", "trusted-public-key"}, {"server_crt", "server.crt"}, {"server_key", "server.key"}, {"client_ca_pem", "client-ca.pem"}, {"server_ca_pem", "server-ca.pem"}, {"client_managed_manifest", "client-managed-manifest.json"}, {"client_config", "client-config.json"}, {"client_chain", "client-chain.pem"}, {"client_private_key", "client-private-key.pem"}, {"client_api_keys", "client-api-keys.json"}, {"signed_v2_s3_config", "signed-v2-s3-config.json"}}
var ManagedCommonInputs = []string{"kernel", "rootfs", "firecracker", "go_host_test", "tb_server"}
var ManagedMemberInputs = []string{"volume_ext4", "authority_tbca", "trusted_public_key", "server_crt", "server_key", "client_ca_pem", "server_ca_pem", "client_managed_manifest", "client_config", "client_chain", "client_private_key", "client_api_keys", "client_api_token", "client_https_ca_pem", "signed_v2_s3_config"}
var opaqueIdentityPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40,64}$`)

type strictNumber string

func decodeStrict(data []byte) (any, error) {
	d := jsontext.NewDecoder(bytes.NewReader(data))
	v, e := readStrict(d)
	if e != nil {
		return nil, e
	}
	if _, e = d.ReadToken(); !errors.Is(e, io.EOF) {
		return nil, errors.New("unexpected trailing JSON")
	}
	return v, nil
}
func readStrict(d *jsontext.Decoder) (any, error) {
	t, e := d.ReadToken()
	if e != nil {
		return nil, e
	}
	switch t.Kind() {
	case '{':
		m := Object{}
		for d.PeekKind() != '}' {
			k, e := d.ReadToken()
			if e != nil {
				return nil, e
			}
			if k.Kind() != '"' {
				return nil, errors.New("JSON object key must be string")
			}
			name := k.String()
			if _, ok := m[name]; ok {
				return nil, errors.New("duplicate JSON field " + name)
			}
			v, e := readStrict(d)
			if e != nil {
				return nil, e
			}
			m[name] = v
		}
		_, e = d.ReadToken()
		return m, e
	case '[':
		a := []any{}
		for d.PeekKind() != ']' {
			v, e := readStrict(d)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		_, e = d.ReadToken()
		return a, e
	case '"':
		return t.String(), nil
	case '0':
		return strictNumber(t.String()), nil
	case 't':
		return true, nil
	case 'f':
		return false, nil
	case 'n':
		return nil, nil
	}
	return nil, errors.New("unsupported JSON token")
}
func integerExact(v any) (uint64, bool) {
	switch n := v.(type) {
	case strictNumber:
		if !regexp.MustCompile(`^(0|[1-9][0-9]*)$`).MatchString(string(n)) {
			return 0, false
		}
		u, e := strconv.ParseUint(string(n), 10, 64)
		return u, e == nil
	case int:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case uint64:
		return n, true
	case int64:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	}
	return 0, false
}
func exactValue(v any, want uint64) bool { n, ok := integerExact(v); return ok && n == want }
func strictToJSON(v any) any {
	switch v := v.(type) {
	case strictNumber:
		return jsontext.Value(v)
	case Object:
		m := Object{}
		for k, x := range v {
			m[k] = strictToJSON(x)
		}
		return m
	case []any:
		a := make([]any, len(v))
		for i, x := range v {
			a[i] = strictToJSON(x)
		}
		return a
	}
	return v
}
func exactFields(o Object, names []string) bool {
	if len(o) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := o[n]; !ok {
			return false
		}
	}
	return true
}
func DirectDigest(path string) (string, error) {
	before, e := os.Lstat(path)
	if e != nil {
		return "", e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return "", e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, e := f.Stat()
	if e != nil {
		return "", e
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", fmt.Errorf("file changed type or inode before hashing: %s", path)
	}
	b := make([]byte, 4<<20)
	h := sha256.New()
	if _, e = io.CopyBuffer(h, f, b); e != nil {
		return "", e
	}
	after, e := f.Stat()
	if e != nil {
		return "", e
	}
	afterPath, e := os.Lstat(path)
	if e != nil {
		return "", e
	}
	if !os.SameFile(opened, after) || !os.SameFile(after, afterPath) || opened.Size() != after.Size() || after.Size() != afterPath.Size() || !opened.ModTime().Equal(after.ModTime()) || !after.ModTime().Equal(afterPath.ModTime()) {
		return "", fmt.Errorf("file changed while hashing: %s", path)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

type ManagedInput struct {
	Path, SHA256 string
	Size         int64
}

func ExactManagedInput(name string, record Object) (ManagedInput, error) {
	if !exactFields(record, []string{"path", "sha256"}) {
		return ManagedInput{}, fmt.Errorf("%s: input must have exactly path and sha256", name)
	}
	path, expected := str(record["path"]), str(record["sha256"])
	if !filepath.IsAbs(path) || !shaPattern.MatchString(expected) {
		return ManagedInput{}, fmt.Errorf("%s: invalid absolute path or lowercase SHA-256", name)
	}
	s, e := os.Lstat(path)
	if e != nil {
		return ManagedInput{}, e
	}
	if !s.Mode().IsRegular() {
		return ManagedInput{}, fmt.Errorf("%s: input is not a regular, direct file", name)
	}
	h, e := DirectDigest(path)
	if e != nil {
		return ManagedInput{}, e
	}
	if h != expected {
		return ManagedInput{}, fmt.Errorf("%s: input SHA-256 mismatch: %s", name, path)
	}
	return ManagedInput{path, expected, s.Size()}, nil
}
func ReadS3Credential(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("S3 credential path must be absolute")
	}
	before, e := os.Lstat(path)
	if e != nil {
		return "", e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if e != nil {
		return "", e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return "", e
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !os.SameFile(before, info) || !ok || (owner.Uid != 0 && owner.Uid != uint32(os.Getuid())) || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 1024 {
		return "", errors.New("S3 credential file has unsafe ownership, mode or size")
	}
	b, e := io.ReadAll(io.LimitReader(f, 1025))
	if e != nil {
		return "", e
	}
	after, e := f.Stat()
	if e != nil {
		return "", e
	}
	if int64(len(b)) != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return "", errors.New("S3 credential file changed while reading")
	}
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return "", errors.New("S3 credential file contains invalid bytes")
		}
	}
	return string(b), nil
}
func S3Credentials(paths [2]string) ([2]string, error) {
	var values [2]string
	for i, p := range paths {
		v, e := ReadS3Credential(p)
		if e != nil {
			return values, e
		}
		if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(v) {
			return values, errors.New("S3 fixture credentials must use ASCII letters, digits, '-' or '_'")
		}
		values[i] = v
	}
	return values, nil
}
func S3TargetDigest(region, bucket, endpoint string) string {
	b := []byte("terrabase-s3-target-v1\x00")
	for _, v := range []string{region, bucket, endpoint} {
		b = binary.BigEndian.AppendUint64(b, uint64(len(v)))
		b = append(b, []byte(v)...)
	}
	return hashBytes(b)
}
func SignedS3Config(member string, r ManagedInput) (Object, error) {
	if r.Size <= 0 || r.Size > 16<<10 {
		return nil, fmt.Errorf("%s: signed S3 config size invalid", member)
	}
	before, e := os.Lstat(r.Path)
	if e != nil {
		return nil, e
	}
	fd, e := unix.Open(r.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), r.Path)
	defer f.Close()
	opened, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%s: signed S3 config is not a direct regular file", member)
	}
	raw, e := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if int64(len(raw)) != r.Size || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || hashBytes(raw) != r.SHA256 {
		return nil, fmt.Errorf("%s: signed S3 config changed", member)
	}
	v, e := decodeStrict(raw)
	if e != nil {
		return nil, fmt.Errorf("%s: signed S3 config is not JSON: %w", member, e)
	}
	c := object(v)
	if !exactFields(c, []string{"version", "ack_profile", "bucket", "region", "endpoint"}) || !exactValue(c["version"], 1) || c["ack_profile"] != "object_durable" || c["region"] != S3Region || c["endpoint"] != S3Endpoint || !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`).MatchString(str(c["bucket"])) || strings.Contains(str(c["bucket"]), "..") {
		return nil, fmt.Errorf("%s: signed S3 target is invalid", member)
	}
	// Preserve exporter field order while requiring its exact JSON string and number encodings.
	decoder := jsontext.NewDecoder(bytes.NewReader(raw))
	_, _ = decoder.ReadToken()
	var canonical bytes.Buffer
	canonical.WriteByte('{')
	first := true
	for decoder.PeekKind() != '}' {
		key, err := decoder.ReadToken()
		if err != nil {
			return nil, err
		}
		name := key.String()
		if _, err = decoder.ReadValue(); err != nil {
			return nil, err
		}
		if !first {
			canonical.WriteByte(',')
		}
		first = false
		encodedKey, err := json.Marshal(name)
		if err != nil {
			return nil, err
		}
		encodedValue, err := json.Marshal(strictToJSON(c[name]))
		if err != nil {
			return nil, err
		}
		canonical.Write(encodedKey)
		canonical.WriteByte(':')
		canonical.Write(encodedValue)
	}
	canonical.WriteByte('}')
	if !bytes.Equal(raw, canonical.Bytes()) {
		return nil, fmt.Errorf("%s: signed S3 config is not canonical exporter JSON", member)
	}
	return c, nil
}
func CanonicalUUID(s string) bool {
	parsed, err := uuid.Parse(s)
	return err == nil && parsed != uuid.Nil() && parsed.String() == s
}

func ManagedMemberDirectory(scope Object, attempt uint64) string {
	identity := fmt.Sprintf("%s/%s/%s/%v/%s/%s/%d", str(scope["cluster_id"]), str(scope["tenant_id"]), str(scope["database_id"]), scope["shard_id"], str(scope["member_id"]), str(scope["incarnation"]), attempt)
	return "/srv/ts-managed/" + head(hashBytes([]byte(identity)), 32)
}
func ValidateManagedConfig(member string, c Object, inputs map[string]ManagedInput) error {
	required := []string{"version", "node", "failure_domain", "member", "authority", "runtime", "volume_id", "attachment_id", "attachment_etag", "source_digest", "system_reserve_bytes", "collection_id", "schema_generation", "schema_digest", "document_id"}
	if !exactFields(c, required) {
		return fmt.Errorf("%s: guest_config has unexpected or missing fields", member)
	}
	fault := "FAULT-DOMAIN-1"
	inc := strings.Repeat("b", 32)
	peer := "b"
	if member == "b" {
		fault = "FAULT-DOMAIN-2"
		inc = strings.Repeat("c", 32)
		peer = "a"
	}
	if !exactValue(c["version"], 1) || c["node"] != "node-"+member || c["failure_domain"] != fault {
		return fmt.Errorf("%s: node or failure-domain mismatch", member)
	}
	binding := object(c["member"])
	if !exactFields(binding, []string{"scope", "host_attempt"}) || !exactValue(binding["host_attempt"], 1) {
		return fmt.Errorf("%s: member binding is malformed", member)
	}
	scope := object(binding["scope"])
	shard, shardOK := integerExact(scope["shard_id"])
	if !exactFields(scope, []string{"cluster_id", "tenant_id", "database_id", "shard_id", "member_id", "incarnation"}) || !opaqueIdentityPattern.MatchString(str(scope["cluster_id"])) || strings.Trim(str(scope["cluster_id"]), "0") == "" || !entityid.Valid(str(scope["tenant_id"])) || !entityid.Valid(str(scope["database_id"])) || !entityid.Valid(str(scope["member_id"])) || scope["member_id"] != ManagedMemberIDs[member] || !shardOK || shard == 0 || !opaqueIdentityPattern.MatchString(str(scope["incarnation"])) || strings.Trim(str(scope["incarnation"]), "0") == "" {
		return fmt.Errorf("%s: member scope is malformed", member)
	}
	if scope["incarnation"] != inc {
		return fmt.Errorf("%s: member incarnation mismatch", member)
	}
	if ManagedMemberDirectory(scope, 1) != ManagedMemberDirs[member] {
		return fmt.Errorf("%s: member scope derives an unexpected runtime directory", member)
	}
	authority := object(c["authority"])
	if !exactFields(authority, []string{"epoch", "configuration_id", "certificate_sha256", "tls_leaf_sha256"}) || !exactValue(authority["epoch"], 1) || authority["certificate_sha256"] != inputs["authority_tbca"].SHA256 {
		return fmt.Errorf("%s: signed authority hash mismatch", member)
	}
	for _, k := range []string{"configuration_id", "tls_leaf_sha256"} {
		if !shaPattern.MatchString(str(authority[k])) {
			return fmt.Errorf("%s: invalid authority %s", member, k)
		}
	}
	runtime := object(c["runtime"])
	runtimeKeys := []string{"device_path", "mount_path", "filesystem_uuid", "filesystem_type", "trusted_key_sha256", "server_certificate_sha256", "server_private_key_sha256", "client_ca_roots_sha256", "client_managed_material_manifest_sha256", "replication_listen_address", "replication_peer_member_id", "replication_peer_address", "replication_server_ca_sha256", "live_s3_config_sha256", "live_s3_target_sha256", "live_s3_credential"}
	if !exactFields(runtime, runtimeKeys) {
		return fmt.Errorf("%s: runtime pins are malformed", member)
	}
	credential := object(runtime["live_s3_credential"])
	if !exactFields(credential, []string{"secret_ocid", "version_number"}) || credential["secret_ocid"] != S3SecretOCID || !exactValue(credential["version_number"], 1) {
		return fmt.Errorf("%s: runtime S3 credential reference is malformed", member)
	}
	s3, e := SignedS3Config(member, inputs["signed_v2_s3_config"])
	if e != nil {
		return e
	}
	expected := Object{"device_path": "/dev/oracleoci/oraclevdb", "mount_path": ManagedMemberDirs[member] + "/volume", "filesystem_uuid": ManagedVolumeUUIDs[member], "filesystem_type": "ext4", "trusted_key_sha256": inputs["trusted_public_key"].SHA256, "server_certificate_sha256": inputs["server_crt"].SHA256, "server_private_key_sha256": inputs["server_key"].SHA256, "client_ca_roots_sha256": inputs["client_ca_pem"].SHA256, "client_managed_material_manifest_sha256": inputs["client_managed_manifest"].SHA256, "replication_listen_address": ManagedGuestIPs[member] + ":7000", "replication_peer_member_id": ManagedMemberIDs[peer], "replication_peer_address": ManagedGuestIPs[peer] + ":7000", "replication_server_ca_sha256": inputs["server_ca_pem"].SHA256, "live_s3_config_sha256": inputs["signed_v2_s3_config"].SHA256, "live_s3_target_sha256": S3TargetDigest(str(s3["region"]), str(s3["bucket"]), str(s3["endpoint"])), "live_s3_credential": Object{"secret_ocid": S3SecretOCID, "version_number": 1}}
	if !jsonEqual(strictToJSON(runtime), expected) {
		return fmt.Errorf("%s: runtime pins differ from immutable inputs or peer layout", member)
	}
	if c["volume_id"] != "ocid1.volume.fixture-"+member || c["attachment_id"] != "ocid1.volumeattachment.fixture-"+member || c["attachment_etag"] != "fixture-attachment-"+member {
		return fmt.Errorf("%s: fixture volume/attachment identity mismatch", member)
	}
	if !shaPattern.MatchString(str(c["source_digest"])) {
		return fmt.Errorf("%s: source digest invalid", member)
	}
	if !exactValue(c["system_reserve_bytes"], 1<<30) {
		return fmt.Errorf("%s: signed system reserve mismatch", member)
	}
	if c["collection_id"] != "1144GJ289144GJ289144GJ2891" || c["document_id"] != "01HW000000E008000000000011" || !exactValue(c["schema_generation"], 1) || !shaPattern.MatchString(str(c["schema_digest"])) {
		return fmt.Errorf("%s: active document binding mismatch", member)
	}
	return nil
}

type ManagedMember struct {
	Inputs     map[string]ManagedInput
	Config, S3 Object
}
type ManagedManifest struct {
	Raw     []byte
	SHA256  string
	Commits Object
	Inputs  map[string]ManagedInput
	Members map[string]ManagedMember
}

func LoadManagedManifest(path string) (ManagedManifest, error) {
	var manifest ManagedManifest
	raw, e := os.ReadFile(path)
	if e != nil {
		return manifest, e
	}
	if len(raw) > 64<<10 {
		return manifest, errors.New("manifest exceeds 64 KiB")
	}
	v, e := decodeStrict(raw)
	if e != nil {
		return manifest, e
	}
	m := object(v)
	if !exactFields(m, []string{"profile", "source_commits", "inputs", "members"}) || m["profile"] != ManagedMemberProfile {
		return manifest, errors.New("unsupported or malformed qualification manifest")
	}
	commits := object(m["source_commits"])
	if !exactFields(commits, []string{"orchestrator", "terrabase"}) || !commitPattern.MatchString(str(commits["orchestrator"])) || !commitPattern.MatchString(str(commits["terrabase"])) {
		return manifest, errors.New("source commits must be full hexadecimal IDs")
	}
	common, members := object(m["inputs"]), object(m["members"])
	if !exactFields(common, ManagedCommonInputs) || !exactFields(members, []string{"a", "b"}) {
		return manifest, errors.New("manifest has missing or extra common/member inputs")
	}
	manifest = ManagedManifest{Raw: raw, SHA256: hashBytes(raw), Commits: commits, Inputs: map[string]ManagedInput{}, Members: map[string]ManagedMember{}}
	for _, name := range ManagedCommonInputs {
		input, e := ExactManagedInput(name, object(common[name]))
		if e != nil {
			return manifest, e
		}
		if slices.Contains([]string{"firecracker", "go_host_test", "tb_server"}, name) {
			if e := unix.Access(input.Path, unix.X_OK); e != nil {
				return manifest, fmt.Errorf("%s: input must be executable", name)
			}
		}
		manifest.Inputs[name] = input
	}
	for _, member := range []string{"a", "b"} {
		record := object(members[member])
		if !exactFields(record, []string{"inputs", "guest_config"}) || !exactFields(object(record["inputs"]), ManagedMemberInputs) {
			return manifest, fmt.Errorf("%s: input names are incomplete", member)
		}
		inputs := map[string]ManagedInput{}
		for _, name := range ManagedMemberInputs {
			r, e := ExactManagedInput(member+"."+name, object(object(record["inputs"])[name]))
			if e != nil {
				return manifest, e
			}
			inputs[name] = r
		}
		if inputs["volume_ext4"].Size != 256<<20 {
			return manifest, fmt.Errorf("%s: volume image must be exactly 256 MiB", member)
		}
		config := object(record["guest_config"])
		if e = ValidateManagedConfig(member, config, inputs); e != nil {
			return manifest, e
		}
		s3, e := SignedS3Config(member, inputs["signed_v2_s3_config"])
		if e != nil {
			return manifest, e
		}
		manifest.Members[member] = ManagedMember{inputs, config, s3}
	}
	a, b := manifest.Members["a"], manifest.Members["b"]
	for _, key := range []string{"cluster_id", "tenant_id", "database_id", "shard_id"} {
		if !jsonEqual(object(object(a.Config["member"])["scope"])[key], object(object(b.Config["member"])["scope"])[key]) {
			return manifest, errors.New("members are not in one signed shard")
		}
	}
	for _, key := range []string{"epoch", "configuration_id", "certificate_sha256"} {
		if !jsonEqual(object(a.Config["authority"])[key], object(b.Config["authority"])[key]) {
			return manifest, errors.New("members disagree on signed authority")
		}
	}
	for _, key := range []string{"source_digest", "system_reserve_bytes", "collection_id", "schema_generation", "schema_digest", "document_id"} {
		if !jsonEqual(a.Config[key], b.Config[key]) {
			return manifest, errors.New("members disagree on transaction fixture")
		}
	}
	if !jsonEqual(a.S3, b.S3) {
		return manifest, errors.New("members disagree on signed S3 target")
	}
	return manifest, nil
}
