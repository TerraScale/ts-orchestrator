// Package sourcedigest reproduces the reviewed TerraBase tracked-source identity
// from Git objects, including the prepared Turso tree.
package sourcedigest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const Domain = "terrascale.terrabase.source-tree-sha256.v1\x00"

// Repository is historical hash framing for the fixed CI #1004 audit reproduction; it is never fetched.
const Repository = "https://git.terrascale.tech/TerraScale/TerraBase"
const QualificationSHA256 = "8ae3133ab66b6b300e5ad2e34ca42a11b61cef580657715480e68362f4bc7b09"
const ServerSHA256 = "bd940fe8055c61ea076e584b7d221c0f6b2c7dc1fee02232a82c476cb34ba81c"

type Entry struct {
	Mode, Kind, OID string
	Path            []byte
}
type Record struct {
	Mode   string
	Path   []byte
	Digest [32]byte
}
type Options struct{ TerraBaseRepo, PreparedTursoRepo, Qualification, Server, Out string }
type object = map[string]any

func git(ctx context.Context, repo string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repo}, args...)...)
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Git object read failed: %w", err)
	}
	return b, nil
}
func Fields(ctx context.Context, repo, tree string) ([]Entry, error) {
	wire, err := git(ctx, repo, "ls-tree", "-r", "-z", tree)
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for row := range bytes.SplitSeq(wire, []byte{0}) {
		if len(row) == 0 {
			continue
		}
		head, path, ok := bytes.Cut(row, []byte{'\t'})
		parts := bytes.Fields(head)
		if !ok || len(parts) != 3 {
			return nil, fmt.Errorf("invalid Git tree entry")
		}
		entries = append(entries, Entry{string(parts[0]), string(parts[1]), string(parts[2]), bytes.Clone(path)})
	}
	return entries, nil
}
func ContentHashes(ctx context.Context, repo string, entries []Entry) (records []Record, err error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "--batch")
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	defer func() {
		in.Close()
		if err != nil {
			cmd.Process.Kill()
		}
		waitErr := cmd.Wait()
		if err == nil && waitErr != nil {
			err = fmt.Errorf("Git batch blob reader failed: %w", waitErr)
		}
	}()
	reader := bufio.NewReader(out)
	for _, entry := range entries {
		if entry.Kind != "blob" {
			return nil, fmt.Errorf("unexpected non-blob at %q", entry.Path)
		}
		if _, err = fmt.Fprintln(in, entry.OID); err != nil {
			return nil, err
		}
		header, e := reader.ReadString('\n')
		if e != nil {
			return nil, e
		}
		parts := strings.Fields(header)
		if len(parts) != 3 || parts[0] != entry.OID || parts[1] != "blob" {
			return nil, fmt.Errorf("invalid Git blob response for %q", entry.Path)
		}
		size, e := strconv.ParseInt(parts[2], 10, 64)
		if e != nil || size < 0 {
			return nil, fmt.Errorf("invalid Git blob length")
		}
		leaf := sha256.New()
		if _, e = io.CopyN(leaf, reader, size); e != nil {
			return nil, fmt.Errorf("truncated Git blob for %q: %w", entry.Path, e)
		}
		term, e := reader.ReadByte()
		if e != nil || term != '\n' {
			return nil, fmt.Errorf("invalid Git blob terminator")
		}
		var digest [32]byte
		copy(digest[:], leaf.Sum(nil))
		records = append(records, Record{entry.Mode, bytes.Clone(entry.Path), digest})
	}
	return records, nil
}
func framed(h hash.Hash, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	h.Write(size[:])
	h.Write(value)
}

// Digest preserves the v1 domain, framing and bytewise Git path ordering.
func Digest(source, tree, tursoRevision, preparedTree string, records []Record) (string, error) {
	records = slices.Clone(records)
	slices.SortFunc(records, func(a, b Record) int { return bytes.Compare(a.Path, b.Path) })
	h := sha256.New()
	h.Write([]byte(Domain))
	for _, v := range []string{Repository, source, tree, tursoRevision, preparedTree} {
		framed(h, []byte(v))
	}
	for i, r := range records {
		if i > 0 && bytes.Equal(r.Path, records[i-1].Path) {
			return "", fmt.Errorf("source paths are not unique")
		}
		h.Write([]byte{'F', 0})
		framed(h, []byte(r.Mode))
		framed(h, r.Path)
		h.Write(r.Digest[:])
	}
	h.Write([]byte{'E', 'N', 'D', 0})
	var count [8]byte
	binary.BigEndian.PutUint64(count[:], uint64(len(records)))
	h.Write(count[:])
	return hex.EncodeToString(h.Sum(nil)), nil
}
func shaFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func mapOf(v any) object            { m, _ := v.(map[string]any); return m }
func str(m object, k string) string { v, _ := m[k].(string); return v }
func require(ok bool, message string) error {
	if !ok {
		return fmt.Errorf("%s", message)
	}
	return nil
}
func Generate(ctx context.Context, o Options) (object, error) {
	b, e := os.ReadFile(o.Qualification)
	if e != nil {
		return nil, e
	}
	sum := sha256.Sum256(b)
	if e = require(hex.EncodeToString(sum[:]) == QualificationSHA256, "qualification bytes differ from CI #1004 release receipt"); e != nil {
		return nil, e
	}
	var q object
	if e = json.Unmarshal(b, &q); e != nil {
		return nil, e
	}
	expected := object{"schema": "terrascale.terrabase.qualification.v2", "repository": "TerraScale/TerraBase", "source_revision": "1909dcd36c1f0e09189756d976891127312a2d19", "source_tree": "9c3855d1bcc53e45882a70da1e5beb94d0025eff", "turso_revision": "64b8ef5742fc18937f9c89806c81e3f6475dc7a3", "turso_source_tree": "1f89fbacaf2214005ecebf0d98a40c15d01ae5eb"}
	for k, v := range expected {
		if q[k] != v {
			return nil, fmt.Errorf("qualification %s mismatch", k)
		}
	}
	check := mapOf(q["verification"])
	if len(check) != 5 || check["workflow"] != "fast.yml" || check["job"] != "fast" || check["run_id"] != float64(11644) || check["run_number"] != float64(1004) || check["conclusion"] != "success" {
		return nil, fmt.Errorf("qualification Fast run mismatch")
	}
	source := str(q, "source_revision")
	treeBytes, e := git(ctx, o.TerraBaseRepo, "rev-parse", source+"^{tree}")
	if e != nil {
		return nil, e
	}
	tree := strings.TrimSpace(string(treeBytes))
	if tree != q["source_tree"] {
		return nil, fmt.Errorf("local source tree differs from qualification")
	}
	entries, e := Fields(ctx, o.TerraBaseRepo, source)
	if e != nil {
		return nil, e
	}
	var links []Entry
	var blobs []Entry
	for _, entry := range entries {
		if entry.Kind == "commit" {
			links = append(links, entry)
		} else {
			blobs = append(blobs, entry)
		}
	}
	if len(links) != 1 || string(links[0].Path) != "crates/turso" || links[0].OID != q["turso_revision"] {
		return nil, fmt.Errorf("source gitlinks differ from qualified Turso input")
	}
	lock, e := git(ctx, o.TerraBaseRepo, "show", source+":Cargo.lock")
	if e != nil {
		return nil, e
	}
	lockDigest := sha256.Sum256(lock)
	lockSHA := hex.EncodeToString(lockDigest[:])
	if len(lock) == 0 || lockSHA != q["cargo_lock_sha256"] {
		return nil, fmt.Errorf("Cargo.lock differs from qualification")
	}
	prepared := str(q, "turso_source_tree")
	kind, e := git(ctx, o.PreparedTursoRepo, "cat-file", "-t", prepared)
	if e != nil {
		return nil, e
	}
	if strings.TrimSpace(string(kind)) != "tree" {
		return nil, fmt.Errorf("prepared Turso tree object is missing")
	}
	turso, e := Fields(ctx, o.PreparedTursoRepo, prepared)
	if e != nil {
		return nil, e
	}
	for _, entry := range turso {
		if entry.Kind != "blob" {
			return nil, fmt.Errorf("prepared Turso has nested gitlink")
		}
	}
	var artifact object
	count := 0
	artifacts, _ := q["artifacts"].([]any)
	for _, v := range artifacts {
		item := mapOf(v)
		if item["name"] == "tb-server-linux-arm64" {
			artifact = item
			count++
		}
	}
	if count != 1 || artifact["target"] != "aarch64-unknown-linux-musl" || artifact["bytes"] != float64(45845688) || artifact["sha256"] != ServerSHA256 {
		return nil, fmt.Errorf("qualified ARM64 artifact target, size or digest mismatch")
	}
	info, e := os.Stat(o.Server)
	if e != nil {
		return nil, e
	}
	serverSHA, e := shaFile(o.Server)
	if e != nil {
		return nil, e
	}
	if info.Size() != 45845688 || serverSHA != ServerSHA256 {
		return nil, fmt.Errorf("local ARM64 artifact size or digest mismatch")
	}
	records, e := ContentHashes(ctx, o.TerraBaseRepo, blobs)
	if e != nil {
		return nil, e
	}
	preparedRecords, e := ContentHashes(ctx, o.PreparedTursoRepo, turso)
	if e != nil {
		return nil, e
	}
	for _, r := range preparedRecords {
		r.Path = append([]byte("crates/turso/"), r.Path...)
		records = append(records, r)
	}
	digest, e := Digest(source, tree, str(q, "turso_revision"), prepared, records)
	if e != nil {
		return nil, e
	}
	return object{"schema": "terrascale.terrabase.source-digest-candidate.v1", "status": "candidate_pending_independent_policy_review", "algorithm": "SHA-256 of DOMAIN; length-prefixed HTTPS repository, commit, Git tree, Turso gitlink and prepared tree; then Git-path-sorted mode/path and SHA-256 of every tracked blob; END and 8-byte big-endian file count", "domain_hex": hex.EncodeToString([]byte(Domain)), "repository": Repository, "source_revision": source, "source_tree_git_sha1": tree, "turso_gitlink_revision": q["turso_revision"], "turso_prepared_tree_git_sha1": prepared, "cargo_lock_sha256": lockSHA, "qualification_sha256": QualificationSHA256, "server_linux_arm64_sha256": ServerSHA256, "superproject_blob_count": len(blobs), "prepared_turso_blob_count": len(turso), "total_blob_count": len(records), "source_digest_sha256": digest}, nil
}

// WriteNew atomically publishes a receipt without replacing existing evidence.
func WriteNew(path string, value any) error {
	wire, e := json.Marshal(value, json.Deterministic(true), jsontext.Multiline(true), jsontext.WithIndent("  "))
	if e != nil {
		return e
	}
	wire = append(wire, '\n')
	f, e := os.CreateTemp(filepath.Dir(path), ".source-digest-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(wire); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Link(f.Name(), path)
}
func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	var o Options
	fs := flag.NewFlagSet("source-digest", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&o.TerraBaseRepo, "terrabase-repo", "", "qualified source repository")
	fs.StringVar(&o.PreparedTursoRepo, "prepared-turso-repo", "", "prepared Turso repository")
	fs.StringVar(&o.Qualification, "qualification", "", "retained qualification")
	fs.StringVar(&o.Server, "server", "", "retained ARM64 server")
	fs.StringVar(&o.Out, "out", "", "new receipt path")
	if e := fs.Parse(args); e != nil {
		return 2
	}
	if fs.NArg() != 0 || o.TerraBaseRepo == "" || o.PreparedTursoRepo == "" || o.Qualification == "" || o.Server == "" || o.Out == "" {
		fmt.Fprintln(errOut, "all source-digest flags are required")
		return 2
	}
	receipt, e := Generate(ctx, o)
	if e == nil {
		e = WriteNew(o.Out, receipt)
	}
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	fmt.Fprintln(out, receipt["source_digest_sha256"])
	return 0
}
