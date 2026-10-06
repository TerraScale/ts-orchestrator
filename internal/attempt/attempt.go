// Package attempt runs a resumable, signed regional controller bootstrap.
package attempt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/core"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
)

const Region = "sa-saopaulo-1"
const OperatorCLI = "terrascale-orchestrator-linux-amd64"

var Slots = []string{"controller-a", "controller-b", "controller-c"}
var Phases = []string{"material", "release", "image", "sign", "launch", "complete", "continuity", "operator", "services", "members", "terrabase"}

type Object = map[string]any
type Command struct {
	Args    []string
	Dir     string
	Env     []string
	Capture bool
}
type Runner func(context.Context, Command) (string, error)
type Attempt struct {
	Config                   Object
	Work, Deployment, Prefix string
	Env                      []string
	Executable               string
	Runner                   Runner
	// Cloud reaches OCI through the in-binary SDK; nil builds the operator
	// ~/.oci/config client on first use.
	Cloud       Cloud
	Now         func() time.Time
	Sleep       func(context.Context, time.Duration) error
	Out, ErrOut io.Writer
	ctx         context.Context
	err         error
}

func object(v any) Object {
	m, _ := v.(map[string]any)
	if m == nil {
		return Object{}
	}
	return m
}
func rows(v any) []any              { a, _ := v.([]any); return a }
func str(m Object, k string) string { s, _ := m[k].(string); return s }
func num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	}
	return 0
}
func text(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	case string:
		return n
	default:
		return fmt.Sprint(v)
	}
}
func (a *Attempt) fail(e error) {
	if a.err == nil && e != nil {
		a.err = e
	}
}
func (a *Attempt) Err() error { return a.err }
func New(ctx context.Context, configPath string, out, errOut io.Writer) (*Attempt, error) {
	b, e := os.ReadFile(configPath)
	if e != nil {
		return nil, e
	}
	var c Object
	if e = json.Unmarshal(b, &c); e != nil {
		return nil, e
	}
	if c == nil || str(c, "workdir") == "" || str(c, "deployment_id") == "" || str(c, "prefix") == "" {
		return nil, fmt.Errorf("attempt config lacks workdir, deployment_id or prefix")
	}
	work, e := filepath.Abs(str(c, "workdir"))
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(work, 0700); e != nil {
		return nil, e
	}
	executable, e := os.Executable()
	if e != nil {
		return nil, e
	}
	tools := object(c["tools"])
	env := append([]string{}, os.Environ()...)
	set := func(k, v string) {
		for i, s := range env {
			if strings.HasPrefix(s, k+"=") {
				env[i] = k + "=" + v
				return
			}
		}
		env = append(env, k+"="+v)
	}
	set("PATH", strings.Join([]string{str(tools, "fj_dir"), str(tools, "guestfs_tools_dir"), str(tools, "libguestfs_dir"), os.Getenv("PATH")}, ":"))
	set("LIBGUESTFS_PATH", str(tools, "libguestfs_appliance"))
	a := &Attempt{Config: c, Work: work, Deployment: str(c, "deployment_id"), Prefix: str(c, "prefix"), Env: env, Executable: executable, Now: time.Now, Out: out, ErrOut: errOut, ctx: ctx}
	a.Sleep = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
	a.Runner = func(ctx context.Context, c Command) (string, error) {
		cmd := exec.CommandContext(ctx, c.Args[0], c.Args[1:]...)
		cmd.Dir = c.Dir
		cmd.Env = c.Env
		cmd.Stderr = errOut
		var b bytes.Buffer
		if c.Capture {
			cmd.Stdout = &b
		} else {
			cmd.Stdout = out
		}
		e := cmd.Run()
		if e != nil {
			return "", fmt.Errorf("command %s failed: %w", strings.Join(c.Args[:min(4, len(c.Args))], " "), e)
		}
		return b.String(), nil
	}
	return a, nil
}
func (a *Attempt) Path(parts ...string) string {
	return filepath.Join(append([]string{a.Work}, parts...)...)
}
func exists(path string) bool { _, e := os.Stat(path); return e == nil }
func (a *Attempt) LegacyTools() bool {
	return exists(a.Path("source", "cmd", "ts-bootstrap", "main.go"))
}
func (a *Attempt) BootstrapTool() string {
	if a.LegacyTools() {
		return a.Path("tools", "ts-bootstrap")
	}
	return a.Path("tools", "ts-orch")
}
func (a *Attempt) ReleaseTool() string {
	if a.LegacyTools() {
		return a.Path("tools", "ts-release")
	}
	return a.BootstrapTool()
}
func (a *Attempt) Plan() string            { return a.Path("plan.json") }
func (a *Attempt) trust(key string) string { return str(object(a.Config["trust"]), key) }
func (a *Attempt) execute(c Command) string {
	if a.err != nil {
		return ""
	}
	if c.Dir == "" {
		c.Dir = "/tmp"
	}
	if c.Env == nil {
		c.Env = a.Env
	}
	fmt.Fprintf(a.Out, "%s $ %s ...\n", a.Now().UTC().Format("15:04:05"), strings.Join(c.Args[:min(3, len(c.Args))], " "))
	s, e := a.Runner(a.ctx, c)
	a.fail(e)
	return s
}
func (a *Attempt) run(args ...string) string { return a.execute(Command{Args: args}) }
func (a *Attempt) capture(args ...string) string {
	return a.execute(Command{Args: args, Capture: true})
}
func (a *Attempt) sudo(capture bool, args ...string) string {
	return a.execute(Command{Args: append([]string{"sudo", "--preserve-env=PATH,LIBGUESTFS_PATH"}, args...), Capture: capture})
}
func (a *Attempt) bootstrapCommand(args []string) []string {
	c := []string{a.BootstrapTool()}
	if !a.LegacyTools() {
		c = append(c, "bootstrap")
	}
	return append(c, args...)
}
func (a *Attempt) RunBootstrap(args ...string) string { return a.run(a.bootstrapCommand(args)...) }
func (a *Attempt) bootstrapCapture(args ...string) string {
	return a.capture(a.bootstrapCommand(args)...)
}
func (a *Attempt) bootstrapSudo(args ...string) string {
	return a.sudo(false, a.bootstrapCommand(args)...)
}
func (a *Attempt) release(args ...string) string {
	c := []string{a.ReleaseTool()}
	if !a.LegacyTools() {
		c = append(c, "release")
	}
	return a.run(append(c, args...)...)
}
func (a *Attempt) preview(args ...string) string {
	return a.run(append([]string{a.Executable, "oci-region", "preview"}, args...)...)
}

// cloud returns the OCI seam after announcing the operation, or nil once the
// attempt has failed.
func (a *Attempt) cloud(operation string) Cloud {
	if a.err != nil {
		return nil
	}
	if a.Cloud == nil {
		cloud, err := newSDKCloud(Region)
		if err != nil {
			a.fail(err)
			return nil
		}
		a.Cloud = cloud
	}
	fmt.Fprintf(a.Out, "%s OCI %s ...\n", a.Now().UTC().Format("15:04:05"), operation)
	return a.Cloud
}

// typed re-decodes value into the struct a signing command decodes, so the
// written candidate keeps that struct's canonical field order.
func typed[T any](a *Attempt, value any, into *T) *T {
	b, e := json.Marshal(value)
	if e == nil {
		e = json.Unmarshal(b, into, json.RejectUnknownMembers(true))
	}
	a.fail(e)
	return into
}

func (a *Attempt) read(path string) Object {
	if a.err != nil {
		return Object{}
	}
	b, e := os.ReadFile(path)
	a.fail(e)
	if e != nil {
		return Object{}
	}
	var o Object
	a.fail(json.Unmarshal(b, &o))
	return object(o)
}
func (a *Attempt) sha(path string) string {
	if a.err != nil {
		return ""
	}
	f, e := os.Open(path)
	a.fail(e)
	if e != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	_, e = io.Copy(h, f)
	a.fail(e)
	return hex.EncodeToString(h.Sum(nil))
}
func (a *Attempt) mkdir(path string) {
	if a.err == nil {
		a.fail(os.MkdirAll(path, 0700))
	}
}
func (a *Attempt) remove(path string) {
	if a.err != nil {
		return
	}
	e := os.Remove(path)
	if !os.IsNotExist(e) {
		a.fail(e)
	}
}
func (a *Attempt) WriteNew(path string, data []byte) error {
	if a.err != nil {
		return a.err
	}
	if b, e := os.ReadFile(path); e == nil {
		if !bytes.Equal(b, data) {
			a.fail(fmt.Errorf("%s exists with different content", path))
		}
		return a.err
	} else if !os.IsNotExist(e) {
		a.fail(e)
		return a.err
	}
	a.mkdir(filepath.Dir(path))
	if a.err != nil {
		return a.err
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	a.fail(e)
	if e != nil {
		return a.err
	}
	_, e = f.Write(data)
	a.fail(e)
	a.fail(f.Close())
	return a.err
}
func (a *Attempt) writeJSON(path string, value any) {
	if a.err != nil {
		return
	}
	b, e := json.Marshal(value, json.Deterministic(true))
	a.fail(e)
	// Keep the original bytes of an equivalent resumed record. Historical
	// Python formatting differs, and those bytes may already be signed.
	if old, err := os.ReadFile(path); err == nil {
		var retained any
		if err = json.Unmarshal(old, &retained); err == nil {
			canonical, err := json.Marshal(retained, json.Deterministic(true))
			if err == nil && bytes.Equal(canonical, b) {
				return
			}
		}
	}
	a.WriteNew(path, b)
}
func (a *Attempt) pair(path, flag string) []string {
	return []string{flag, path, flag + "-sha256", a.sha(path)}
}
func join(parts ...[]string) []string {
	var result []string
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}
func (a *Attempt) validity() (string, string) {
	path := a.Path("validity.json")
	if !exists(path) {
		issued := a.Now().UTC().Truncate(time.Second).Add(-time.Minute)
		a.writeJSON(path, Object{"issued_at": issued.Format(time.RFC3339), "expires_at": issued.Add(time.Duration(num(a.Config["validity_days"])*24) * time.Hour).Format(time.RFC3339)})
	}
	o := a.read(path)
	return str(o, "issued_at"), str(o, "expires_at")
}
func (a *Attempt) rootMaterial(f func(string)) {
	copy := strings.TrimSpace(a.sudo(true, "mktemp", "-d", "/run/ts-attempt-material.XXXXXX"))
	if a.err != nil {
		return
	}
	defer a.cleanup("rm", "-rf", "--", copy)
	a.sudo(false, "cp", "-a", a.Path("material")+"/.", copy)
	a.sudo(false, "chown", "-R", "root:root", copy)
	if a.err == nil {
		f(copy)
	}
}
func (a *Attempt) cleanup(args ...string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(a.ctx), 30*time.Second)
	defer cancel()
	_, err := a.Runner(ctx, Command{Args: append([]string{"sudo", "--preserve-env=PATH,LIBGUESTFS_PATH"}, args...), Dir: "/tmp", Env: a.Env})
	a.fail(err)
}
func (a *Attempt) rootSHA(path string) string {
	fields := strings.Fields(a.sudo(true, "sha256sum", path))
	if len(fields) == 0 {
		a.fail(fmt.Errorf("root material digest is absent"))
		return ""
	}
	return fields[0]
}
func (a *Attempt) FreshAdmission(name string) (string, string) {
	inventory, admission := a.Path(name+"-inventory.json"), a.Path(name+"-admission.json")
	a.captureInventory(a.Plan(), inventory)
	a.preview("admit", "--plan", a.Plan(), "--inventory", inventory, "--out", admission)
	return inventory, admission
}

// captureInventory writes a live inventory of plan, trying the read three
// times.
func (a *Attempt) captureInventory(plan, inventory string) {
	if a.err != nil {
		return
	}
	command := Command{Args: []string{a.Executable, "oci-region", "preview", "inventory", "--plan", plan, "--out", inventory}, Dir: "/tmp", Env: a.Env}
	var e error
	for range 3 {
		_, e = a.Runner(a.ctx, command)
		if e == nil {
			break
		}
		if a.ctx.Err() != nil {
			break
		}
	}
	if e != nil {
		a.fail(fmt.Errorf("live inventory failed three times: %w", e))
	}
}
func (a *Attempt) BuildTools() {
	orch := object(a.Config["orchestrator"])
	source := a.Path("source")
	if !exists(source) {
		a.run("git", "-C", str(orch, "repository"), "worktree", "add", "--detach", source, str(orch, "source_revision"))
	}
	if exists(a.BootstrapTool()) && exists(a.ReleaseTool()) {
		return
	}
	a.mkdir(a.Path("tools"))
	targets := [][2]string{{a.BootstrapTool(), "./cmd/terrascale-orchestrator"}}
	if a.LegacyTools() {
		targets = [][2]string{{a.BootstrapTool(), "./cmd/ts-bootstrap"}, {a.ReleaseTool(), "./cmd/ts-release"}}
	}
	for _, p := range targets {
		a.execute(Command{Args: []string{"go", "build", "-trimpath", "-buildvcs=true", "-o", p[0], p[1]}, Dir: source})
	}
}
func (a *Attempt) controllerObjectGrants(plan Object) {
	ids := object(plan["resource_ids"])
	expected, e := ociregion.RequiredControllerStatements(plan, ids, a.Prefix)
	a.fail(e)
	if a.err != nil {
		return
	}
	cloud := a.cloud("GetPolicy")
	if cloud == nil {
		return
	}
	policyID := str(ids, "controller_policy")
	statements, etag, e := cloud.PolicyStatements(a.ctx, policyID)
	a.fail(e)
	if a.err != nil || slices.Equal(statements, expected) {
		return
	}
	// The replacement is conditional on the version just read; without an
	// ETag it would silently overwrite a concurrent policy change.
	if etag == "" {
		a.fail(fmt.Errorf("OCI policy %s read returned no ETag; refusing an unconditional update", policyID))
		return
	}
	if cloud = a.cloud("UpdatePolicy"); cloud != nil {
		a.fail(cloud.ReplacePolicyStatements(a.ctx, policyID, etag, expected))
	}
	if a.err == nil {
		fmt.Fprintln(a.Out, "controller object grants now target prefix", a.Prefix, "- waiting for IAM propagation")
		a.fail(a.Sleep(a.ctx, time.Minute))
	}
}
func (a *Attempt) PhaseMaterial() {
	a.BuildTools()
	base := a.read(str(a.Config, "base_plan"))
	if a.err != nil {
		return
	}
	base["bootstrap_object_prefix"] = a.Prefix
	base["purpose"] = "GRU bootstrap attempt " + a.Deployment
	id := sha256.Sum256([]byte(a.Deployment + "\x00" + a.Prefix))
	base["seed_a_create_identity"] = "seed-a-" + hex.EncodeToString(id[:])[:16]
	for slot := range object(object(base["resource_ids"])["instances"]) {
		object(object(base["resource_ids"])["instances"])[slot] = nil
	}
	a.writeJSON(a.Plan(), base)
	// verify-anchor requires the identity's canonical field order, which a
	// map's sorted keys do not keep.
	a.writeJSON(a.Path("identity.json"), bootstrapstart.BakedIdentity{SchemaVersion: 1, DeploymentID: a.Deployment, Environment: "canary", Cell: "GRU"})
	material, record := a.Path("material"), a.Path("controller-material.json")
	if !exists(record) {
		hosts := hostMap(base)
		config := a.Path("controller-material.config.json")
		var slots []any
		for _, slot := range Slots {
			slots = append(slots, Object{"name": slot, "privateIp": hosts[slot]["private_ip"]})
		}
		a.writeJSON(config, Object{"cell": "gru", "clusterId": a.Deployment, "deploymentId": a.Deployment, "environment": "canary", "region": Region, "slots": slots, "subnetCidr": base["subnet_cidr"], "validityHours": num(a.Config["validity_days"]) * 24})
		a.RunBootstrap("generate-controller-material", "--config", config, "--config-sha256", a.sha(config), "--directory", material, "--out", record)
	}
	a.controllerObjectGrants(base)
	references := a.Path("controller-vault-references.json")
	if !exists(references) {
		inventory, admission := a.FreshAdmission("material")
		readback := a.Path("material-foundation.json")
		a.remove(readback)
		a.preview("inspect-foundation", "--plan", a.Plan(), "--inventory", inventory, "--admission", admission, "--out", readback)
		a.RunBootstrap("provision-controller-material", "--directory", material, "--manual-readback", readback, "--manual-readback-sha256", a.sha(readback), "--inventory", inventory, "--inventory-sha256", a.sha(inventory), "--cost-admission", admission, "--cost-admission-sha256", a.sha(admission), "--cost-plan-sha256", a.sha(a.Plan()), "--oci-config", ociConfig(), "--oci-profile", "DEFAULT", "--out", references)
	}
	issued, expires := a.validity()
	ledger := a.Path("ledger-delegation.signed.json")
	if !exists(ledger) {
		args := []string{"sign-ledger-delegation", "--deployment", a.Deployment, "--cell", "GRU", "--environment", "canary"}
		for _, slot := range Slots {
			args = append(args, "--slot", slot)
		}
		a.RunBootstrap(append(args, "--signer-public-key", record+".ledger.pem", "--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--issued-at", issued, "--expires-at", expires, "--out", ledger)...)
	}
	anchor := a.Path("anchor.signed.json")
	if !exists(anchor) {
		ids, buckets := object(base["resource_ids"]), object(base["foundation_buckets"])
		candidate := a.Path("anchor.candidate.json")
		a.writeJSON(candidate, Object{"schemaVersion": 3, "deploymentId": a.Deployment, "environment": "canary", "clusterId": a.Deployment, "cell": "GRU", "ociRegion": Region, "storageDomain": Object{"namespace": a.Config["namespace"], "ledgerBucket": buckets["ledger"], "ledgerKmsKeyOcid": ids["key"], "headBucket": buckets["head"], "headKmsKeyOcid": ids["key"], "prefix": a.Prefix}, "controllerSlots": Slots})
		expiry, e := time.Parse(time.RFC3339, expires)
		a.fail(e)
		validFor := int64(expiry.Sub(a.Now()).Seconds()) - 60
		a.RunBootstrap("sign-anchor", "--candidate", candidate, "--region-intent", str(a.Config, "region_intent"), "--ledger-delegation", ledger, "--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--valid-for", fmt.Sprintf("%ds", validFor), "--out", anchor)
	}
	a.RunBootstrap("verify-anchor", "--anchor", anchor, "--identity", a.Path("identity.json"), "--root-key", a.trust("root_public"))
	enrollment := a.Path("host-enrollment-public.json")
	if !exists(enrollment) {
		a.rootMaterial(func(copy string) {
			a.bootstrapSudo(join([]string{"render-host-enrollment-public"}, a.pair(record, "--material-record"), []string{"--material-directory", copy, "--out", enrollment})...)
		})
		a.sudo(false, "chown", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), enrollment)
	}
	peer := a.Path("peer-receipt-delegation.signed.json")
	if !exists(peer) {
		a.RunBootstrap("sign-peer-receipt-delegation", "--identity", a.Path("identity.json"), "--anchor", anchor, "--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--peer-public-key", record+".peer.pem", "--out", peer, "--valid-for", a.validFor())
	}
}
func ociConfig() string { home, _ := os.UserHomeDir(); return filepath.Join(home, ".oci", "config") }
func hostMap(plan Object) map[string]Object {
	m := map[string]Object{}
	for _, v := range rows(plan["hosts"]) {
		h := object(v)
		m[str(h, "slot")] = h
	}
	return m
}
func (a *Attempt) validFor() string { return text(num(a.Config["validity_days"])*24) + "h" }
func (a *Attempt) PhaseRelease() {
	orch := object(a.Config["orchestrator"])
	revision, runNumber := str(orch, "source_revision"), text(orch["ci_run_number"])
	release := a.Path("release")
	a.mkdir(release)
	s := a.capture("fj", "actions", "run-detail", runNumber, "-r", "TerraScale/ts-orchestrator")
	var detail Object
	if a.err == nil {
		a.fail(json.Unmarshal([]byte(s), &detail))
	}
	if a.err != nil {
		return
	}
	if detail["head_sha"] != revision || detail["status"] != "success" {
		a.fail(fmt.Errorf("CI run %s is not a successful run of %s", runNumber, revision))
		return
	}
	tag := "ci-" + revision + "-run-" + text(detail["run_id"])
	for _, asset := range []string{"qualification.json", "terrascale-orchestrator-linux-arm64", OperatorCLI} {
		if !exists(filepath.Join(release, asset)) {
			a.run("fj", "release", "asset", "download", "-r", "TerraScale/ts-orchestrator", tag, asset, "-o", filepath.Join(release, asset))
		}
	}
	issued, expires := a.validity()
	delegation := filepath.Join(release, "binary-delegation.signed.json")
	if !exists(delegation) {
		a.release("sign-delegation", "--subject-public-key", a.trust("release_leaf_public"), "--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--source-revision", revision, "--arch", "arm64", "--environment", "canary", "--issued-at", issued, "--expires-at", expires, "--out", delegation)
	}
	candidate, receipt := filepath.Join(release, "binary-receipt.candidate.json"), filepath.Join(release, "binary-receipt.signed.json")
	binary, qualification := filepath.Join(release, "terrascale-orchestrator-linux-arm64"), filepath.Join(release, "qualification.json")
	if !exists(candidate) {
		a.release("binary-candidate", "--binary", binary, "--source-revision", revision, "--qualification", qualification, "--out", candidate)
	}
	if !exists(receipt) {
		a.release("sign-binary", "--candidate", candidate, "--binary", binary, "--qualification", qualification, "--delegation", delegation, "--root-key", a.trust("root_public"), "--signing-key", a.trust("release_leaf_private"), "--environment", "canary", "--out", receipt)
	}
	a.release("verify-binary", "--receipt", receipt, "--delegation", delegation, "--root-key", a.trust("root_public"), "--binary", binary, "--qualification", qualification, "--environment", "canary")
}
func (a *Attempt) Kernel() string              { return a.Path("image", "guest-kernel") }
func (a *Attempt) ImageReceipt() string        { return a.Path("image", "image-receipt.signed.json") }
func (a *Attempt) ImageID() string             { return str(a.read(a.Path("image", "import.json")), "image_id") }
func (a *Attempt) Manifest(slot string) string { return a.Path("signed", slot+".manifest.signed.json") }
func (a *Attempt) PhaseImage() {
	image := object(a.Config["image"])
	orch := object(a.Config["orchestrator"])
	revision := str(orch, "source_revision")
	release := a.Path("release")
	qcow2 := a.Path("image", "terrascale-arm64.qcow2")
	if !exists(qcow2) {
		a.mkdir(filepath.Dir(qcow2))
		priority := object(image["priority"])
		args := []string{"bash", a.Path("source", "deploy/image/build-offline.sh"), "--base", str(image, "base_qcow2"), "--kernel-release", str(image, "kernel_release"), "--binary", filepath.Join(release, "terrascale-orchestrator-linux-arm64"), "--qualification", filepath.Join(release, "qualification.json"), "--source-revision", revision, "--native-verifier-binary", str(image, "native_verifier"), "--native-verifier-sha256", str(image, "native_verifier_sha256"), "--release-tool", a.ReleaseTool(), "--bootstrap-root", a.trust("root_public"), "--timesyncd-config", str(image, "timesyncd_config"), "--runtime-priority-profile-id", str(priority, "profile_id")}
		for _, p := range [][2]string{{"--runtime-priority-system-reserve-bytes", "system_reserve_bytes"}, {"--host-memory-min-bytes", "host_memory_min_bytes"}, {"--host-memory-low-bytes", "host_memory_low_bytes"}, {"--controller-memory-min-bytes", "controller_memory_min_bytes"}, {"--controller-memory-low-bytes", "controller_memory_low_bytes"}, {"--system-slice-memory-min-bytes", "system_slice_memory_min_bytes"}, {"--system-slice-memory-low-bytes", "system_slice_memory_low_bytes"}} {
			args = append(args, p[0], text(priority[p[1]]))
		}
		// NetBird is optional: a cell whose servers enroll as NetBird peers
		// bakes the pinned client and enrollment config into its image.
		if binary := str(image, "netbird_binary"); binary != "" {
			args = append(args, "--netbird-binary", binary, "--netbird-sha256", str(image, "netbird_sha256"), "--netbird-config", str(image, "netbird_config"))
		}
		args = append(args, "--out", qcow2, "--kernel-out", a.Kernel())
		a.execute(Command{Args: args, Dir: a.Path("source")})
	}
	digest := a.sha(qcow2)
	imported := a.Path("image", "import.json")
	if !exists(imported) {
		plan := a.read(a.Plan())
		if len(revision) < 12 || len(digest) < 12 {
			a.fail(fmt.Errorf("image source or digest is malformed"))
			return
		}
		// The cell image name is static; the revision and digest are in the
		// signed image receipt.
		name, e := naming.RegionCell("GRU").Image()
		a.fail(e)
		a.run(a.Executable, "oci-region", "import-image", "--qcow2", qcow2, "--sha256", digest, "--compartment-id", str(object(plan["resource_ids"]), "control_compartment"), "--namespace", str(a.Config, "namespace"), "--bucket", str(image, "bucket"), "--display-name", name, "--out", imported)
	}
	imageID := str(a.read(imported), "image_id")
	issued, expires := a.validity()
	delegation := a.Path("image", "image-delegation.signed.json")
	if !exists(delegation) {
		a.release("sign-delegation", "--subject-public-key", a.trust("release_leaf_public"), "--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--source-revision", revision, "--arch", "arm64", "--environment", "canary", "--image-cell", "GRU", "--image-ocid", imageID, "--previous-delegation", filepath.Join(release, "binary-delegation.signed.json"), "--issued-at", issued, "--expires-at", expires, "--out", delegation)
	}
	candidate, receipt := a.Path("image", "image-receipt.candidate.json"), a.ImageReceipt()
	common := []string{"--binary-receipt", filepath.Join(release, "binary-receipt.signed.json"), "--binary", filepath.Join(release, "terrascale-orchestrator-linux-arm64"), "--qualification", filepath.Join(release, "qualification.json"), "--delegation", delegation, "--root-key", a.trust("root_public"), "--environment", "canary", "--image-file", qcow2, "--base-image-file", str(image, "base_qcow2"), "--kernel-file", a.Kernel()}
	if !exists(candidate) {
		a.release(join([]string{"image-candidate"}, common, []string{"--base-image-ocid", str(image, "base_image_ocid"), "--base-image-region", "GRU", "--kernel-release", str(image, "kernel_release"), "--image-ocid", imageID, "--region", "GRU", "--out", candidate})...)
	}
	if !exists(receipt) {
		a.release(join([]string{"sign-image", "--candidate", candidate}, common, []string{"--signing-key", a.trust("release_leaf_private"), "--out", receipt})...)
	}
	a.release("verify-image", "--receipt", receipt, "--delegation", delegation, "--root-key", a.trust("root_public"), "--image-file", qcow2, "--base-image-file", str(image, "base_qcow2"), "--kernel-file", a.Kernel(), "--region", "GRU", "--environment", "canary")
}
func (a *Attempt) PhaseSign() {
	signed := a.Path("signed")
	a.mkdir(signed)
	plan := a.read(a.Plan())
	hosts := hostMap(plan)
	ids := object(plan["resource_ids"])
	anchor := a.Path("anchor.signed.json")
	anchorPayload := object(a.read(anchor)["payload"])
	references := rows(a.read(a.Path("controller-vault-references.json"))["references"])
	members := []Object{hosts["member-a"], hosts["member-b"]}
	region := a.Path("signed", "oci-region.json")
	a.writeJSON(region, Object{"region": "GRU", "generation": 1, "endpoint": "https://iaas." + Region + ".oraclecloud.com", "compartment_id": ids["workload_compartment"], "image_compartment_id": ids["control_compartment"], "availability_domain": plan["availability_domain"], "fault_domains": []any{members[0]["fault_domain"], members[1]["fault_domain"]}, "subnet_id": ids["subnet"], "network_security_group_ids": []any{ids["workload_network_security_group"]}, "image_id": a.ImageID(), "shape": "VM.Standard.A1.Flex", "boot_volume_gb": 50, "boot_volume_vpus_per_gb": plan["volume_vpus_per_gb"], "data_volume_vpus_per_gb": plan["volume_vpus_per_gb"], "max_data_volume_gb": max(num(members[0]["data_gb"]), num(members[1]["data_gb"])), "owner": a.Prefix})
	sidecars := join(a.pair(str(a.Config, "region_intent"), "--oci-region-intent"), a.pair(region, "--oci-region-config"), a.pair(str(a.Config, "placement_config"), "--placement-config"))
	receipt, delegation := a.ImageReceipt(), a.Path("image", "image-delegation.signed.json")
	// Embed the signed envelope's bytes: its payload is raw JSON, and
	// re-encoding a decoded map sorts the payload's keys and voids the
	// signature.
	peerWire, e := os.ReadFile(a.Path("peer-receipt-delegation.signed.json"))
	a.fail(e)
	peer := jsontext.Value(bytes.TrimSpace(peerWire))
	domain := a.read(str(a.Config, "managed_material_domain"))
	domain["nativeVerifierSha256"] = object(a.Config["image"])["native_verifier_sha256"]
	var profiles []any
	for _, slot := range Slots {
		nsgs := []string{str(ids, "network_security_group")}
		profiles = append(profiles, Object{"slot": slot, "compartmentOcid": ids["control_compartment"], "availabilityDomain": plan["availability_domain"], "faultDomain": hosts[slot]["fault_domain"], "subnetOcid": ids["subnet"], "networkSecurityGroupOcids": nsgs, "shape": hosts[slot]["shape"]})
	}
	// ts-auth can join a controller config only before it is first signed,
	// so a cell that runs ts-auth renders it into every slot's config, and a
	// resumed attempt refuses configs rendered the other way.
	authProfile, authService := str(a.Config, "ts_auth_profile"), str(a.Config, "ts_auth_service")
	if (authProfile == "") != (authService == "") {
		a.fail(errors.New("attempt config needs ts_auth_profile and ts_auth_service together"))
		return
	}
	for _, slot := range Slots {
		config := a.Path("signed", slot+".config.json")
		if !exists(config) {
			continue
		}
		_, rendered := object(object(a.read(config)["controller"])["workloads"])["ts-auth"]
		if rendered != (authProfile != "") {
			a.fail(fmt.Errorf("%s does not match the attempt's ts_auth_profile; a signed controller config cannot gain or lose ts-auth", config))
			return
		}
	}
	for _, slot := range Slots {
		manifest := a.Manifest(slot)
		if exists(manifest) {
			continue
		}
		var secrets []any
		for _, v := range references {
			ref := object(object(v)["reference"])
			if ref["purpose"] == "regional-shared" || ref["purpose"] == "host-issuer" || ref["slot"] == slot {
				secrets = append(secrets, ref)
			}
		}
		candidate, config := a.Path("signed", slot+".candidate.json"), a.Path("signed", slot+".config.json")
		a.writeJSON(candidate, Object{"schemaVersion": 2, "deploymentId": a.Deployment, "environment": "canary", "clusterId": a.Deployment, "cell": "GRU", "ociRegion": Region, "intentGeneration": anchorPayload["initialRegionIntentGeneration"], "intentSha256": anchorPayload["initialRegionIntentSha256"], "controllerRole": "controller", "slot": slot, "seedSlot": "controller-a", "controllerSlots": Slots, "profiles": profiles, "imageOcid": a.ImageID(), "imageArchitecture": "linux-arm64", "releaseReceiptSha256": a.sha(receipt), "peerReceiptDelegation": peer, "storageDomain": anchorPayload["storageDomain"], "managedMaterial": domain, "secrets": secrets})
		if !exists(config) {
			args := join([]string{"render-controller-config"}, a.pair(candidate, "--candidate"), a.pair(a.Path("controller-material.json"), "--material-record"), a.pair(str(a.Config, "operator_grant"), "--operator-grant"), sidecars)
			if profile := str(a.Config, "terrabase_profile"); profile != "" {
				args = append(args, a.pair(profile, "--terrabase-profile")...)
			}
			if authProfile != "" {
				args = append(args, join(a.pair(authProfile, "--ts-auth-profile"), a.pair(authService, "--ts-auth-service"))...)
			}
			if snapshot := str(a.Config, "kv_snapshot"); snapshot != "" {
				args = append(args, a.pair(snapshot, "--kv-snapshot")...)
			}
			a.RunBootstrap(append(args, "--out", config)...)
		}
		a.RunBootstrap(join([]string{"sign-manifest", "--candidate", candidate}, a.pair(config, "--controller-config"), sidecars, []string{"--anchor", anchor, "--image-receipt", receipt, "--release-delegation", delegation, "--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--out", manifest, "--valid-for", a.validFor()})...)
		verified := a.bootstrapCapture("verify-manifest", "--anchor", anchor, "--manifest", manifest, "--identity", a.Path("identity.json"), "--slot", slot, "--image-ocid", a.ImageID(), "--root-key", a.trust("root_public"))
		a.WriteNew(a.Path("signed", slot+".verify.json"), []byte(verified))
	}
	founder, selection := a.Path("signed", "founder-plan.signed.json"), a.Path("signed", "founder-selection.signed.json")
	var manifests []string
	for _, slot := range Slots {
		manifests = append(manifests, "--manifest", a.Manifest(slot))
	}
	identity := a.Path("identity.json")
	if !exists(founder) {
		vault := Object{}
		for _, v := range references {
			r := object(object(v)["reference"])
			vault[str(r, "targetFile")] = r["sha256"]
		}
		var peers []any
		budget := Object{"wholeOcpus": 0.0, "memoryInGb": 0.0, "bootVolumeGb": 0.0}
		for _, slot := range []string{"controller-b", "controller-c"} {
			profile := object(a.read(a.Path("signed", slot+".verify.json"))["profile"])
			h := hosts[slot]
			var routes []any
			for _, name := range Slots {
				if name != slot {
					routes = append(routes, Object{"slot": name, "privateIp": hosts[name]["private_ip"], "port": 6222})
				}
			}
			peers = append(peers, Object{"slot": slot, "manifestSha256": a.sha(a.Manifest(slot)), "imageOcid": a.ImageID(), "image_compartment_ocid": ids["control_compartment"], "compartmentOcid": profile["compartmentOcid"], "availabilityDomain": profile["availabilityDomain"], "faultDomain": profile["faultDomain"], "subnetOcid": profile["subnetOcid"], "networkSecurityGroupOcids": profile["networkSecurityGroupOcids"], "shape": h["shape"], "wholeOcpus": h["ocpus"], "memoryInGb": h["memory_gb"], "bootVolumeGb": h["boot_gb"], "bootVolumeTier": "balanced", "privateIp": h["private_ip"], "routeEndpoints": routes, "clientEndpoints": []any{Object{"slot": slot, "privateIp": h["private_ip"], "port": 4222}}, "tlsMaterial": Object{"clientCaSha256": vault["ca.pem"], "clientCertificateSha256": vault[slot+"-tls-cert.pem"], "clientPrivateKeySha256": vault[slot+"-tls-key.pem"], "routeCaSha256": vault["ca.pem"], "routeCertificateSha256": vault[slot+"-tls-cert.pem"], "routePrivateKeySha256": vault[slot+"-tls-key.pem"]}})
			budget["wholeOcpus"] = num(budget["wholeOcpus"]) + num(h["ocpus"])
			budget["memoryInGb"] = num(budget["memoryInGb"]) + num(h["memory_gb"])
			budget["bootVolumeGb"] = num(budget["bootVolumeGb"]) + num(h["boot_gb"])
		}
		deadline := a.Now().UTC().Add(22 * time.Hour).Truncate(time.Minute)
		candidate := a.Path("signed", "founder-plan.candidate.json")
		if exists(candidate) {
			// Resume the already rendered launch window rather than changing a
			// record that may have been retained before signing was interrupted.
			retained := a.read(candidate)
			var err error
			deadline, err = time.Parse(time.RFC3339, str(retained, "launchDeadline"))
			a.fail(err)
		}
		// sign-founder-plan requires FounderPlan's canonical field order.
		a.writeJSON(candidate, typed(a, Object{"schemaVersion": 1, "deploymentId": a.Deployment, "cell": "GRU", "environment": "canary", "seedSlot": "controller-a", "anchorSha256": a.sha(anchor), "controllerSlots": Slots, "seedManifestSha256": a.sha(a.Manifest("controller-a")), "seedPrivateIp": hosts["controller-a"]["private_ip"], "peers": peers, "budget": budget, "launchDeadline": deadline.Format(time.RFC3339)}, &bootstrap.FounderPlan{}))
		a.RunBootstrap(join([]string{"sign-founder-plan", "--candidate", candidate, "--identity", identity, "--anchor", anchor}, manifests, []string{"--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--out", founder, "--valid-for", "24h"})...)
	}
	if !exists(selection) {
		candidate := a.Path("signed", "founder-selection.candidate.json")
		var ms []any
		for _, slot := range Slots {
			ms = append(ms, Object{"slot": slot, "sha256": a.sha(a.Manifest(slot))})
		}
		// The selector signers require FounderSelection's canonical field order.
		a.writeJSON(candidate, typed(a, Object{"schemaVersion": 1, "deploymentId": a.Deployment, "cell": "GRU", "environment": "canary", "generation": 1, "planSha256": a.sha(founder), "anchorSha256": a.sha(anchor), "manifests": ms}, &bootstrapstart.FounderSelection{}))
		a.RunBootstrap(join([]string{"sign-initial-founder-selection", "--candidate", candidate, "--identity", identity, "--anchor", anchor, "--plan", founder}, manifests, []string{"--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--out", selection, "--valid-for", "24h"})...)
	}
	a.RunBootstrap(join([]string{"publish-initial-founder-selection", "--selection", selection, "--identity", identity, "--anchor", anchor, "--plan", founder}, manifests, []string{"--root-key", a.trust("root_public"), "--oci-config", ociConfig(), "--oci-profile", "DEFAULT"})...)
}
func (a *Attempt) SeedArgs() []string {
	args := []string{"--identity", a.Path("identity.json"), "--anchor", a.Path("anchor.signed.json"), "--founder-plan", a.Path("signed", "founder-plan.signed.json"), "--root-key", a.trust("root_public")}
	for _, slot := range Slots {
		args = append(args, "--manifest", a.Manifest(slot))
	}
	return args
}

// slotRecordPrefixes are the bootstrap ledger paths of one deployment. A
// cell's earlier deployment keeps its records under the same object prefix,
// so a new deployment re-founds the cell beside them.
func slotRecordPrefixes(prefix, deployment string) []string {
	return []string{prefix + "/bootstrap/v1/" + deployment + "/", prefix + "/bootstrap/v2/" + deployment + "/"}
}

func (a *Attempt) listObjects(bucket, prefix string) []string {
	cloud := a.cloud("ListObjects " + bucket)
	if cloud == nil {
		return nil
	}
	names, e := cloud.ListObjects(a.ctx, str(a.Config, "namespace"), bucket, prefix)
	a.fail(e)
	return names
}

// bindSeed records the launched controller A in the attempt plan: admission
// accepts a live seed instance only when the plan binds its exact OCID.
func (a *Attempt) bindSeed() {
	b, e := os.ReadFile(a.Path("launch", "controller-a.ocid"))
	if a.err != nil || errors.Is(e, os.ErrNotExist) {
		return
	}
	a.fail(e)
	plan := a.read(a.Plan())
	instances := object(object(plan["resource_ids"])["instances"])
	if a.err != nil || instances == nil {
		a.fail(fmt.Errorf("attempt plan has no instance bindings"))
		return
	}
	id := strings.TrimSpace(string(b))
	if bound, ok := instances["controller-a"].(string); ok && bound != id {
		a.fail(fmt.Errorf("attempt plan binds controller A %s, not the launched %s", bound, id))
		return
	}
	if instances["controller-a"] == id {
		return
	}
	instances["controller-a"] = id
	// The plan is otherwise write-once; this one recorded fact replaces it.
	wire, e := json.Marshal(plan, json.Deterministic(true))
	a.fail(e)
	temporary := a.Plan() + ".bind"
	if a.err == nil {
		a.fail(os.WriteFile(temporary, wire, 0600))
	}
	if a.err == nil {
		a.fail(os.Rename(temporary, a.Plan()))
	}
}
func (a *Attempt) PhaseLaunch() {
	launch := a.Path("launch")
	ocid := filepath.Join(launch, "controller-a.ocid")
	if exists(ocid) {
		b, e := os.ReadFile(ocid)
		a.fail(e)
		fmt.Fprintln(a.Out, "controller A already launched:", strings.TrimSpace(string(b)))
		return
	}
	if exists(filepath.Join(launch, "seed-reservation.json")) {
		a.fail(fmt.Errorf("a seed reservation exists without a launched controller A; reconcile before retrying"))
		return
	}
	a.mkdir(launch)
	inventory, admission := a.FreshAdmission("launch/launch")
	image := object(a.Config["image"])
	reviewed := filepath.Join(launch, "reviewed-seed-plan.json")
	a.remove(reviewed)
	args := []string{"seed-preflight", "--plan", a.Plan(), "--inventory", inventory, "--admission", admission, "--bootstrap-tool", a.BootstrapTool(), "--anchor", a.Path("anchor.signed.json"), "--manifest", a.Manifest("controller-a"), "--identity", a.Path("identity.json"), "--bootstrap-root", a.trust("root_public"), "--image-ocid", a.ImageID(), "--release-tool", a.ReleaseTool()}
	if a.LegacyTools() {
		args = append(args, "--legacy-bootstrap-tool", "--legacy-release-tool")
	}
	args = append(args, "--image-receipt", a.ImageReceipt(), "--release-delegation", a.Path("image", "image-delegation.signed.json"), "--release-root", a.trust("root_public"), "--image-file", a.Path("image", "terrascale-arm64.qcow2"), "--base-image-file", str(image, "base_qcow2"), "--kernel-file", a.Kernel(), "--out", reviewed)
	a.preview(args...)
	launchInput := filepath.Join(launch, "controller-a-launch.json")
	a.remove(launchInput)
	a.preview("seed-launch", "--plan", a.Plan(), "--reviewed-plan", reviewed, "--manifest", a.Manifest("controller-a"), "--identity", a.Path("identity.json"), "--anchor", a.Path("anchor.signed.json"), "--host-enrollment", a.Path("host-enrollment-public.json"), "--owner-ssh-public-key", str(a.Config, "owner_ssh_public_key"), "--out", launchInput)
	if a.err != nil {
		return
	}
	// Decode the exact launch request before any reservation is signed, so
	// a malformed input can never strand a published reservation.
	wire, e := os.ReadFile(launchInput)
	a.fail(e)
	if a.err != nil {
		return
	}
	details, e := LaunchDetails(wire)
	a.fail(e)
	if a.err != nil {
		return
	}
	plan := a.read(a.Plan())
	for _, bucket := range []string{"head", "ledger"} {
		for _, prefix := range slotRecordPrefixes(a.Prefix, a.Deployment) {
			for _, name := range a.listObjects(str(object(plan["foundation_buckets"]), bucket), prefix) {
				if !strings.Contains(name, "/founder-selection/") {
					a.fail(fmt.Errorf("attempt deployment already holds slot records: %s", name))
					return
				}
			}
		}
	}
	if a.requireAdmission(admission); a.err != nil {
		return
	}
	reservation := filepath.Join(launch, "seed-reservation.json")
	reviewedSHA := a.sha(reviewed)
	createIdentity := str(a.read(reviewed), "create_identity")
	a.RunBootstrap(join([]string{"sign-external-seed-reservation"}, a.SeedArgs(), []string{"--reviewed-plan", reviewed, "--reviewed-plan-sha256", reviewedSHA, "--create-identity", createIdentity, "--ledger-signing-key", a.Path("material", "founder-ledger.key"), "--out", reservation})...)
	a.RunBootstrap(join([]string{"publish-external-seed-reservation"}, a.SeedArgs(), []string{"--reservation", reservation, "--oci-config", ociConfig(), "--oci-profile", "DEFAULT"})...)
	a.launchInstance("controller A", details, wire, filepath.Join(launch, "controller-a-launch-submit.json"), ocid)
}
func (a *Attempt) requireAdmission(admission string) {
	expires, e := time.Parse(time.RFC3339Nano, str(a.read(admission), "expires_at"))
	a.fail(e)
	if expires.Sub(a.Now()) < 180*time.Second {
		a.fail(fmt.Errorf("cost admission has less than 180 seconds left"))
	}
}

// launchInstance submits the exact launch input, then records the CLI-shaped
// submit document and the instance ID.
func (a *Attempt) launchInstance(who string, details core.LaunchInstanceDetails, wire []byte, submit, ocid string) string {
	cloud := a.cloud("LaunchInstance")
	if cloud == nil {
		return ""
	}
	launched, workRequest, e := cloud.LaunchInstance(a.ctx, details, LaunchRetryToken(wire))
	a.fail(e)
	if a.err != nil {
		return ""
	}
	data, e := sdkcli.Render(launched)
	a.fail(e)
	var rendered any
	if a.err == nil {
		a.fail(json.Unmarshal(data, &rendered))
	}
	if a.err != nil {
		return ""
	}
	// The retained record keeps the CLI-shaped {"data": ...} document.
	submitted := Object{"data": rendered, "opc-work-request-id": workRequest}
	id := str(object(rendered), "id")
	if id == "" {
		a.fail(fmt.Errorf("%s launch omitted instance ID", who))
		return ""
	}
	a.writeJSON(submit, submitted)
	a.WriteNew(ocid, []byte(id+"\n"))
	fmt.Fprintln(a.Out, "launched", who, id)
	return id
}

// waitRunning polls an instance until it is RUNNING, 60 times 10 s apart.
func (a *Attempt) waitRunning(who, instance string) {
	// Announce the poll once; the seam is reused for every attempt.
	cloud := a.cloud("GetInstance (polling until RUNNING)")
	if cloud == nil {
		return
	}
	for range 60 {
		state, e := cloud.GetInstance(a.ctx, instance)
		a.fail(e)
		if a.err != nil || state.LifecycleState == "RUNNING" {
			return
		}
		a.fail(a.Sleep(a.ctx, 10*time.Second))
	}
	a.fail(fmt.Errorf("%s did not reach RUNNING", who))
}
func (a *Attempt) PhaseComplete() {
	launch := a.Path("launch")
	b, e := os.ReadFile(filepath.Join(launch, "controller-a.ocid"))
	a.fail(e)
	instance := strings.TrimSpace(string(b))
	if a.waitRunning("controller A", instance); a.err != nil {
		return
	}
	reviewed := filepath.Join(launch, "reviewed-seed-plan.json")
	reviewedArgs := []string{"--reviewed-plan", reviewed, "--reviewed-plan-sha256", a.sha(reviewed)}
	ociArgs := []string{"--oci-config", ociConfig(), "--oci-profile", "DEFAULT"}
	observation, completion := filepath.Join(launch, "seed-observation.json"), filepath.Join(launch, "seed-completion.json")
	if !exists(completion) {
		a.remove(observation)
		a.RunBootstrap(join([]string{"observe-external-seed"}, a.SeedArgs(), []string{"--reservation", filepath.Join(launch, "seed-reservation.json")}, reviewedArgs, []string{"--instance-ocid", instance}, ociArgs, []string{"--out", observation})...)
		a.RunBootstrap(join([]string{"sign-external-seed-completion"}, a.SeedArgs(), []string{"--reservation", filepath.Join(launch, "seed-reservation.json"), "--observation", observation, "--signing-key", a.trust("root_private"), "--ledger-signing-key", a.Path("material", "founder-ledger.key"), "--out", completion})...)
	}
	a.RunBootstrap(join([]string{"publish-external-seed-completion"}, a.SeedArgs(), []string{"--reservation", filepath.Join(launch, "seed-reservation.json"), "--completion", completion}, reviewedArgs, ociArgs)...)
}

// markerObject names a controller slot's accepted-install marker in the head
// bucket.
func (a *Attempt) markerObject(slot string) string {
	key := sha256.Sum256([]byte("GRU\x00controller\x00" + slot))
	return a.Prefix + "/bootstrap/v1/" + a.Deployment + "/" + hex.EncodeToString(key[:]) + "/accepted-install.json"
}
func (a *Attempt) PhaseContinuity() {
	continuity := a.Path("continuity")
	a.mkdir(continuity)
	plan := a.read(a.Plan())
	anchor := a.Path("anchor.signed.json")
	for _, slot := range Slots {
		marker := filepath.Join(continuity, slot+".marker.json")
		name := a.markerObject(slot)
		deadline := a.Now().Add(20 * time.Minute)
		if exists(marker) {
			continue
		}
		// Announce the poll once per slot; the seam is reused for every read.
		cloud := a.cloud("GetObject " + slot + " accepted-install marker (polling)")
		if cloud == nil {
			return
		}
		for !exists(marker) {
			if a.err != nil {
				return
			}
			// A read error is retried like an absent marker until the
			// deadline: the controller may still be publishing it.
			data, found, e := cloud.GetObject(a.ctx, str(a.Config, "namespace"), str(object(plan["foundation_buckets"]), "head"), name)
			if e != nil {
				fmt.Fprintln(a.ErrOut, e)
			}
			if a.ctx.Err() != nil {
				a.fail(a.ctx.Err())
				return
			}
			if e == nil && found && len(data) > 0 {
				a.WriteNew(marker, data)
				break
			}
			if a.Now().After(deadline) {
				a.fail(fmt.Errorf("%s did not publish its accepted-install marker", slot))
				return
			}
			a.fail(a.Sleep(a.ctx, 20*time.Second))
		}
	}
	record := filepath.Join(continuity, "generation")
	generation := 2
	if exists(record) {
		b, e := os.ReadFile(record)
		a.fail(e)
		previous, e := strconv.Atoi(strings.TrimSpace(string(b)))
		a.fail(e)
		generation = previous + 1
	}
	work := filepath.Join(continuity, fmt.Sprintf("g%d", generation))
	a.mkdir(work)
	var proofs []string
	for _, slot := range Slots {
		candidate, proof := filepath.Join(work, slot+".candidate.json"), filepath.Join(work, slot+".signed.json")
		if !exists(proof) {
			a.remove(candidate)
			// An install that adopted material generations is bound to the
			// chain the attempt holds, not to its bootstrap material.
			material, signing := []string{"--material-directory", a.Path("material")}, []string(nil)
			if chain := a.Path("material-generations.json"); exists(chain) {
				material, signing = []string{"--material-generations", chain}, []string{"--material-generations", chain}
			}
			a.RunBootstrap(append(append([]string{"render-founder-continuity", "--marker", filepath.Join(continuity, slot+".marker.json"), "--anchor", anchor}, material...), "--selector-generation", strconv.Itoa(generation), "--out", candidate)...)
			a.RunBootstrap(append([]string{"sign-founder-continuity", "--candidate", candidate, "--marker", filepath.Join(continuity, slot+".marker.json"), "--anchor", anchor, "--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--out", proof, "--valid-for", a.validFor()}, signing...)...)
		}
		proofs = append(proofs, "--proof", proof)
	}
	selection := filepath.Join(work, "selection.signed.json")
	if !exists(selection) {
		candidate := filepath.Join(work, "selection.candidate.json")
		var refs []any
		for _, slot := range Slots {
			refs = append(refs, Object{"slot": slot, "sha256": a.sha(filepath.Join(work, slot+".signed.json"))})
		}
		// The selector signers require FounderSelection's canonical field order.
		a.writeJSON(candidate, typed(a, Object{"schemaVersion": 2, "deploymentId": a.Deployment, "cell": "GRU", "environment": "canary", "generation": generation, "continuities": refs}, &bootstrapstart.FounderSelection{}))
		a.RunBootstrap(join([]string{"sign-founder-selection", "--candidate", candidate, "--identity", a.Path("identity.json"), "--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--out", selection, "--valid-for", a.validFor()}, proofs)...)
	}
	a.RunBootstrap(join([]string{"publish-founder-selection", "--selection", selection, "--identity", a.Path("identity.json"), "--anchor", anchor, "--root-key", a.trust("root_public"), "--oci-config", ociConfig(), "--oci-profile", "DEFAULT"}, proofs)...)
	if a.err == nil {
		a.fail(os.WriteFile(record, []byte(strconv.Itoa(generation)), 0600))
	}
}
func (a *Attempt) PhaseOperator() {
	record, grant := a.Path("controller-material.json"), str(a.Config, "operator_grant")
	key := str(a.Config, "operator_signing_key")
	rendered := "/run/ts-attempt-operator-" + a.Deployment + ".json"
	a.rootMaterial(func(material string) {
		a.sudo(false, "rm", "-f", "--", rendered)
		defer a.cleanup("rm", "-f", "--", rendered)
		a.bootstrapSudo(join([]string{"render-operator-config"}, a.pair(record, "--material-record"), []string{"--material-directory", material}, a.pair(grant, "--operator-grant"), []string{"--operator-signing-key", key, "--operator-signing-key-sha256", a.rootSHA(key), "--out", rendered})...)
		args := []string{"rm", "-f", "--"}
		for _, name := range []string{"operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem", "ca.pem", "ticket.pub", "operator-signing.key", "operator.json"} {
			args = append(args, filepath.Join("/var/lib/terrascale-operator", name))
		}
		a.sudo(false, args...)
		a.bootstrapSudo(join([]string{"install-operator-material"}, a.pair(record, "--material-record"), []string{"--material-directory", material, "--operator-config", rendered, "--operator-config-sha256", a.rootSHA(rendered), "--operator-signing-key", key, "--operator-signing-key-sha256", a.rootSHA(key)})...)
	})
	cli := a.Path("release", OperatorCLI)
	artifacts := rows(a.read(a.Path("release", "qualification.json"))["artifacts"])
	count := 0
	matches := false
	sha := a.sha(cli)
	for _, v := range artifacts {
		row := object(v)
		if row["name"] == OperatorCLI {
			count++
			matches = row["sha256"] == sha
		}
	}
	if count != 1 || !matches {
		a.fail(fmt.Errorf("operator CLI differs from the qualified CI artifact"))
		return
	}
	if a.err == nil {
		a.fail(os.Chmod(cli, 0755))
		fmt.Fprintln(a.Out, "operator CLI for this cell:", cli)
	}
}

var serviceRole = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// PhaseServices adds the configured services ({role, profile, spec}) to the
// running cell through the signed cell spec amendments of any later change:
// the operator CLI plans each, the release leaf signs it under the root's
// cell spec delegation, and the cell applies it. A service already in the
// spec plans nothing, so a rerun changes nothing.
func (a *Attempt) PhaseServices() {
	services := rows(a.Config["services"])
	if len(services) == 0 {
		return
	}
	// A role names files the phase deletes as root.
	for _, v := range services {
		service := object(v)
		if !serviceRole.MatchString(str(service, "role")) || str(service, "profile") == "" {
			a.fail(fmt.Errorf("attempt config services need a valid role and a profile"))
			return
		}
	}
	dir := a.Path("services")
	a.mkdir(dir)
	// Every run issues a fresh delegation, so a resumed attempt never signs
	// with an expired one.
	delegation := filepath.Join(dir, "spec-delegation.signed.json")
	if err := os.Remove(delegation); !errors.Is(err, os.ErrNotExist) {
		a.fail(err)
	}
	issued := a.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	a.release("sign-spec-delegation", "--subject-public-key", a.trust("release_leaf_public"), "--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--deployment-id", a.Deployment, "--cell", "gru", "--environment", "canary", "--issued-at", issued.Format(time.RFC3339), "--expires-at", issued.Add(7*24*time.Hour).Format(time.RFC3339), "--out", delegation)
	cli, config := a.Path("release", OperatorCLI), "/var/lib/terrascale-operator/operator.json"
	for _, v := range services {
		service := object(v)
		role, profile, spec := str(service, "role"), str(service, "profile"), str(service, "spec")
		// Every run plans from the cell's current spec, so a spec another
		// change made stale is never reapplied.
		candidate, signed := filepath.Join(dir, role+".candidate.json"), filepath.Join(dir, role+".signed.json")
		a.sudo(false, "rm", "-f", "--", candidate, signed)
		args := []string{cli, "service", "add", "--config", config, "--role", role, "--profile", profile, "--out", candidate}
		if spec != "" {
			args = append(args, "--spec", spec)
		}
		plan := a.sudo(true, args...)
		if a.err != nil {
			return
		}
		if !exists(candidate) {
			continue
		}
		// The leader's plan names what only a root may sign, such as a
		// role's Vault secrets; the attempt holds the root key.
		var planned struct {
			RootRequired []string `json:"root_required"`
		}
		if a.fail(json.Unmarshal([]byte(plan), &planned)); a.err != nil {
			return
		}
		if len(planned.RootRequired) != 0 {
			a.release("sign-spec", "--candidate", candidate, "--root", "--root-key", a.trust("root_public"), "--signing-key", a.trust("root_private"), "--out", signed)
		} else {
			a.release("sign-spec", "--candidate", candidate, "--delegation", delegation, "--root-key", a.trust("root_public"), "--signing-key", a.trust("release_leaf_private"), "--out", signed)
		}
		a.sudo(false, cli, "service", "apply", "--config", config, "--file", signed)
	}
}

// PhaseMembers launches the plan's database hosts. They enroll with the
// controllers themselves through host-setup.
func (a *Attempt) PhaseMembers() {
	launch := a.Path("launch")
	a.mkdir(launch)
	a.bindSeed()
	for _, v := range rows(a.read(a.Plan())["hosts"]) {
		slot := str(object(v), "slot")
		if !strings.HasPrefix(slot, "member-") {
			continue
		}
		name, e := naming.RegionCell("GRU").MemberSlot(slot)
		a.fail(e)
		if a.err != nil {
			return
		}
		ocid, launchInput := filepath.Join(launch, name+".ocid"), filepath.Join(launch, name+"-launch.json")
		var id string
		if exists(ocid) {
			b, e := os.ReadFile(ocid)
			a.fail(e)
			id = strings.TrimSpace(string(b))
			fmt.Fprintln(a.Out, name, "already launched:", id)
		} else if id = a.adoptMember(name, launchInput, ocid); a.err != nil {
			return
		} else if id != "" {
			fmt.Fprintln(a.Out, name, "was launched before its OCID was recorded:", id)
		} else {
			// An earlier input may be the record of a launch OCI has not listed
			// yet, which adoption needs: replace it only once a new input is
			// admitted and about to be launched.
			inventory, admission := a.FreshAdmission("launch/" + name)
			next := filepath.Join(launch, name+"-launch.next.json")
			a.remove(next)
			a.preview("member-launch", "--plan", a.Plan(), "--inventory", inventory, "--admission", admission, "--slot", slot, "--image-ocid", a.ImageID(), "--host-enrollment", a.Path("host-enrollment-public.json"), "--owner-ssh-public-key", str(a.Config, "owner_ssh_public_key"), "--out", next)
			if a.err != nil {
				return
			}
			wire, e := os.ReadFile(next)
			a.fail(e)
			if a.err != nil {
				return
			}
			details, e := LaunchDetails(wire)
			a.fail(e)
			if a.requireAdmission(admission); a.err != nil {
				return
			}
			a.fail(os.Rename(next, launchInput))
			if a.err != nil {
				return
			}
			id = a.launchInstance(name, details, wire, filepath.Join(launch, name+"-launch-submit.json"), ocid)
		}
		// A resumed host may still be booting: wait for it either way.
		if a.waitRunning(name, id); a.err != nil {
			return
		}
	}
}

// adoptMember records the instance an interrupted members run launched
// before it wrote the OCID. It adopts the one live workload instance with
// the host's static name only when it is exactly the launch of this
// attempt's retained input, whose metadata carries this attempt's
// enrollment bundle; any other instance of the name needs reconciliation.
// member-launch refuses a name the inventory already holds.
func (a *Attempt) adoptMember(name, launchInput, ocid string) string {
	cloud := a.cloud("ListInstances workload_compartment")
	if cloud == nil {
		return ""
	}
	listed, e := cloud.ListInstances(a.ctx, str(object(a.read(a.Plan())["resource_ids"]), "workload_compartment"))
	a.fail(e)
	var ids []string
	for _, instance := range listed {
		if instance.DisplayName == name && instance.LifecycleState != "TERMINATED" && instance.LifecycleState != "TERMINATING" {
			ids = append(ids, instance.ID)
		}
	}
	if a.err != nil || len(ids) == 0 {
		return ""
	}
	wire, e := os.ReadFile(launchInput)
	if e != nil || len(ids) != 1 {
		a.fail(fmt.Errorf("%d live instances are named %s and this attempt has no single launch input for them; reconcile before retrying", len(ids), name))
		return ""
	}
	details, e := LaunchDetails(wire)
	a.fail(e)
	var launched Instance
	if a.err == nil {
		launched, e = cloud.GetInstance(a.ctx, ids[0])
		a.fail(e)
	}
	if a.err == nil && !launchedFrom(launched, details) {
		a.fail(fmt.Errorf("%s (%s) is not the launch of this attempt's %s; reconcile before retrying", name, ids[0], filepath.Base(launchInput)))
	}
	if a.err != nil {
		return ""
	}
	a.fail(a.WriteNew(ocid, []byte(ids[0]+"\n")))
	return ids[0]
}

// PhasePlan prints the phase-2 cell plan and its cost estimate against a
// fresh inventory. It changes nothing. Before material writes the attempt
// plan, it reads the reviewed base plan.
func (a *Attempt) PhasePlan() {
	plan := a.Plan()
	if !exists(plan) {
		plan = str(a.Config, "base_plan")
	}
	inventory := a.Path("plan-inventory.json")
	a.captureInventory(plan, inventory)
	args := []string{"cell-plan", "--plan", plan, "--inventory", inventory}
	if profile := str(a.Config, "terrabase_profile"); profile != "" {
		args = append(args, "--profile", profile)
	}
	a.preview(args...)
}

// PhaseTerraBase fetches and verifies the C# TerraBase arm64 release, then
// rolls it out with the qualified operator CLI of this attempt.
func (a *Attempt) PhaseTerraBase() {
	release := object(a.Config["terrabase"])
	tag, commit, environment, profile := str(release, "tag"), str(release, "commit"), str(release, "environment"), str(a.Config, "terrabase_profile")
	if tag == "" || filepath.Base(tag) != tag || strings.HasPrefix(tag, ".") || len(commit) != 40 ||
		strings.Trim(commit, "0123456789abcdef") != "" || environment == "" || profile == "" {
		a.fail(fmt.Errorf("attempt config needs terrabase tag, a 40-hex commit and environment, and terrabase_profile"))
		return
	}
	// The rollout records commit as the binary's source, so it must be the
	// commit the release tag names: a CI prerelease tag carries it, and a
	// version tag is resolved in the clone below.
	tagged, ciTag := ciReleaseCommit(tag)
	if ciTag && tagged != commit {
		a.fail(fmt.Errorf("terrabase release %s is commit %s, not the configured %s", tag, tagged, commit))
		return
	}
	// Assets are kept per tag: a new release never reuses the previous
	// release's downloads under its own commit.
	dir := a.Path("terrabase", tag)
	a.mkdir(dir)
	binary := filepath.Join(dir, "terrabase-linux-arm64")
	checksum := binary + ".sha256"
	for _, asset := range []string{binary, checksum} {
		if !exists(asset) {
			a.run("fj", "release", "asset", "download", "-r", "TerraScale/terrabase", tag, filepath.Base(asset), "-o", asset)
		}
	}
	if a.err != nil {
		return
	}
	_, e := terrabase.VerifyRelease(binary, checksum)
	a.fail(e)
	source := a.Path("terrabase", "source")
	if !exists(source) {
		a.run("git", "clone", "--quiet", terrabase.Repository, source)
	} else {
		a.run("git", "-C", source, "fetch", "--quiet", "--tags", "origin")
	}
	a.run("git", "-C", source, "cat-file", "-e", commit+"^{commit}")
	if !ciTag {
		if resolved := strings.TrimSpace(a.capture("git", "-C", source, "rev-parse", "--verify", "--end-of-options", tag+"^{commit}")); a.err == nil && resolved != commit {
			a.fail(fmt.Errorf("terrabase release %s is commit %s, not the configured %s", tag, resolved, commit))
			return
		}
	}
	a.sudo(false, a.Path("release", OperatorCLI), "operator", "terrabase-release", "--config", "/var/lib/terrascale-operator/operator.json", "--binary", binary, "--sha256", checksum, "--source-checkout", source, "--commit", commit, "--environment", environment, "--profile", profile, "--wait", "10m")
}

// ciReleaseCommit returns the commit of a TerraBase CI prerelease tag,
// ci-<commit>-run-<run id>.
func ciReleaseCommit(tag string) (string, bool) {
	rest, ok := strings.CutPrefix(tag, "ci-")
	commit, run, found := strings.Cut(rest, "-run-")
	if !ok || !found || len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" ||
		run == "" || strings.Trim(run, "0123456789") != "" {
		return "", false
	}
	return commit, true
}
func (a *Attempt) PhaseStatus() {
	plan := a.read(a.Plan())
	for _, bucket := range []string{"head", "ledger"} {
		for _, prefix := range slotRecordPrefixes(a.Prefix, a.Deployment) {
			for _, name := range a.listObjects(str(object(plan["foundation_buckets"]), bucket), prefix) {
				fmt.Fprintf(a.Out, "%s: %s\n", bucket, strings.TrimPrefix(name, a.Prefix+"/bootstrap/"))
			}
		}
	}
	var instances []Instance
	for _, compartment := range []string{"control_compartment", "workload_compartment"} {
		cloud := a.cloud("ListInstances " + compartment)
		if cloud == nil {
			return
		}
		listed, e := cloud.ListInstances(a.ctx, str(object(plan["resource_ids"]), compartment))
		a.fail(e)
		instances = append(instances, listed...)
	}
	// Cell server names are static (internal/naming), so this lists every
	// server of the GRU cell, not only this deployment's.
	cell, _ := naming.RegionCell("GRU").Name()
	for _, instance := range instances {
		if instance.LifecycleState != "TERMINATED" && strings.HasPrefix(instance.DisplayName, cell+"-") {
			fmt.Fprintf(a.Out, "instance %v %v %v\n", instance.DisplayName, instance.LifecycleState, instance.ID)
		}
	}
}
func (a *Attempt) Phase(phase string) error {
	if a.err != nil {
		return a.err
	}
	switch phase {
	case "material":
		a.PhaseMaterial()
	case "release":
		a.PhaseRelease()
	case "image":
		a.PhaseImage()
	case "sign":
		a.PhaseSign()
	case "launch":
		a.PhaseLaunch()
	case "complete":
		a.PhaseComplete()
	case "continuity":
		a.PhaseContinuity()
	case "operator":
		a.PhaseOperator()
	case "services":
		a.PhaseServices()
	case "members":
		a.PhaseMembers()
	case "plan":
		a.PhasePlan()
	case "terrabase":
		a.PhaseTerraBase()
	case "status":
		a.PhaseStatus()
	case "up":
		for _, p := range Phases {
			fmt.Fprintln(a.Out, "==", p)
			if e := a.Phase(p); e != nil {
				return e
			}
		}
	default:
		a.fail(fmt.Errorf("unknown attempt phase %q", phase))
	}
	return a.err
}
func Run(ctx context.Context, args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("oci-region attempt", flag.ContinueOnError)
	fs.SetOutput(errOut)
	config := fs.String("config", "", "attempt configuration")
	if e := fs.Parse(args); e != nil {
		return 2
	}
	if *config == "" || fs.NArg() != 1 {
		fmt.Fprintln(errOut, "usage: oci-region attempt --config attempt.json PHASE")
		return 2
	}
	a, e := New(ctx, *config, out, errOut)
	if e == nil {
		e = a.Phase(fs.Arg(0))
	}
	if e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	return 0
}

// MarshalIndented is provided for retained JSON artifacts, whose hashes are
// always taken from the actual on-disk bytes.
func MarshalIndented(v any) ([]byte, error) {
	return json.Marshal(v, json.Deterministic(true), jsontext.Multiline(true), jsontext.WithIndent("  "))
}
