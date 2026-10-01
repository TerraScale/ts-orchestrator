package memberstatus

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func (q *Qualification) CollectGuestLogs() {
	if !lexists(q.Image) {
		return
	}
	q.Mount(true)
	if q.err != nil {
		return
	}
	defer func() {
		if e := q.Unmount(); e != nil {
			q.CleanupErrors = append(q.CleanupErrors, e.Error())
			q.fail(e)
		}
	}()
	directory := "/var/log/ts-member-status-qualification"
	logs := [][2]string{{"go-host-test.log", "guest-go-host-test.log"}, {"rust-test.log", "guest-rust-test.log"}}
	if q.Managed {
		directory = "/var/log/ts-managed-volume-qualification"
		logs = [][2]string{{"go-host-test.log", "guest-managed-volume-test.log"}}
	}
	for _, l := range logs {
		guest := directory + "/" + l[0]
		s, oversized, e := ReadGuestRegularFile(q.MountPath, guest, MaxGuestLogBytes)
		if os.IsNotExist(e) {
			q.note("guest_log_missing", Object{"path": guest})
			continue
		}
		q.fail(e)
		if q.err != nil {
			return
		}
		target := filepath.Join(q.Logs, l[1])
		q.fail(os.WriteFile(target, []byte(s), 0600))
		q.note("guest_log_collected", Object{"source": guest, "target": target, "oversized": oversized})
		if oversized {
			q.fail(fmt.Errorf("guest test log exceeded %d bytes", MaxGuestLogBytes))
			return
		}
	}
}
func (q *Qualification) CheckResults() {
	serial, oversized, e := ReadTextBounded(filepath.Join(q.Logs, "guest-serial.log"), MaxSerialLogBytes)
	q.fail(e)
	if oversized {
		q.fail(fmt.Errorf("guest serial log exceeded its collection bound"))
	}
	if q.err != nil {
		return
	}
	runner, e := ParseRunnerResult(serial, q.Managed)
	q.fail(e)
	if q.err != nil {
		return
	}
	if runner["status"] == "FAILED" {
		q.TestResults = Object{"runner": runner}
		q.fail(fmt.Errorf("guest test command failed stage=%v status=%v", runner["stage"], runner["exit_status"]))
		return
	}
	goPath := filepath.Join(q.Logs, "guest-go-host-test.log")
	if q.Managed {
		goPath = filepath.Join(q.Logs, "guest-managed-volume-test.log")
	}
	goOutput, oversized, e := ReadTextBounded(goPath, MaxGuestLogBytes)
	q.fail(e)
	if oversized {
		q.fail(fmt.Errorf("Go test evidence log exceeded its collection bound"))
	}
	if q.err != nil {
		return
	}
	if q.Managed {
		q.TestResults, e = ParseManagedVolumeResult(goOutput, 0, serial)
	} else {
		rustOutput, oversized, re := ReadTextBounded(filepath.Join(q.Logs, "guest-rust-test.log"), MaxGuestLogBytes)
		q.fail(re)
		if oversized {
			q.fail(fmt.Errorf("Rust evidence log exceeded its collection bound"))
		}
		if q.err != nil {
			return
		}
		q.TestResults, e = ParseQualificationResult(goOutput, 0, rustOutput, 0, serial, str(q.Manifest, "rust_test_name"))
	}
	q.fail(e)
	q.note("test_results", Object{"results": q.TestResults})
}
func (q *Qualification) CleanupSocketDirectory() {
	if q.SocketDir == "" {
		return
	}
	if q.VM != nil && q.VM.Process != nil && (!q.VM.Process.Reaped || !q.VM.ProcessGroupStopped) {
		q.CleanupErrors = append(q.CleanupErrors, "API socket directory retained while Firecracker is live: "+q.SocketDir)
		return
	}
	if q.VM != nil {
		socket := q.VM.SocketPath()
		info, e := os.Lstat(socket)
		if e == nil {
			if info.Mode()&os.ModeSocket == 0 {
				q.CleanupErrors = append(q.CleanupErrors, "unexpected non-socket at owned API path: "+socket)
				return
			}
			if e = os.Remove(socket); e != nil {
				q.CleanupErrors = append(q.CleanupErrors, e.Error())
				return
			}
		} else if !os.IsNotExist(e) {
			q.CleanupErrors = append(q.CleanupErrors, e.Error())
			return
		}
	}
	if e := os.Remove(q.SocketDir); e != nil && !os.IsNotExist(e) {
		q.CleanupErrors = append(q.CleanupErrors, "remove owned API socket directory: "+e.Error())
		return
	}
	q.note("api_socket_dir_removed", Object{"path": q.SocketDir})
}
func (q *Qualification) CleanupImage() {
	stopped := q.VM == nil || q.VM.Process == nil || (q.VM.Process.Reaped && q.VM.ProcessGroupStopped)
	commandsStopped := !q.CommandRunner.Pending()
	mounted := q.IsMounted(q.MountPath)
	safe := stopped && commandsStopped && !mounted && !q.MountOwned
	images := []string{q.Image}
	if q.Managed {
		images = append(images, q.ManagedVolumeImage)
	}
	for _, image := range images {
		if !lexists(image) {
			continue
		}
		if !safe || q.Failure != "" || len(q.CleanupErrors) > 0 || q.Events.Err != nil {
			q.note("private_image_retained", Object{"image": image, "stopped": stopped, "commands_stopped": commandsStopped, "mounted": mounted, "tracked_mount": q.MountOwned, "reason": "qualification or cleanup failed; preserve guest-side evidence"})
			continue
		}
		if e := os.Remove(image); e != nil {
			q.CleanupErrors = append(q.CleanupErrors, "remove stopped and unmounted private image: "+e.Error())
		} else {
			q.note("private_image_removed", Object{"image": image})
		}
	}
}
func (q *Qualification) Summary() Object {
	outcome := "PASS"
	if len(q.CleanupErrors) > 0 {
		outcome = "CLEANUP_FAILED"
	} else if q.Failure != "" {
		outcome = "FAILED"
	}
	hashes, paths := Object{}, Object{}
	for _, name := range q.names() {
		hashes[name] = q.expected(name)
		paths[name] = q.Inputs[name]
	}
	logs := Object{"events": q.Events.Path, "serial": filepath.Join(q.Logs, "guest-serial.log"), "vmm": filepath.Join(q.Logs, "firecracker-vmm.log")}
	if q.Managed {
		logs["managed_volume_test"] = filepath.Join(q.Logs, "guest-managed-volume-test.log")
	} else {
		logs["go_host_test"] = filepath.Join(q.Logs, "guest-go-host-test.log")
		logs["rust_test"] = filepath.Join(q.Logs, "guest-rust-test.log")
	}
	var socket any
	if q.SocketDir != "" {
		socket = q.SocketDir
	}
	summary := Object{"schema_version": 1, "outcome": outcome, "failure": q.Failure, "cleanup_errors": q.CleanupErrors, "cleanup_clean": len(q.CleanupErrors) == 0, "started_at": q.StartedAt, "finished_at": time.Now().UTC().Format(time.RFC3339Nano), "run_dir": q.Root, "source_commits": q.Manifest["source_commits"], "manifest_sha256": shaBytes(q.RawManifest), "local_source_hashes": q.SourceHashes, "local_source_hashes_after": q.SourceHashesAfter, "local_source_stable": q.SourceStable, "input_hashes": hashes, "input_paths": paths, "resources": Object{"guest_ram_mib": GuestRAMMiB, "guest_vcpus": GuestVCPUs, "guest_network_interfaces": []any{}, "service_name": ServiceName, "service_memory_max": "5G", "service_delegate": true, "service_delegate_subgroup": "supervisor", "private_image": q.Image, "private_image_removed": !lexists(q.Image), "private_image_retained": lexists(q.Image), "api_socket_dir": socket, "api_socket_dir_removed": q.SocketDir == "" || !lexists(q.SocketDir)}, "tests": q.TestResults, "logs": logs, "events": q.Events.Entries}
	if q.Managed {
		summary["profile"] = ManagedVolumeProfile
		summary["go_test_name"] = q.Manifest["go_test_name"]
		summary["managed_volume"] = Object{"filesystem_uuid": ManagedVolumeUUID, "private_image": q.ManagedVolumeImage, "private_image_removed": !lexists(q.ManagedVolumeImage), "private_image_retained": lexists(q.ManagedVolumeImage), "device": "/dev/oracleoci/oraclevdb", "mount_path": MountPath}
	} else {
		summary["rust_test_name"] = q.Manifest["rust_test_name"]
	}
	return summary
}
func (q *Qualification) Run() (Object, error) {
	if e := q.PrepareDirs(); e != nil {
		return nil, e
	}
	q.CreatePrivateImage()
	q.StageGuest()
	q.recheckInputs()
	if q.err == nil {
		if e := syscall.Access("/dev/kvm", 6); e != nil {
			q.fail(fmt.Errorf("Firecracker requires readable and writable /dev/kvm: %w", e))
		}
	}
	if q.err == nil {
		var err error
		q.SocketDir, err = privateSocketDirectory()
		q.fail(err)
	}
	if q.err == nil {
		q.VM = &VM{Firecracker: q.Inputs["firecracker"], Kernel: q.Inputs["kernel"], Image: q.Image, SocketDir: q.SocketDir, Logs: q.Logs, Events: q.Events}
		if q.Managed {
			q.VM.ManagedVolume = q.ManagedVolumeImage
		}
		q.fail(q.VM.Start(q.ctx))
		if q.err == nil {
			q.fail(q.VM.WaitForShutdown(q.ctx))
		}
	}
	if q.err == nil {
		q.CollectGuestLogs()
		q.CheckResults()
	}
	if q.err != nil {
		q.Failure = q.err.Error()
		q.note("qualification_failure", Object{"failure": q.Failure})
	}
	q.checkSourceStability()
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(q.ctx), 90*time.Second)
	defer cancel()
	if q.VM != nil {
		q.CleanupErrors = append(q.CleanupErrors, q.VM.Stop(cleanupCtx)...)
	}
	q.CleanupErrors = append(q.CleanupErrors, q.CommandRunner.StopPending()...)
	if q.IsMounted(q.MountPath) {
		if e := q.Unmount(); e != nil {
			q.CleanupErrors = append(q.CleanupErrors, "unmount owned guest image: "+e.Error())
		}
	}
	q.CleanupSocketDirectory()
	q.CleanupImage()
	if q.Events.Err != nil {
		q.CleanupErrors = append(q.CleanupErrors, "persist qualification events: "+q.Events.Err.Error())
	}
	summary := q.Summary()
	if e := AtomicReplace(filepath.Join(q.Root, "summary.json"), summary); e != nil {
		return summary, e
	}
	return summary, nil
}
func privateSocketDirectory() (string, error) {
	dir, e := os.MkdirTemp("/tmp", "tsms-")
	if e != nil {
		return "", e
	}
	if e = os.Chmod(dir, 0700); e != nil {
		os.Remove(dir)
		return "", e
	}
	if len([]byte(filepath.Join(dir, "api.sock"))) >= 100 {
		os.Remove(dir)
		return "", fmt.Errorf("Unix socket path too long")
	}
	return dir, nil
}
func ValidateHostPrerequisites(inputs map[string]string, runDir string) error {
	if lexists(runDir) {
		return fmt.Errorf("--run-dir must be a new path")
	}
	parent, e := os.Stat(filepath.Dir(runDir))
	if e != nil || !parent.IsDir() {
		return fmt.Errorf("--run-dir parent must already exist")
	}
	required := []string{"cp", "e2fsck", "resize2fs", "mount", "umount", "install", "ln"}
	if inputs["volume_ext4"] != "" {
		required = append(required, "blkid", "sha256sum", "stat")
	}
	for _, name := range required {
		if _, e = exec.LookPath(name); e != nil {
			return fmt.Errorf("host prerequisite is missing: %s", name)
		}
	}
	if _, e = Sudo(); e != nil {
		return e
	}
	if e = syscall.Access(inputs["firecracker"], 1); e != nil {
		return fmt.Errorf("Firecracker input must be an executable file")
	}
	if _, e = os.Stat("/dev/kvm"); e != nil {
		return fmt.Errorf("Firecracker requires /dev/kvm")
	}
	return nil
}
func repositoryRoot(start string) (string, error) {
	path, e := filepath.Abs(start)
	if e != nil {
		return "", e
	}
	for {
		if _, e = os.Stat(filepath.Join(path, "go.mod")); e == nil {
			return path, nil
		}
		parent := filepath.Dir(path)
		if path == parent {
			return "", fmt.Errorf("qualification requires --repo-root or a repository working directory")
		}
		path = parent
	}
}
func Run(ctx context.Context, args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("qualification memberstatus", flag.ContinueOnError)
	fs.SetOutput(errOut)
	manifest := fs.String("manifest", "", "immutable qualification manifest")
	runDir := fs.String("run-dir", "", "new durable evidence directory")
	repo := fs.String("repo-root", ".", "repository source inventory root")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 || *manifest == "" || *runDir == "" {
		return fmt.Errorf("--manifest and --run-dir are required")
	}
	m, raw, inputs, e := LoadManifest(*manifest)
	if e != nil {
		return fmt.Errorf("member-status qualification preflight failed: %w", e)
	}
	dir := *runDir
	if strings.HasPrefix(dir, "~/") {
		home, e := os.UserHomeDir()
		if e != nil {
			return e
		}
		dir = filepath.Join(home, strings.TrimPrefix(dir, "~/"))
	}
	dir, e = filepath.Abs(dir)
	if e != nil {
		return e
	}
	if e = ValidateHostPrerequisites(inputs, dir); e != nil {
		return e
	}
	root, e := repositoryRoot(*repo)
	if e != nil {
		return e
	}
	q, e := New(ctx, m, raw, inputs, dir, root)
	if e != nil {
		return e
	}
	summary, e := q.Run()
	if e != nil {
		return e
	}
	record := Object{"outcome": summary["outcome"], "summary": filepath.Join(q.Root, "summary.json"), "failure": q.Failure}
	wire, e := canonical(record)
	if e != nil {
		return e
	}
	_, e = fmt.Fprintln(out, string(wire))
	if e != nil {
		return e
	}
	if summary["outcome"] != "PASS" {
		return errors.New("member-status qualification failed; see retained summary")
	}
	return nil
}
