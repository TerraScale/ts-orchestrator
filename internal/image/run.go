package image

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/commandio"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return fmt.Sprint([]string(*s)) }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

// Services are the cloud seams of the image tooling. The zero value uses the
// production OCI SDK clients; tests substitute a local OCI stand-in.
type Services struct {
	// ImageImporter builds the OCI image importer for one region. Nil uses
	// the operator's ~/.oci/config through the in-binary SDK.
	ImageImporter imageimport.ImporterFactory
}

func (s Services) importer() imageimport.ImporterFactory {
	if s.ImageImporter != nil {
		return s.ImageImporter
	}
	return func(region string) (imageimport.Importer, error) {
		client, err := imageimport.NewSDKClient(region)
		if err != nil {
			return imageimport.Importer{}, err
		}
		return imageimport.Importer{Client: client}, nil
	}
}

// Run runs the image tooling within the unified executable.
func Run(ctx context.Context, root string, args []string, stdout, stderr io.Writer) int {
	return RunWith(ctx, root, args, stdout, stderr, Services{})
}

// RunWith runs the image tooling with explicit cloud services.
func RunWith(ctx context.Context, root string, args []string, stdout, stderr io.Writer, services Services) int {
	if err := ctx.Err(); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	output := commandio.NewWriter(stdout)
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: ts-orch image inputs|build-offline|guestfs|promote")
		return 2
	}
	var e error
	var code int
	switch args[0] {
	case "inputs":
		e, code = runInputs(root, args[1:], output, stderr)
	case "guestfs":
		e, code = runGuestfs(ctx, root, args[1:], output, stderr)
	case "build-offline":
		e, code = runOffline(ctx, root, args[1:], output, stderr)
	case "promote":
		e, code = runPromotion(ctx, root, args[1:], output, stderr, services)
	case "help", "--help", "-h":
		fmt.Fprintln(output, "usage: ts-orch image inputs|build-offline|guestfs|promote")
	default:
		fmt.Fprintln(stderr, "unknown image command:", args[0])
		return 2
	}
	e = errors.Join(e, ctx.Err(), output.Err())
	if e != nil {
		fmt.Fprintf(stderr, "image-%s: %v\n", args[0], e)
		if code == 0 {
			code = 1
		}
	}
	return code
}
func runInputs(root string, args []string, out, stderr io.Writer) (error, int) {
	fs := flag.NewFlagSet("image-inputs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", filepath.Join(root, "deploy/image/image-inputs.json"), "image input manifest")
	qualification := fs.String("qualification", "", "TerraBase or archived image qualification")
	binary := fs.String("binary", "", "archived native verifier binary")
	detail := fs.String("run-detail", "", "Fast run detail")
	command := ""
	for i, a := range args {
		if a == "check" || a == "pin-terrabase" || a == "verify-terrabase-archive" {
			command = a
			args = append(append([]string{}, args[:i]...), args[i+1:]...)
			break
		}
	}
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil, 0
		}
		return e, 2
	}
	if fs.NArg() != 0 || command == "" {
		return errors.New("usage: ts-orch image inputs [--file MANIFEST] check|pin-terrabase|verify-terrabase-archive"), 2
	}
	manifest, e := LoadInputs(root, *file)
	if e != nil {
		return e, 1
	}
	if command == "check" {
		digest, e := fileHash(*file)
		if e != nil {
			return e, 1
		}
		_, e = fmt.Fprintf(out, "image inputs valid sha256=%s\n", digest)
		return e, 0
	}
	if command == "verify-terrabase-archive" {
		if e := VerifyTerraBaseArchive(manifest.TerraBase, *qualification, *binary); e != nil {
			return e, 1
		}
		_, e := fmt.Fprintln(out, "archived native verifier valid")
		return e, 0
	}
	if *qualification == "" || *detail == "" {
		return errors.New("pin-terrabase requires --qualification and --run-detail"), 2
	}
	pin, e := TerraBaseQualification(*qualification, *detail)
	if e != nil {
		return e, 1
	}
	previous := manifest.TerraBase
	manifest.TerraBase = pin
	b, e := pinManifest(manifest.raw, pin)
	if e != nil {
		return e, 1
	}
	if e = os.WriteFile(*file, b, 0644); e != nil {
		return e, 1
	}
	record, e := canonical(map[string]any{"previous": previous, "pinned": pin})
	if e == nil {
		_, e = out.Write(record)
	}
	return e, 0
}
func runGuestfs(ctx context.Context, root string, args []string, out, stderr io.Writer) (error, int) {
	if len(args) == 0 {
		return errors.New("guestfs requires build or verify"), 2
	}
	command := args[0]
	fs := flag.NewFlagSet("guestfs-"+command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	o := GuestBuildOptions{}
	fs.StringVar(&o.Image, "image", "", "QCOW2")
	var expectations stringsFlag
	switch command {
	case "build":
		fs.StringVar(&o.KernelRelease, "kernel-release", "", "kernel release")
		fs.StringVar(&o.KernelOut, "kernel-out", "", "kernel output")
		fs.StringVar(&o.Work, "work", "", "work root")
		fs.StringVar(&o.Sysusers, "sysusers", "", "sysusers input")
		fs.StringVar(&o.Profile, "profile", "", "priority profile")
		fs.StringVar(&o.PriorityRoot, "priority-root", "", "priority drop-in root")
		fs.StringVar(&o.Binary, "binary", "", "orchestrator binary")
		fs.StringVar(&o.NativeVerifier, "native-verifier", "", "TerraBase verifier")
		fs.StringVar(&o.Timesyncd, "timesyncd-config", "", "timesyncd input")
		fs.StringVar(&o.NetBirdBinary, "netbird-binary", "", "NetBird executable")
		fs.StringVar(&o.NetBirdConfig, "netbird-config", "", "NetBird config")
		fs.Func("bootstrap-root", "root PEM", func(v string) error { o.BootstrapRoots = append(o.BootstrapRoots, v); return nil })
	case "verify":
		fs.Var(&expectations, "expect", "GUEST_PATH=SHA256")
	default:
		return errors.New("unknown guestfs command"), 2
	}
	if e := fs.Parse(args[1:]); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil, 0
		}
		return e, 2
	}
	if fs.NArg() != 0 || o.Image == "" {
		return errors.New("missing guestfs --image"), 2
	}
	if command == "verify" {
		if len(expectations) == 0 {
			return errors.New("verify requires --expect"), 2
		}
		return GuestVerify(ctx, o.Image, expectations, out), 0
	}
	for _, v := range []string{o.KernelRelease, o.KernelOut, o.Work, o.Sysusers, o.Profile, o.PriorityRoot, o.Binary, o.NativeVerifier, o.Timesyncd, o.NetBirdBinary, o.NetBirdConfig} {
		if v == "" {
			return errors.New("missing guestfs build input"), 2
		}
	}
	if len(o.BootstrapRoots) == 0 {
		return errors.New("missing --bootstrap-root"), 2
	}
	return GuestBuild(ctx, root, o, out), 0
}
func runOffline(ctx context.Context, root string, args []string, out, stderr io.Writer) (error, int) {
	fs := flag.NewFlagSet("build-offline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: build-offline.sh --base QCOW2 --kernel-release RELEASE --binary FILE --qualification FILE --source-revision SHA --native-verifier-binary FILE --native-verifier-sha256 SHA256 --release-tool FILE --bootstrap-root PEM --timesyncd-config FILE --runtime-priority-profile-id TOKEN --runtime-priority-system-reserve-bytes BYTES --host-memory-min-bytes BYTES --host-memory-low-bytes BYTES --controller-memory-min-bytes BYTES --controller-memory-low-bytes BYTES --system-slice-memory-min-bytes BYTES --system-slice-memory-low-bytes BYTES --out QCOW2 --kernel-out FILE")
	}
	o := OfflineOptions{}
	for _, f := range []struct {
		p    *string
		name string
	}{{&o.Base, "base"}, {&o.KernelRelease, "kernel-release"}, {&o.Binary, "binary"}, {&o.Qualification, "qualification"}, {&o.SourceRevision, "source-revision"}, {&o.NativeVerifier, "native-verifier-binary"}, {&o.NativeSHA256, "native-verifier-sha256"}, {&o.NetBirdBinary, "netbird-binary"}, {&o.NetBirdSHA256, "netbird-sha256"}, {&o.NetBirdConfig, "netbird-config"}, {&o.ReleaseTool, "release-tool"}, {&o.Timesyncd, "timesyncd-config"}, {&o.Out, "out"}, {&o.KernelOut, "kernel-out"}, {&o.Priority.ProfileID, "runtime-priority-profile-id"}} {
		fs.StringVar(f.p, f.name, "", f.name)
	}
	for _, f := range []struct {
		p    *int64
		name string
	}{{&o.Priority.SystemReserve, "runtime-priority-system-reserve-bytes"}, {&o.Priority.HostMin, "host-memory-min-bytes"}, {&o.Priority.HostLow, "host-memory-low-bytes"}, {&o.Priority.ControllerMin, "controller-memory-min-bytes"}, {&o.Priority.ControllerLow, "controller-memory-low-bytes"}, {&o.Priority.SystemMin, "system-slice-memory-min-bytes"}, {&o.Priority.SystemLow, "system-slice-memory-low-bytes"}} {
		fs.Func(f.name, f.name, func(raw string) error {
			if f.name == "runtime-priority-system-reserve-bytes" && !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(raw) {
				return errors.New("runtime-priority system reserve must be a positive canonical byte count")
			}
			value, err := strconv.ParseInt(raw, 10, 64)
			if err == nil {
				*f.p = value
			}
			return err
		})
	}
	fs.Func("bootstrap-root", "public root PEM", func(v string) error { o.BootstrapRoots = append(o.BootstrapRoots, v); return nil })
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil, 0
		}
		fs.Usage()
		return e, 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errors.New("unexpected argument"), 2
	}
	if !gitSHA.MatchString(o.SourceRevision) || !kernelRelease.MatchString(o.KernelRelease) {
		return errors.New("invalid source revision or kernel release"), 2
	}
	return OfflineBuild(ctx, root, o, out), 0
}
