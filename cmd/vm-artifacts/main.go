// Command vm-artifacts builds and signs the real binaries used by the
// Firecracker qualification gates. Its signing key is deliberately ephemeral
// and qualification-only; production release keys never enter this command.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	artifactLimit       = int64(16 << 20)
	artifactPrefix      = ".qualification-artifacts-"
	childShutdownWindow = 30 * time.Second
)

var artifactEnvironment = []string{
	"TS_VM_RELEASE_PUBLIC_KEY",
	"TS_VM_TS_NODE", "TS_VM_TS_NODE_SIGNATURE", "TS_VM_TS_NODE_VERSION",
	"TS_VM_ORCHESTRATOR", "TS_VM_ORCHESTRATOR_SIGNATURE", "TS_VM_ORCHESTRATOR_VERSION",
	"TS_VM_TERRABASE", "TS_VM_TERRABASE_SIGNATURE", "TS_VM_TERRABASE_VERSION",
}

type options struct {
	root            string
	repo            string
	terraBaseRepo   string
	terraBaseBinary string
	command         []string
}

type artifact struct {
	component     string
	environment   string
	path          string
	signaturePath string
	version       string
	digest        [sha256.Size]byte
	data          []byte
	info          os.FileInfo
}

type bundle struct {
	directory     string
	directoryInfo os.FileInfo
	publicKey     string
	artifacts     []artifact
}

func main() {
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(signalContext, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "vm-artifacts:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) (result error) {
	config, err := parseOptions(args)
	if err != nil {
		return err
	}
	prepared, err := prepare(ctx, config, errOut)
	if err != nil {
		return err
	}
	defer func() {
		for index := range prepared.artifacts {
			zero(prepared.artifacts[index].data)
		}
		if cleanupErr := cleanupOwnedDirectory(config.root, prepared.directory, prepared.directoryInfo); cleanupErr != nil {
			result = errors.Join(result, fmt.Errorf("clean qualification artifacts: %w", cleanupErr))
		}
	}()

	environment := bundleEnvironment(os.Environ(), prepared)
	return runChild(ctx, config.command, environment, out, errOut)
}

func parseOptions(args []string) (options, error) {
	set := flag.NewFlagSet("vm-artifacts", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var config options
	set.StringVar(&config.root, "root", "", "absolute vm qualification root")
	set.StringVar(&config.repo, "repo", "", "absolute orchestrator repository root")
	set.StringVar(&config.terraBaseRepo, "terrabase-repo", "", "absolute TerraBase repository root")
	set.StringVar(&config.terraBaseBinary, "terrabase-binary", "", "optional prebuilt static TerraBase server")
	if err := set.Parse(args); err != nil {
		return options{}, fmt.Errorf("usage: vm-artifacts --root ABS --repo ABS --terrabase-repo ABS [--terrabase-binary ABS] -- command [args...]: %w", err)
	}
	config.command = set.Args()
	if len(config.command) == 0 {
		return options{}, errors.New("a qualification command is required after --")
	}
	for name, path := range map[string]string{
		"root": config.root, "repo": config.repo, "terrabase-repo": config.terraBaseRepo,
	} {
		if !cleanAbsolute(path) {
			return options{}, fmt.Errorf("--%s must be a clean absolute path", name)
		}
	}
	if config.terraBaseBinary != "" && !cleanAbsolute(config.terraBaseBinary) {
		return options{}, errors.New("--terrabase-binary must be a clean absolute path")
	}
	return config, nil
}

func prepare(ctx context.Context, config options, errOut io.Writer) (bundle, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return bundle{}, fmt.Errorf("native Linux amd64 or arm64 is required, found %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if err := requireRealDirectory(config.repo); err != nil {
		return bundle{}, fmt.Errorf("orchestrator repository: %w", err)
	}
	if config.terraBaseBinary == "" {
		if err := requireRealDirectory(config.terraBaseRepo); err != nil {
			return bundle{}, fmt.Errorf("TerraBase repository: %w", err)
		}
	}
	if err := os.MkdirAll(config.root, 0o700); err != nil {
		return bundle{}, fmt.Errorf("create qualification root: %w", err)
	}
	if err := requireRealDirectory(config.root); err != nil {
		return bundle{}, fmt.Errorf("qualification root: %w", err)
	}
	directory, err := os.MkdirTemp(config.root, artifactPrefix)
	if err != nil {
		return bundle{}, fmt.Errorf("create private artifact directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.Remove(directory)
		return bundle{}, fmt.Errorf("secure private artifact directory: %w", err)
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		_ = os.Remove(directory)
		return bundle{}, fmt.Errorf("inspect private artifact directory: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = cleanupOwnedDirectory(config.root, directory, directoryInfo)
		}
	}()

	artifacts := []artifact{
		{component: "ts-node", environment: "TS_VM_TS_NODE", path: filepath.Join(directory, "ts-node")},
		{component: "orchestrator", environment: "TS_VM_ORCHESTRATOR", path: filepath.Join(directory, "orchestrator")},
		{component: "terrabase", environment: "TS_VM_TERRABASE", path: filepath.Join(directory, "terrabase")},
	}
	if err := buildGoArtifact(ctx, config.repo, "./cmd/ts-node", artifacts[0].path, errOut); err != nil {
		return bundle{}, fmt.Errorf("build ts-node: %w", err)
	}
	if err := buildGoArtifact(ctx, config.repo, "./cmd/orchestrator", artifacts[1].path, errOut); err != nil {
		return bundle{}, fmt.Errorf("build orchestrator: %w", err)
	}
	if config.terraBaseBinary != "" {
		if err := copyArtifact(config.terraBaseBinary, artifacts[2].path); err != nil {
			return bundle{}, fmt.Errorf("materialize TerraBase binary: %w", err)
		}
	} else if err := buildTerraBase(ctx, config.terraBaseRepo, directory, artifacts[2].path, errOut); err != nil {
		return bundle{}, err
	}

	validated, err := validateArtifacts(artifacts)
	if err != nil {
		return bundle{}, err
	}
	prepared, err := signArtifacts(directory, validated, errOut)
	if err != nil {
		zeroArtifacts(validated)
		return bundle{}, err
	}
	prepared.directoryInfo = directoryInfo
	failed = false
	return prepared, nil
}

func signArtifacts(directory string, validated []artifact, errOut io.Writer) (bundle, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return bundle{}, fmt.Errorf("generate qualification-only Ed25519 key: %w", err)
	}
	defer zero(privateKey)
	publicKeyPath := filepath.Join(directory, "qualification-only-release-public-key.hex")
	if err := writeExclusive(publicKeyPath, []byte(hex.EncodeToString(publicKey)+"\n"), 0o444); err != nil {
		return bundle{}, fmt.Errorf("write qualification public key: %w", err)
	}
	for index := range validated {
		validated[index].signaturePath = validated[index].path + ".sig"
		signature := ed25519.Sign(privateKey, validated[index].data)
		encoded := []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
		if err := writeExclusive(validated[index].signaturePath, encoded, 0o444); err != nil {
			zero(signature)
			zero(encoded)
			return bundle{}, fmt.Errorf("sign %s: %w", validated[index].component, err)
		}
		zero(signature)
		zero(encoded)
		validated[index].version = "vmqual." + hex.EncodeToString(validated[index].digest[:8])
	}
	_, _ = fmt.Fprintln(errOut, "vm-artifacts: using an ephemeral qualification-only Ed25519 release key (private key retained in memory only)")
	return bundle{directory: directory, publicKey: publicKeyPath, artifacts: validated}, nil
}

func buildGoArtifact(ctx context.Context, repository, packagePath, output string, errOut io.Writer) error {
	command := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-ldflags=-s -w", "-o", output, packagePath)
	command.Dir = repository
	command.Env = replaceEnvironment(os.Environ(), map[string]string{
		"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": runtime.GOARCH,
	})
	command.Stdout, command.Stderr = io.Discard, errOut
	if err := command.Run(); err != nil {
		return err
	}
	return os.Chmod(output, 0o755)
}

func buildTerraBase(ctx context.Context, repository, directory, output string, errOut io.Writer) error {
	target := "x86_64-unknown-linux-musl"
	if runtime.GOARCH == "arm64" {
		target = "aarch64-unknown-linux-musl"
	}
	targetDirectory := filepath.Join(directory, "cargo-target")
	command := exec.CommandContext(ctx, "cargo", "build", "--locked", "--release", "--target", target, "-p", "terrabase-server", "--bin", "terrabase-server")
	command.Dir = repository
	command.Env = replaceEnvironment(os.Environ(), map[string]string{"CARGO_TARGET_DIR": targetDirectory})
	command.Stdout, command.Stderr = io.Discard, errOut
	if err := command.Run(); err != nil {
		return fmt.Errorf("build TerraBase for %s: %w (install the pinned Rust musl target or set VM_TERRABASE_BINARY to an exact static native terrabase-server)", target, err)
	}
	built := filepath.Join(targetDirectory, target, "release", "terrabase-server")
	if err := copyArtifact(built, output); err != nil {
		return fmt.Errorf("materialize built TerraBase server: %w", err)
	}
	return nil
}

func copyArtifact(source, destination string) error {
	if !cleanAbsolute(source) {
		return errors.New("source path must be clean and absolute")
	}
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil || resolved != source {
		return errors.New("source path must exist without symlinks")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > artifactLimit {
		return errors.New("source must be a nonempty bounded regular file")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("source identity changed while opening")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, artifactLimit+1))
	if copyErr == nil && written != info.Size() {
		copyErr = errors.New("source changed while copying")
	}
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	return os.Chmod(destination, 0o755)
}

func validateArtifacts(inputs []artifact) ([]artifact, error) {
	validated := append([]artifact(nil), inputs...)
	seenDigest := make(map[[sha256.Size]byte]string, len(validated))
	var seenInfo []os.FileInfo
	for index := range validated {
		data, info, digest, err := validateArtifact(validated[index].path)
		if err != nil {
			zeroArtifacts(validated)
			return nil, fmt.Errorf("%s artifact: %w", validated[index].component, err)
		}
		for previous, previousInfo := range seenInfo {
			if os.SameFile(info, previousInfo) {
				zero(data)
				zeroArtifacts(validated)
				return nil, fmt.Errorf("%s artifact aliases %s", validated[index].component, validated[previous].component)
			}
		}
		if previous, exists := seenDigest[digest]; exists {
			zero(data)
			zeroArtifacts(validated)
			return nil, fmt.Errorf("%s artifact duplicates %s bytes", validated[index].component, previous)
		}
		seenDigest[digest] = validated[index].component
		seenInfo = append(seenInfo, info)
		validated[index].data, validated[index].digest, validated[index].info = data, digest, info
	}
	return validated, nil
}

func validateArtifact(path string) ([]byte, os.FileInfo, [sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	if !cleanAbsolute(path) {
		return nil, nil, empty, errors.New("path must be clean and absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, nil, empty, errors.New("path must not contain symlinks")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, empty, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o755 || info.Size() <= 0 || info.Size() > artifactLimit {
		return nil, nil, empty, errors.New("file must be a nonempty regular 0755 binary no larger than 16 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, empty, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, empty, errors.New("file identity changed while opening")
	}
	if err := validateStaticELF(file); err != nil {
		return nil, nil, empty, err
	}
	data, err := io.ReadAll(io.LimitReader(file, artifactLimit+1))
	if err != nil || int64(len(data)) != info.Size() {
		zero(data)
		if err == nil {
			err = errors.New("file changed while reading")
		}
		return nil, nil, empty, err
	}
	final, err := file.Stat()
	if err != nil || !sameFileState(opened, final) {
		zero(data)
		return nil, nil, empty, errors.New("file changed while validating")
	}
	return data, info, sha256.Sum256(data), nil
}

func validateStaticELF(input io.ReaderAt) error {
	file, err := elf.NewFile(input)
	if err != nil {
		return errors.New("binary is not ELF")
	}
	defer file.Close()
	wantMachine := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		wantMachine = elf.EM_AARCH64
	}
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != wantMachine || (file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN) {
		return errors.New("binary ELF format or architecture is not native and admitted")
	}
	for _, program := range file.Progs {
		if program.Type == elf.PT_INTERP {
			return errors.New("binary requires a dynamic interpreter")
		}
	}
	needed, err := file.DynString(elf.DT_NEEDED)
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return fmt.Errorf("inspect ELF dynamic dependencies: %w", err)
	}
	if len(needed) != 0 {
		return fmt.Errorf("binary has dynamic dependencies: %s", strings.Join(needed, ", "))
	}
	return nil
}

func bundleEnvironment(base []string, prepared bundle) []string {
	values := map[string]string{"TS_VM_RELEASE_PUBLIC_KEY": prepared.publicKey}
	for _, artifact := range prepared.artifacts {
		values[artifact.environment] = artifact.path
		values[artifact.environment+"_SIGNATURE"] = artifact.signaturePath
		values[artifact.environment+"_VERSION"] = artifact.version
	}
	return replaceSelectedEnvironment(base, artifactEnvironment, values)
}

func replaceEnvironment(base []string, replacements map[string]string) []string {
	keys := make([]string, 0, len(replacements))
	for key := range replacements {
		keys = append(keys, key)
	}
	return replaceSelectedEnvironment(base, keys, replacements)
}

func replaceSelectedEnvironment(base, keys []string, replacements map[string]string) []string {
	removed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		removed[key] = struct{}{}
	}
	result := make([]string, 0, len(base)+len(replacements))
	for _, item := range base {
		key, _, found := strings.Cut(item, "=")
		if _, remove := removed[key]; !found || !remove {
			result = append(result, item)
		}
	}
	for _, key := range keys {
		if value, exists := replacements[key]; exists {
			result = append(result, key+"="+value)
		}
	}
	return result
}

func runChild(ctx context.Context, arguments, environment []string, out, errOut io.Writer) error {
	command := exec.Command(arguments[0], arguments[1:]...)
	command.Env, command.Stdin, command.Stdout, command.Stderr = environment, os.Stdin, out, errOut
	configureChildProcess(command)
	if err := command.Start(); err != nil {
		return fmt.Errorf("start qualification command: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = interruptChildProcess(command)
		select {
		case err := <-done:
			return errors.Join(ctx.Err(), err)
		case <-time.After(childShutdownWindow):
			_ = killChildProcess(command)
			return errors.Join(ctx.Err(), <-done)
		}
	}
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, file.Sync(), file.Close(), os.Chmod(path, mode))
}

func requireRealDirectory(path string) error {
	if !cleanAbsolute(path) {
		return errors.New("path must be clean and absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("path must exist without symlinks")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path must be a directory")
	}
	return nil
}

func cleanupOwnedDirectory(root, path string, expected os.FileInfo) error {
	if !cleanAbsolute(root) || !cleanAbsolute(path) || filepath.Dir(path) != root || !strings.HasPrefix(filepath.Base(path), artifactPrefix) {
		return errors.New("refusing to remove a directory not owned by vm-artifacts")
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("owned artifact path is not a real directory")
	}
	if expected == nil || !os.SameFile(info, expected) {
		return errors.New("owned artifact directory identity changed")
	}
	return os.RemoveAll(path)
}

func cleanAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func zeroArtifacts(artifacts []artifact) {
	for index := range artifacts {
		zero(artifacts[index].data)
	}
}

func zero(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func sameFileState(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime() == after.ModTime()
}
