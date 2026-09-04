package vmimage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const maxFilesystemToolOutput = 1 << 20

var blockSizePattern = regexp.MustCompile(`(?m)^Block size:\s+([0-9]+)\s*$`)

// RootFSPreparer is the typed filesystem boundary between raw partition
// extraction and final digest verification.
type RootFSPreparer interface {
	Prepare(context.Context, string, string) (RootFSInspection, error)
}

// RootFSPreparerFunc adapts a deterministic test function to RootFSPreparer.
type RootFSPreparerFunc func(context.Context, string, string) (RootFSInspection, error)

func (function RootFSPreparerFunc) Prepare(ctx context.Context, path, ubuntuRelease string) (RootFSInspection, error) {
	return function(ctx, path, ubuntuRelease)
}

// OutputCommandRunner is the no-shell argv boundary used by Ext4Preparer.
type OutputCommandRunner interface {
	Output(context.Context, string, ...string) ([]byte, error)
}

type execOutputRunner struct{}

func (execOutputRunner) Output(ctx context.Context, executable string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, args...)
	var stdout, stderr limitedBuffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

type limitedBuffer struct {
	bytes.Buffer
}

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	if buffer.Len() >= maxFilesystemToolOutput {
		return 0, errors.New("vmimage: filesystem tool output exceeds limit")
	}
	remaining := maxFilesystemToolOutput - buffer.Len()
	if len(data) > remaining {
		_, _ = buffer.Buffer.Write(data[:remaining])
		return remaining, errors.New("vmimage: filesystem tool output exceeds limit")
	}
	return buffer.Buffer.Write(data)
}

// Ext4Preparer verifies the exact Ubuntu identity, removes only the two
// bootloader mounts that Firecracker cannot provide, and checks the resulting
// filesystem. It edits file data in place, preserving inode metadata and file
// length so the result depends only on the pinned source bytes.
type Ext4Preparer struct {
	DebugFSPath string
	E2FSCKPath  string
	Runner      OutputCommandRunner
}

func (preparer Ext4Preparer) Prepare(ctx context.Context, imagePath, ubuntuRelease string) (RootFSInspection, error) {
	if ctx == nil {
		return RootFSInspection{}, errors.New("vmimage: ext4 preparation context is nil")
	}
	if err := verifyRegular(imagePath); err != nil {
		return RootFSInspection{}, fmt.Errorf("vmimage: ext4 image is not a regular file: %w", err)
	}
	if !isUbuntuLTS(ubuntuRelease) {
		return RootFSInspection{}, errors.New("vmimage: expected Ubuntu release is invalid")
	}
	debugfs, err := resolveExecutable(preparer.DebugFSPath, "debugfs")
	if err != nil {
		return RootFSInspection{}, err
	}
	e2fsck, err := resolveExecutable(preparer.E2FSCKPath, "e2fsck")
	if err != nil {
		return RootFSInspection{}, err
	}
	runner := preparer.Runner
	if runner == nil {
		runner = execOutputRunner{}
	}
	osRelease, err := runFilesystemTool(ctx, runner, debugfs, "-R", "cat /usr/lib/os-release", imagePath)
	if err != nil {
		return RootFSInspection{}, fmt.Errorf("vmimage: inspect Ubuntu identity: %w", err)
	}
	identity, err := verifyUbuntuIdentity(osRelease, ubuntuRelease)
	if err != nil {
		return RootFSInspection{}, err
	}
	fstab, err := runFilesystemTool(ctx, runner, debugfs, "-R", "cat /etc/fstab", imagePath)
	if err != nil {
		return RootFSInspection{}, fmt.Errorf("vmimage: inspect guest fstab: %w", err)
	}
	sanitized, err := sanitizeUbuntuFSTab(fstab)
	if err != nil {
		return RootFSInspection{}, err
	}
	stats, err := runFilesystemTool(ctx, runner, debugfs, "-R", "stats", imagePath)
	if err != nil {
		return RootFSInspection{}, fmt.Errorf("vmimage: inspect ext4 geometry: %w", err)
	}
	blockSize, err := parseExt4BlockSize(stats)
	if err != nil {
		return RootFSInspection{}, err
	}
	blocksOutput, err := runFilesystemTool(ctx, runner, debugfs, "-R", "blocks /etc/fstab", imagePath)
	if err != nil {
		return RootFSInspection{}, fmt.Errorf("vmimage: locate guest fstab: %w", err)
	}
	blocks, err := parseExt4Blocks(blocksOutput, len(fstab), blockSize)
	if err != nil {
		return RootFSInspection{}, err
	}
	if err := patchExt4File(imagePath, fstab, sanitized, blockSize, blocks); err != nil {
		return RootFSInspection{}, err
	}
	got, err := runFilesystemTool(ctx, runner, debugfs, "-R", "cat /etc/fstab", imagePath)
	if err != nil {
		return RootFSInspection{}, fmt.Errorf("vmimage: re-read guest fstab: %w", err)
	}
	if !bytes.Equal(got, sanitized) {
		return RootFSInspection{}, errors.New("vmimage: sanitized guest fstab did not round-trip exactly")
	}
	if _, err := runFilesystemTool(ctx, runner, e2fsck, "-fn", imagePath); err != nil {
		return RootFSInspection{}, fmt.Errorf("vmimage: check prepared ext4 filesystem: %w", err)
	}
	return RootFSInspection{OSID: identity.ID, OSVersionID: identity.VersionID, OSVersion: identity.Version, SanitizedMounts: []string{"/boot", "/boot/efi"}, FilesystemCheck: "e2fsck -fn"}, nil
}

func runFilesystemTool(ctx context.Context, runner OutputCommandRunner, executable string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return runner.Output(ctx, executable, args...)
}

func resolveExecutable(configured, name string) (string, error) {
	executable := configured
	if executable == "" {
		var err error
		executable, err = exec.LookPath(name)
		if err != nil {
			return "", fmt.Errorf("vmimage: %s is required to prepare the Ubuntu filesystem", name)
		}
	}
	if !strings.HasPrefix(executable, "/") {
		return "", fmt.Errorf("vmimage: invalid %s executable: path must be absolute", name)
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("vmimage: invalid %s executable: %w", name, err)
	}
	if err := validateExecutable(resolved); err != nil {
		return "", fmt.Errorf("vmimage: invalid %s executable: %w", name, err)
	}
	return resolved, nil
}

func validateExecutable(path string) error {
	if path == "" || !strings.HasPrefix(path, "/") {
		return errors.New("path must be absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return errors.New("path must be an executable regular non-symlink file")
	}
	return nil
}

type ubuntuIdentity struct {
	ID        string
	VersionID string
	Version   string
}

func verifyUbuntuIdentity(content []byte, release string) (ubuntuIdentity, error) {
	values := make(map[string]string)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return ubuntuIdentity{}, errors.New("vmimage: guest os-release is malformed")
		}
		if _, exists := values[key]; exists {
			return ubuntuIdentity{}, errors.New("vmimage: guest os-release repeats a field")
		}
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return ubuntuIdentity{}, errors.New("vmimage: guest os-release contains invalid quoting")
			}
			value = decoded
		} else if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	series := release
	if index := strings.LastIndex(series, "."); index > strings.Index(series, ".") {
		series = series[:index]
	}
	if values["ID"] != "ubuntu" || values["VERSION_ID"] != series || !strings.Contains(values["VERSION"], release+" LTS") {
		return ubuntuIdentity{}, fmt.Errorf("vmimage: guest identity is not Ubuntu %s LTS", release)
	}
	return ubuntuIdentity{ID: values["ID"], VersionID: values["VERSION_ID"], Version: values["VERSION"]}, nil
}

func sanitizeUbuntuFSTab(content []byte) ([]byte, error) {
	if len(content) == 0 || len(content) > maxFilesystemToolOutput {
		return nil, errors.New("vmimage: guest fstab size is invalid")
	}
	result := append([]byte(nil), content...)
	seen := map[string]int{"/boot": 0, "/boot/efi": 0}
	for start := 0; start < len(content); {
		end := bytes.IndexByte(content[start:], '\n')
		if end < 0 {
			end = len(content)
		} else {
			end += start
		}
		line := content[start:end]
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 && trimmed[0] != '#' {
			fields := strings.Fields(string(trimmed))
			if len(fields) < 4 {
				return nil, errors.New("vmimage: guest fstab contains a malformed active record")
			}
			mount := fields[1]
			if mount == "/boot" || mount == "/boot/efi" {
				expectedSource := map[string]string{"/boot": "LABEL=BOOT", "/boot/efi": "LABEL=UEFI"}[mount]
				if fields[0] != expectedSource || seen[mount] != 0 {
					return nil, fmt.Errorf("vmimage: guest fstab has an unexpected %s mount", mount)
				}
				first := bytes.IndexFunc(line, func(character rune) bool { return character != ' ' && character != '\t' })
				if first < 0 {
					return nil, errors.New("vmimage: guest fstab boot record is empty")
				}
				result[start+first] = '#'
				seen[mount]++
			}
		}
		if end == len(content) {
			break
		}
		start = end + 1
	}
	if seen["/boot"] != 1 || seen["/boot/efi"] != 1 {
		return nil, errors.New("vmimage: guest fstab does not contain the expected BOOT and UEFI records")
	}
	return result, nil
}

func parseExt4BlockSize(output []byte) (int64, error) {
	match := blockSizePattern.FindSubmatch(output)
	if match == nil {
		return 0, errors.New("vmimage: debugfs did not report an ext4 block size")
	}
	value, err := strconv.ParseInt(string(match[1]), 10, 64)
	if err != nil || value < 1024 || value > 65536 || value&(value-1) != 0 {
		return 0, errors.New("vmimage: ext4 block size is invalid")
	}
	return value, nil
}

func parseExt4Blocks(output []byte, fileSize int, blockSize int64) ([]int64, error) {
	want := (int64(fileSize) + blockSize - 1) / blockSize
	fields := strings.Fields(string(output))
	if int64(len(fields)) != want || want == 0 {
		return nil, errors.New("vmimage: guest fstab block map is sparse or incomplete")
	}
	blocks := make([]int64, len(fields))
	for index, field := range fields {
		block, err := strconv.ParseInt(field, 10, 64)
		if err != nil || block <= 0 || block > (1<<63-1)/blockSize {
			return nil, errors.New("vmimage: guest fstab block map is invalid")
		}
		blocks[index] = block
	}
	return blocks, nil
}

func patchExt4File(imagePath string, original, replacement []byte, blockSize int64, blocks []int64) error {
	if len(original) != len(replacement) || bytes.Equal(original, replacement) {
		return errors.New("vmimage: guest fstab replacement must change bytes without changing length")
	}
	file, err := os.OpenFile(imagePath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	for index, block := range blocks {
		start := int64(index) * blockSize
		end := start + blockSize
		if end > int64(len(original)) {
			end = int64(len(original))
		}
		offset := block * blockSize
		length := end - start
		if offset < 0 || length <= 0 || offset > info.Size() || length > info.Size()-offset {
			return errors.New("vmimage: guest fstab block lies outside the ext4 image")
		}
		current := make([]byte, length)
		if _, err := file.ReadAt(current, offset); err != nil {
			return err
		}
		if !bytes.Equal(current, original[start:end]) {
			return errors.New("vmimage: guest fstab block map does not match inspected content")
		}
		if _, err := file.WriteAt(replacement[start:end], offset); err != nil {
			return err
		}
	}
	return file.Sync()
}
