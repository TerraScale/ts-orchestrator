package deploy_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// The image package separately covers download checksums and runtime installation.
// This command contract uses inert ELF fixtures instead of GitHub release downloads.
func offlineRuntimeFetch(ctx context.Context, source, target, checksum string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var payload []byte
	switch {
	case strings.Contains(source, "/containerd-static-"):
		parts := strings.Split(source, "/")
		version := parts[len(parts)-2]
		architecture := strings.TrimSuffix(strings.TrimPrefix(parts[len(parts)-1], "containerd-static-"+strings.TrimPrefix(version, "v")+"-linux-"), ".tar.gz")
		executable := offlineRuntimeELF(architecture, "github.com/containerd/containerd/v2", version)
		var archive bytes.Buffer
		gz := gzip.NewWriter(&archive)
		tw := tar.NewWriter(gz)
		for _, name := range []string{"bin/containerd", "bin/containerd-shim-runc-v2"} {
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(executable)), Typeflag: tar.TypeReg}); err != nil {
				return err
			}
			if _, err := tw.Write(executable); err != nil {
				return err
			}
		}
		if err := tw.Close(); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		payload = archive.Bytes()
	case strings.Contains(source, "/runc/releases/download/"):
		parts := strings.Split(source, "/")
		payload = offlineRuntimeELF(strings.TrimPrefix(parts[len(parts)-1], "runc."), "github.com/opencontainers/runc", parts[len(parts)-2])
	default:
		return fmt.Errorf("unexpected runtime artifact: %s", source)
	}
	if len(checksum) != 64 {
		return fmt.Errorf("missing pinned runtime checksum")
	}
	return os.WriteFile(target, payload, 0755)
}

// The fixture contains ELF and Go build metadata; guest executable bytes are never run.
func offlineRuntimeELF(architecture, module, version string) []byte {
	data := make([]byte, 32)
	copy(data, "\xff Go buildinf:")
	data[14], data[15] = 8, 2
	for _, value := range []string{"go1.27.0", strings.Repeat("x", 16) + "path\t" + module + "/cmd/runtime\nmod\t" + module + "\t" + version + "\t\nbuild\tGOOS=linux\nbuild\tGOARCH=" + architecture + "\n" + strings.Repeat("y", 16)} {
		data = binary.AppendUvarint(data, uint64(len(value)))
		data = append(data, value...)
	}
	file := make([]byte, 4096)
	copy(file, "\x7fELF\x02\x01\x01")
	put16, put32, put64 := binary.LittleEndian.PutUint16, binary.LittleEndian.PutUint32, binary.LittleEndian.PutUint64
	put16(file[16:], 2)
	machine := uint16(183)
	if architecture == "amd64" {
		machine = 62
	}
	put16(file[18:], machine)
	put32(file[20:], 1)
	put64(file[32:], 64)
	put64(file[40:], 128)
	put16(file[52:], 64)
	put16(file[54:], 56)
	put16(file[56:], 1)
	put16(file[58:], 64)
	put16(file[60:], 3)
	put16(file[62:], 2)
	put32(file[64:], 1)
	put32(file[68:], 6)
	put64(file[72:], 4096)
	put64(file[80:], 0x400000)
	put64(file[96:], uint64(len(data)))
	put64(file[104:], uint64(len(data)))
	put64(file[112:], 4096)
	// Go 1.27 locates ELF build metadata through its named section, without a PT_LOAD fallback.
	put32(file[192:], 1)
	put32(file[196:], 1)
	put64(file[200:], 3)
	put64(file[208:], 0x400000)
	put64(file[216:], 4096)
	put64(file[224:], uint64(len(data)))
	put64(file[240:], 16)
	names := "\x00.go.buildinfo\x00.shstrtab\x00"
	put32(file[256:], uint32(len("\x00.go.buildinfo\x00")))
	put32(file[260:], 3)
	put64(file[280:], 320)
	put64(file[288:], uint64(len(names)))
	put64(file[304:], 1)
	copy(file[320:], names)
	return append(file, data...)
}
