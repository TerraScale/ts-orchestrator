//go:build sandboxvm

package vmqualruntime

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

type qualificationChronyPin struct {
	URL, SHA256 string
	Size        int64
}

// Pins transcribed from Ubuntu noble-updates/main Packages for chrony
// 4.5-1ubuntu4.2. Only binaries are extracted; installation is offline inside
// each private guest root. The pinned minimal image supplies the shared libs.
var qualificationChronyPins = map[vmimage.Architecture]qualificationChronyPin{
	vmimage.ArchitectureAMD64: {"https://archive.ubuntu.com/ubuntu/pool/main/c/chrony/chrony_4.5-1ubuntu4.2_amd64.deb", "434f9fda4bf0de2d0c89c132a0b2c1ddda2fdd50c2b0338e1422d015c45d72d2", 316380},
	vmimage.ArchitectureARM64: {"https://ports.ubuntu.com/ubuntu-ports/pool/main/c/chrony/chrony_4.5-1ubuntu4.2_arm64.deb", "503d1f389dde1d540ae6f2c98bdac98040c70a2ce7d8da1458a8e04cd9dad1fd", 319008},
}
var qualificationChronyCache sync.Map

func loadQualificationChrony(ctx context.Context, architecture vmimage.Architecture) ([]vmimage.NoCloudRootFile, error) {
	pin, ok := qualificationChronyPins[architecture]
	if !ok {
		return nil, errors.New("vmqual: chrony architecture is not pinned")
	}
	if cached, ok := qualificationChronyCache.Load(architecture); ok {
		return copyChronyFiles(cached.([]vmimage.NoCloudRootFile)), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pin.URL, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("vmqual: chrony package redirects are forbidden")
	}}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("vmqual: download pinned chrony: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vmqual: chrony download status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, pin.Size+1))
	if err != nil {
		return nil, err
	}
	files, err := extractQualificationChrony(data, pin, architecture)
	if err != nil {
		return nil, err
	}
	qualificationChronyCache.Store(architecture, files)
	return copyChronyFiles(files), nil
}

func copyChronyFiles(files []vmimage.NoCloudRootFile) []vmimage.NoCloudRootFile {
	result := append([]vmimage.NoCloudRootFile(nil), files...)
	for i := range result {
		result[i].Content = bytes.Clone(result[i].Content)
	}
	return result
}

func extractQualificationChrony(data []byte, pin qualificationChronyPin, architecture vmimage.Architecture) ([]vmimage.NoCloudRootFile, error) {
	sum := sha256.Sum256(data)
	if int64(len(data)) != pin.Size || hex.EncodeToString(sum[:]) != pin.SHA256 {
		return nil, errors.New("vmqual: chrony package size or digest mismatch")
	}
	if !bytes.HasPrefix(data, []byte("!<arch>\n")) {
		return nil, errors.New("vmqual: invalid chrony Debian archive")
	}
	var compressed []byte
	for offset := 8; offset < len(data); {
		if len(data)-offset < 60 {
			return nil, errors.New("vmqual: truncated chrony archive")
		}
		header := data[offset : offset+60]
		offset += 60
		size, err := strconv.Atoi(strings.TrimSpace(string(header[48:58])))
		if err != nil || size < 0 || size > len(data)-offset || string(header[58:60]) != "`\n" {
			return nil, errors.New("vmqual: invalid chrony archive member")
		}
		if strings.TrimSpace(string(header[:16])) == "data.tar.zst" {
			if compressed != nil {
				return nil, errors.New("vmqual: duplicate chrony data member")
			}
			compressed = data[offset : offset+size]
		}
		offset += size + size%2
	}
	if len(compressed) == 0 {
		return nil, errors.New("vmqual: chrony data archive missing")
	}
	decoder, err := zstd.NewReader(bytes.NewReader(compressed), zstd.WithDecoderMaxMemory(8<<20), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	archive := tar.NewReader(io.LimitReader(decoder, (8<<20)+1))
	found := make(map[string][]byte)
	for count := 0; ; count++ {
		entry, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if count > 512 {
			return nil, errors.New("vmqual: chrony archive has too many entries")
		}
		if entry.Name != "./usr/sbin/chronyd" && entry.Name != "./usr/bin/chronyc" {
			continue
		}
		if entry.Typeflag != tar.TypeReg || entry.Size < 1 || entry.Size > 2<<20 || found[entry.Name] != nil {
			return nil, errors.New("vmqual: invalid chrony executable entry")
		}
		content, err := io.ReadAll(archive)
		if err != nil {
			return nil, err
		}
		executable, err := elf.NewFile(bytes.NewReader(content))
		if err != nil {
			return nil, err
		}
		machine := elf.EM_X86_64
		if architecture == vmimage.ArchitectureARM64 {
			machine = elf.EM_AARCH64
		}
		if executable.Machine != machine || executable.Class != elf.ELFCLASS64 {
			return nil, errors.New("vmqual: chrony executable architecture mismatch")
		}
		found[entry.Name] = content
	}
	if len(found) != 2 {
		return nil, errors.New("vmqual: chrony executables missing")
	}
	return []vmimage.NoCloudRootFile{{Path: "/usr/sbin/chronyd", Mode: 0555, Content: found["./usr/sbin/chronyd"]}, {Path: "/usr/bin/chronyc", Mode: 0555, Content: found["./usr/bin/chronyc"]}}, nil
}
