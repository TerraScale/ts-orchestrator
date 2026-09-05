//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"os"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
)

func TestQualificationChronyRejectsUnpinnedBytes(t *testing.T) {
	for architecture, pin := range qualificationChronyPins {
		for _, data := range [][]byte{nil, make([]byte, pin.Size), []byte("!<arch>\n")} {
			if _, err := extractQualificationChrony(data, pin, architecture); err == nil {
				t.Fatal("unverified package accepted")
			}
		}
	}
}

func TestQualificationChronyRealPinnedPackages(t *testing.T) {
	for architecture, env := range map[vmimage.Architecture]string{vmimage.ArchitectureAMD64: "TS_VM_CHRONY_PACKAGE_AMD64", vmimage.ArchitectureARM64: "TS_VM_CHRONY_PACKAGE_ARM64"} {
		t.Run(string(architecture), func(t *testing.T) {
			path := os.Getenv(env)
			if path == "" {
				t.Skip("set " + env + " to a downloaded pinned Debian package")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			files, err := extractQualificationChrony(data, qualificationChronyPins[architecture], architecture)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				if err := file.Validate(); err != nil {
					t.Fatal(err)
				}
			}
			copied := copyChronyFiles(files)
			copied[0].Content[0] ^= 1
			if bytes.Equal(copied[0].Content, files[0].Content) {
				t.Fatal("binary cache aliases caller memory")
			}
			data[len(data)/2] ^= 1
			if _, err := extractQualificationChrony(data, qualificationChronyPins[architecture], architecture); err == nil {
				t.Fatal("corrupted package accepted")
			}
		})
	}
}
