package deploy_test

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

func deviceLines(t *testing.T) []string {
	t.Helper()
	var lines []string
	for line := range strings.SplitSeq(string(read(t, filepath.Join(deployRoot(t), "deploy/udev/65-terrascale-oci-device-paths.rules"))), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}
func ociDeviceName(lun int) string {
	letters := ""
	for lun > 0 {
		lun--
		letters = string(rune('a'+lun%26)) + letters
		lun /= 26
	}
	return "oraclevd" + letters
}

var linkRule = regexp.MustCompile(`^ENV\{ID_PATH\}=="pci-\*-scsi-0:0:0:(\d+)", SYMLINK\+="oracleoci/(oraclevd[a-z]+)"$`)

func TestOCIDevicePathsNameEveryLUN(t *testing.T) {
	links := map[int]string{}
	count := 0
	for _, line := range deviceLines(t) {
		if strings.Contains(line, "SYMLINK") {
			count++
		}
		if m := linkRule.FindStringSubmatch(line); m != nil {
			lun, _ := strconv.Atoi(m[1])
			if _, found := links[lun]; found {
				t.Fatalf("duplicate LUN %d", lun)
			}
			links[lun] = m[2]
		}
	}
	equal(t, count, 32)
	equal(t, len(links), 32)
	for lun := range 32 {
		equal(t, links[lun+1], ociDeviceName(lun+1))
	}
	for lun, name := range map[int]string{1: "oraclevda", 2: "oraclevdb", 6: "oraclevdf", 27: "oraclevdaa", 32: "oraclevdaf"} {
		equal(t, links[lun], name)
	}
}
func TestOCIDevicePathsGateWholeOraclePCISCSIVolumes(t *testing.T) {
	lines := deviceLines(t)
	i := slices.Index(lines, `LABEL="terrascale_oci_block_volume"`)
	if i < 0 {
		t.Fatal("missing block-volume label")
	}
	equal(t, lines[:i], []string{`ACTION=="remove", GOTO="terrascale_oci_device_paths_end"`, `SUBSYSTEM!="block", GOTO="terrascale_oci_device_paths_end"`, `ENV{DEVTYPE}!="disk", GOTO="terrascale_oci_device_paths_end"`, `KERNEL!="sd*", GOTO="terrascale_oci_device_paths_end"`, `SUBSYSTEMS=="scsi", ATTRS{vendor}=="ORACLE*", ATTRS{model}=="BlockVolume*", GOTO="terrascale_oci_block_volume"`, `GOTO="terrascale_oci_device_paths_end"`})
	body := lines[i:]
	equal(t, body[:2], []string{`LABEL="terrascale_oci_block_volume"`, `IMPORT{builtin}="path_id"`})
	equal(t, body[len(body)-1], `LABEL="terrascale_oci_device_paths_end"`)
	for _, line := range body[2 : len(body)-1] {
		if !linkRule.MatchString(line) {
			t.Fatal(fmt.Sprintf("unexpected body rule: %s", line))
		}
	}
}
func TestOCIDevicePathsParseUnderUdev(t *testing.T) {
	if _, err := exec.LookPath("udevadm"); err != nil {
		t.Skip("udevadm is not installed")
	}
	successful(t, script.Run(t, deployRoot(t), nil, "udevadm", "verify", filepath.Join(deployRoot(t), "deploy/udev/65-terrascale-oci-device-paths.rules")))
}
