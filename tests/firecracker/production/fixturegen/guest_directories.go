package fixturegen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const guestDirectoryPlanPath = "simulator/guest-directories.json"

// GuestDirectory is an explicit installation instruction for a signed guest
// root. The VM driver must create it with this owner and mode before copying
// service-owned floor, lock, and credential files into the guest.
type GuestDirectory struct {
	ControllerSlot string `json:"controllerSlot"`
	GuestPath      string `json:"guestPath"`
	Mode           uint32 `json:"mode"`
	OwnerRole      string `json:"ownerRole"`
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
}

// GuestDirectories returns the signed directory installation plan for one
// controller and rechecks the plan bytes against the packet inventory.
func (packet VerifiedPacket) GuestDirectories(slot string) ([]GuestDirectory, error) {
	if packet.root == "" {
		return nil, errors.New("packet was not verified")
	}
	var listed *FileEntry
	files := make(map[string]bool, len(packet.manifest.Files))
	for index := range packet.manifest.Files {
		entry := &packet.manifest.Files[index]
		files[entry.Path] = true
		if entry.Path == guestDirectoryPlanPath {
			listed = entry
		}
	}
	if listed == nil {
		return nil, errors.New("packet lacks signed guest directory plan")
	}
	name := filepath.Join(packet.root, guestDirectoryPlanPath)
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() != listed.Size {
		return nil, errors.New("signed guest directory plan is missing or nonregular")
	}
	wire, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(wire)
	if hex.EncodeToString(digest[:]) != listed.SHA256 {
		return nil, errors.New("signed guest directory plan changed")
	}
	plan, err := parseGuestDirectories(wire, packet.manifest.Controllers,
		func(path string) bool { return files[path] })
	if err != nil {
		return nil, err
	}
	var selected []GuestDirectory
	for _, directory := range plan {
		if directory.ControllerSlot == slot {
			selected = append(selected, directory)
		}
	}
	if len(selected) != 2 {
		return nil, fmt.Errorf("unknown or incomplete controller slot %q", slot)
	}
	return selected, nil
}

func parseGuestDirectories(wire []byte, controllers []Controller, hasFile func(string) bool) ([]GuestDirectory, error) {
	if len(wire) == 0 || len(wire) > 4096 || len(controllers) != 3 || hasFile == nil {
		return nil, errors.New("guest directory plan is absent or oversized")
	}
	var plan []GuestDirectory
	if err := json.Unmarshal(wire, &plan, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("decode guest directory plan: %w", err)
	}
	canonical, err := protocol.EncodeJSON(plan)
	if err != nil || !bytes.Equal(canonical, wire) || len(plan) != 2*len(controllers) {
		return nil, errors.New("guest directory plan is not canonical or complete")
	}
	for index, controller := range controllers {
		state := plan[index*2]
		secrets := plan[index*2+1]
		if state.ControllerSlot != controller.Slot || secrets.ControllerSlot != controller.Slot ||
			state.GuestPath != "/var/lib/terrascale-orchestrator-controller" ||
			secrets.GuestPath != serviceSecretsGuestDir ||
			state.Mode != 0o700 || secrets.Mode != 0o700 ||
			state.OwnerRole != "service:"+controller.Slot ||
			secrets.OwnerRole != state.OwnerRole ||
			state.UID == 0 || state.GID == 0 ||
			secrets.UID != state.UID || secrets.GID != state.GID {
			return nil, fmt.Errorf("guest directories for %q lack fixed service ownership", controller.Slot)
		}
		for _, name := range []string{"founder-selection-floor.json", ".founder-selection-floor.lock"} {
			if !hasFile(controller.GuestRoot + state.GuestPath + "/" + name) {
				return nil, fmt.Errorf("guest directory %q lacks verified %s", controller.Slot, name)
			}
		}
		credentialPrefix := controller.GuestRoot + secrets.GuestPath + "/"
		if !hasFile(credentialPrefix + "operator.jwt") {
			return nil, fmt.Errorf("guest directory %q lacks signed operator credential", controller.Slot)
		}
	}
	if !slices.ContainsFunc(plan, func(directory GuestDirectory) bool { return directory.ControllerSlot == "seed-a" }) {
		return nil, errors.New("guest directory plan lacks seed")
	}
	return plan, nil
}
