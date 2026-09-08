//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"maps"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

// prepareRemoteRun retains a distinct production manifest; candidate preparation
// remains the predecessor until the actual promoted store permits its handoff.
// The service lock is held by Bootstrap, so callers cannot replace cached intent.
func (services *qualificationRuntimeServices) prepareRemoteRun(guest vmqual.Guest, predecessor []byte, initialFiles map[string][]byte) (*vmcontrolseed.RunMaterial, error) {
	admission, ok := services.runAdmissions[guest.ID]
	if !ok {
		return nil, nil
	}
	if services.controlAdmission == nil {
		return nil, errors.New("vmqual: remote run lacks member admission")
	}
	bound, ok := services.controlAdmission.source.admissions[guest.ID]
	if !ok || bound.Generation != int64(admission.Generation) {
		return nil, errors.New("vmqual: run generation differs from immutable member admission")
	}
	var previous hostmanifest.HostManifest
	var err error
	if len(predecessor) > 0 {
		previous, err = hostmanifest.ParseHostManifest(predecessor)
		if err != nil {
			return nil, err
		}
	}
	if material := services.runMaterials[guest.ID]; material != nil {
		if len(predecessor) > 0 {
			err = material.ValidatePredecessor(guest.ID, previous)
		} else {
			err = material.ValidateManifest(guest.ID, material.Manifest)
		}
		return material, err
	}
	identity := services.natsAuthority.memberships[guest.ID]
	if identity == nil {
		return nil, errors.New("vmqual: remote run membership identity missing")
	}
	pins := map[string]string{}
	for host, member := range services.controlAdmission.memberships {
		pins[host] = member.PublicKey
	}
	membershipPins, err := json.Marshal(pins, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(membershipPins)
	membership := initialgrant.Membership{SigningKeyFile: vmcontrolseed.MembershipKeyPath, PublicKey: identity.PublicKey, PinsFile: vmcontrolseed.MembershipPinsPath, PinsSHA256: hex.EncodeToString(digest[:])}
	dependencies := map[string][]byte{vmcontrolseed.MembershipKeyPath: bytes.Clone(identity.PrivatePEM), vmcontrolseed.MembershipPinsPath: membershipPins}
	defer func() {
		for _, raw := range dependencies {
			clear(raw)
		}
	}()
	base, err := hostmanifest.ParseHostManifest(services.manifest)
	if err != nil {
		return nil, err
	}
	if engine := services.engineSeeds[guest.ID]; engine != nil {
		base, err = engine.Apply(base)
		if err != nil {
			return nil, err
		}
		for _, files := range []map[string][]byte{engine.ControlFiles(), engine.DatabaseFiles()} {
			for path, raw := range files {
				if previous, ok := dependencies[path]; ok {
					if !bytes.Equal(previous, raw) {
						return nil, errors.New("vmqual: conflicting remote run dependencies")
					}
					clear(previous)
				}
				dependencies[path] = raw
			}
		}
	}
	if len(predecessor) == 0 {
		reader, err := services.ordinaryAuthority(guest.ID)
		if err != nil {
			return nil, err
		}
		if reader.Reader.PublicNKey == admission.Regional.Connection.PublicNKey {
			return nil, errors.New("vmqual: ordinary reader reuses runtime authority")
		}
		pin, err := reader.ReaderSHA256()
		if err != nil {
			return nil, err
		}
		if admission.Settings == nil {
			return nil, errors.New("vmqual: ordinary run settings missing")
		}
		admission.Settings = maps.Clone(admission.Settings)
		if existing := admission.Settings[vmcontrolseed.NodeAuthorityReaderSHA256Setting]; existing != "" && existing != pin {
			return nil, errors.New("vmqual: ordinary reader differs from declared run pin")
		}
		admission.Settings[vmcontrolseed.NodeAuthorityReaderSHA256Setting] = pin
	}
	material, err := vmcontrolseed.PrepareRunManifest(base, admission, dependencies, vmcontrolseed.RunHost{HostID: guest.ID, Cell: strings.ToLower(string(guest.Region)), Membership: membership, Predecessor: previous, InitialFiles: initialFiles})
	if err != nil {
		return nil, err
	}
	if len(predecessor) == 0 {
		reader := services.controlAdmission.ordinaryAuthorities[guest.ID]
		for path, raw := range reader.Files {
			if material.Files[path] != nil || bytes.Equal(raw, material.Files[material.Regional.Connection.TLS.KeyFile]) {
				material.Clear()
				return nil, errors.New("vmqual: root authority material entered ordinary runtime inventory")
			}
		}
	}
	if services.runMaterials == nil {
		services.runMaterials = map[string]*vmcontrolseed.RunMaterial{}
	}
	services.runMaterials[guest.ID] = material
	return material, nil
}

// ordinaryAuthority loads only separately declared root-owned reader files.
// It runs with the services lock held; bytes never enter RunMaterial inventory.
func (services *qualificationRuntimeServices) ordinaryAuthority(host string) (*vmcontrolseed.AuthorityMaterial, error) {
	admission := services.controlAdmission
	if admission == nil {
		return nil, errors.New("vmqual: ordinary reader admission missing")
	}
	if material := admission.ordinaryAuthorities[host]; material != nil {
		return material, nil
	}
	declaration, ok := admission.authorityReaders[host]
	if !ok {
		return nil, errors.New("vmqual: ordinary host has no independent authority reader")
	}
	material := &vmcontrolseed.AuthorityMaterial{HostID: host, Reader: declaration.Reader, Files: map[string][]byte{}}
	for path, ref := range declaration.Files {
		raw, err := readQualificationControlFile(ref, true, 64<<10)
		if err != nil {
			material.Clear()
			return nil, err
		}
		material.Files[path] = raw
	}
	if err := material.Validate(); err != nil {
		material.Clear()
		return nil, err
	}
	if admission.ordinaryAuthorities == nil {
		admission.ordinaryAuthorities = map[string]*vmcontrolseed.AuthorityMaterial{}
	}
	admission.ordinaryAuthorities[host] = material
	return material, nil
}
