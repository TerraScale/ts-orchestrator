package vmimage

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/serviceidentity"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/vmengineconfig"
)

func canonicalEngineBootstrap(input TSNodeBootstrap) ([]NoCloudRootFile, error) {
	if input.Engine == nil {
		return nil, nil
	}
	manifest, err := hostmanifest.ParseHostManifest(input.DesiredHostManifest)
	if err != nil {
		return nil, err
	}
	validate := func() error {
		if input.ControllerRun != nil {
			if input.Controller != nil {
				if err := input.ControllerRun.ValidateStage(*input.Controller, manifest); err != nil {
					return err
				}
				return input.Engine.ValidateStagedManifest(input.Config.NodeID, input.Engine.Address(), manifest, input.ControllerRun.Manifest)
			}
			if input.Candidate != nil {
				if err := input.ControllerRun.ValidatePredecessor(input.Config.NodeID, manifest); err != nil {
					return err
				}
				return input.Engine.ValidateStagedManifest(input.Config.NodeID, input.Engine.Address(), manifest, input.ControllerRun.Manifest)
			}
			if input.InitialGrant == nil {
				return errors.New("vmimage: ordinary run requires finite owner grant")
			}
			if err := input.ControllerRun.ValidateManifest(input.Config.NodeID, manifest); err != nil {
				return err
			}
		}
		return input.Engine.ValidateManifest(input.Config.NodeID, input.Engine.Address(), manifest)
	}
	if err := validate(); err != nil {
		return nil, err
	}
	material := input.Engine.Files()
	var files []NoCloudRootFile
	for _, path := range []string{vmengineconfig.CertificatePath, vmengineconfig.PrivateKeyPath, vmengineconfig.CAPath} {
		file := NoCloudRootFile{Path: path, Owner: vmengineconfig.ServiceUser, Mode: 0400, Content: material[path]}
		if err := file.Validate(); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	observer := input.Engine.ObserverFiles()
	for _, path := range []string{vmengineconfig.ObserverCertificatePath, vmengineconfig.ObserverPrivateKeyPath, vmengineconfig.ObserverCAPath} {
		file := NoCloudRootFile{Path: path, Mode: 0600, Content: observer[path]}
		if err := file.Validate(); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	trust := input.Engine.TransitionFiles()
	for _, path := range input.Engine.TransitionPaths() {
		file := NoCloudRootFile{Path: path, Owner: vmengineconfig.ServiceUser, Mode: 0400, Content: trust[path]}
		if err := file.Validate(); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	for path, content := range input.Engine.BackupFiles() {
		file := NoCloudRootFile{Path: path, Owner: vmengineconfig.ServiceUser, Mode: 0400, Content: content}
		if err := file.Validate(); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	for path, content := range input.Engine.IdentityFiles() {
		file := NoCloudRootFile{Path: path, Owner: vmengineconfig.ServiceUser, Mode: 0400, Content: content}
		if err := file.Validate(); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	control := input.Engine.ControlFiles()
	maps.Copy(control, input.Engine.DatabaseFiles())
	for _, path := range slices.Sorted(maps.Keys(control)) {
		file := NoCloudRootFile{Path: path, Owner: membershipServiceUser, Mode: 0400, Content: control[path]}
		if err := file.Validate(); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func engineOwnershipBootstrap(files []NoCloudRootFile) string {
	var script strings.Builder
	for _, file := range files {
		if !vmengineconfig.IsTLSPath(file.Path) && !vmengineconfig.IsTransitionTrustPath(file.Path) && !vmengineconfig.IsBackupPath(file.Path) && !vmengineconfig.IsIdentityPath(file.Path) {
			continue
		}
		if script.Len() == 0 {
			script.WriteString(serviceidentity.Bootstrap(serviceidentity.TerraBase))
		}
		script.WriteString("/usr/bin/chown terrascale-terrabase:terrascale-terrabase " + file.Path + "\n/usr/bin/chmod 0400 " + file.Path + "\n/usr/bin/test \"$(/usr/bin/stat -c %U:%G:%a " + file.Path + ")\" = terrascale-terrabase:terrascale-terrabase:400\n")
	}
	return script.String()
}
