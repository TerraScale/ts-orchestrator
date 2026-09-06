package vmimage

import (
	"strings"

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
	if err := input.Engine.ValidateManifest(input.Config.NodeID, input.Engine.Address(), manifest); err != nil {
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
	return files, nil
}

func engineOwnershipBootstrap(files []NoCloudRootFile) string {
	var script strings.Builder
	for _, file := range files {
		if !vmengineconfig.IsTLSPath(file.Path) {
			continue
		}
		if script.Len() == 0 {
			script.WriteString("if ! /usr/bin/id -u terrascale-terrabase >/dev/null 2>&1; then\n  /usr/sbin/useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin terrascale-terrabase\nfi\n/usr/bin/test \"$(/usr/bin/id -u terrascale-terrabase)\" -ne 0\n")
		}
		script.WriteString("/usr/bin/chown terrascale-terrabase:terrascale-terrabase " + file.Path + "\n/usr/bin/chmod 0400 " + file.Path + "\n/usr/bin/test \"$(/usr/bin/stat -c %U:%G:%a " + file.Path + ")\" = terrascale-terrabase:terrascale-terrabase:400\n")
	}
	return script.String()
}
