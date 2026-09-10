//go:build sandboxvm

// Command vm-qualify-material signs explicit local six-guest qualification intent.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"flag"
	"fmt"
	"os"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualruntime"
)

func main() {
	out := flag.String("out", "", "new private output directory")
	intentPath := flag.String("input", "", "protected local network, artifact, control and production run intent JSON")
	tsNode := flag.String("ts-node", "", "exact ts-node executable")
	orchestrator := flag.String("orchestrator", "", "exact orchestrator executable")
	terrabase := flag.String("terrabase", "", "exact TerraBase executable")
	flag.Parse()
	if err := generate(*out, *intentPath, map[string]string{"ts-node": *tsNode, "orchestrator": *orchestrator, "terrabase": *terrabase}); err != nil {
		fmt.Fprintln(os.Stderr, "vm-qualify-material:", err)
		os.Exit(1)
	}
}

func generate(root, intent string, executables map[string]string) error {
	raw, err := bootstrapcredentials.ReadFile(intent, true, 4<<20)
	if err != nil {
		return err
	}
	defer clear(raw)
	var envelope vmqualruntime.LocalQualificationMaterialIntent
	if err := json.Unmarshal(raw, &envelope, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	plan, err := vmnet.Plan(envelope.NetworkConfig)
	if err != nil {
		return err
	}
	payload, err := vmqualruntime.BuildLocalQualificationControlPayload(plan, envelope.RunDeclaration, envelope.Artifacts, envelope.Control)
	if err != nil {
		return err
	}
	input := vmqualruntime.LocalQualificationMaterialInput{Network: plan, NetworkConfig: envelope.NetworkConfig, Architecture: envelope.Architecture, Artifacts: envelope.Artifacts, RunDeclaration: envelope.RunDeclaration, ControlPayload: payload}
	if len(input.Artifacts) != 3 {
		return fmt.Errorf("three exact artifact records required")
	}
	seen := map[string]bool{}
	for _, artifact := range input.Artifacts {
		path, ok := executables[artifact.Component]
		if !ok || seen[artifact.Component] {
			return fmt.Errorf("unexpected or duplicate artifact %q", artifact.Component)
		}
		seen[artifact.Component] = true
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
			return fmt.Errorf("%s artifact must be an executable regular file", artifact.Component)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if artifact.SHA256 != hex.EncodeToString(sum[:]) || artifact.Size != int64(len(data)) || artifact.Architecture != input.Architecture {
			return fmt.Errorf("%s executable differs from exact artifact intent", artifact.Component)
		}
	}
	return vmqualruntime.GenerateLocalQualificationMaterial(root, input)
}
