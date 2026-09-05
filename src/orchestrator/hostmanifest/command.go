package hostmanifest

import (
	"bytes"
	"encoding/json"
	"io"
	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// ApplyManifestCommand publishes the complete canonical desired manifest if
// the currently durable manifest has the expected digest.
type ApplyManifestCommand struct {
	CommandId              string       `json:"commandId"`
	ExpectedManifestSha256 string       `json:"expectedManifestSha256"`
	Manifest               HostManifest `json:"manifest"`
}

// NewApplyManifestCommand validates one durable manifest compare-and-swap.
func NewApplyManifestCommand(commandId, expectedManifestSha256 string, manifest HostManifest) (ApplyManifestCommand, error) {
	validatedCommand, err := RequireToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return ApplyManifestCommand{}, err
	}
	if !ValidDigest(expectedManifestSha256) {
		return ApplyManifestCommand{}, &errs.Argument{Param: "expectedManifestSha256", Message: "Expected manifest sha256 must be canonical lowercase hex."}
	}
	components, err := ValidateComponentSet(manifest.Components)
	if err != nil {
		return ApplyManifestCommand{}, err
	}
	return ApplyManifestCommand{
		CommandId:              validatedCommand,
		ExpectedManifestSha256: expectedManifestSha256,
		Manifest:               HostManifest{Components: components},
	}, nil
}

// ParseApplyManifestCommand validates the exact host manifest handoff wire contract.
func ParseApplyManifestCommand(data []byte) (ApplyManifestCommand, error) {
	if len(data) == 0 || len(data) > MaximumManifestBytes+4096 {
		return ApplyManifestCommand{}, &InvalidDataError{Message: "The command payload exceeds its size bound."}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := validateHostManifestObject(decoder, "apply-manifest", map[string]hostManifestJSONField{"commandId": {}, "expectedManifestSha256": {}, "manifest": {}}, []string{"commandId", "expectedManifestSha256", "manifest"}); err != nil {
		return ApplyManifestCommand{}, &InvalidDataError{Message: err.Error()}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ApplyManifestCommand{}, &InvalidDataError{Message: "The command payload must be exactly one JSON document."}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return ApplyManifestCommand{}, &InvalidDataError{Message: "The command payload is not a JSON object."}
	}
	var commandId, expected string
	if json.Unmarshal(fields["commandId"], &commandId) != nil ||
		json.Unmarshal(fields["expectedManifestSha256"], &expected) != nil {
		return ApplyManifestCommand{}, &InvalidDataError{Message: "The apply-manifest command has invalid field types."}
	}
	manifest, err := ParseHostManifest(fields["manifest"])
	if err != nil {
		return ApplyManifestCommand{}, err
	}
	canonical, err := CanonicalHostManifestJSON(manifest)
	if err != nil || !bytes.Equal(canonical, fields["manifest"]) {
		return ApplyManifestCommand{}, &InvalidDataError{Message: "The embedded manifest must use canonical compact JSON."}
	}
	return NewApplyManifestCommand(commandId, expected, manifest)
}
