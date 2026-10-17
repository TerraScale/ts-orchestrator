package native

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"os/user"
	"strconv"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

const maxRootCredentialProofBytes = 256 << 10
const maxRootCredentialResultBytes = 64 << 10
const rootCredentialSocket = "/run/terrascale-orchestrator/oci.sock"

type rootCredentialOutput struct{ bytes.Buffer }

func (b *rootCredentialOutput) Write(wire []byte) (int, error) {
	if b.Len()+len(wire) > maxRootCredentialResultBytes {
		return 0, errors.New("installed root credential result exceeds its bound")
	}
	return b.Buffer.Write(wire)
}

func (w *worker) rootCredentialBoundary(ctx context.Context, proof []byte) (response, error) {
	if !w.credentialOnly || len(proof) == 0 || len(proof) > maxRootCredentialProofBytes {
		return response{}, errors.New("root credential operation requires its exact finite signed host admission")
	}
	before, err := fileDigest(candidateBinary)
	if err != nil || before != w.binaryHash {
		return response{}, errors.New("installed root credential candidate differs from approved image")
	}
	account, err := user.Lookup("terrascale-orchestrator")
	if err != nil {
		return response{}, errors.New("installed ordinary controller account missing")
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 || uid == 2000 {
		return response{}, errors.New("installed ordinary controller UID invalid")
	}
	process := exec.CommandContext(ctx, candidateBinary, "root-oci-qualification")
	process.Stdin = bytes.NewReader(proof)
	output := new(rootCredentialOutput)
	process.Stdout, process.Stderr = output, io.Discard
	if err := process.Run(); err != nil {
		return response{}, fmt.Errorf("installed root credential qualification failed: %w", err)
	}
	after, err := fileDigest(candidateBinary)
	if err != nil || after != before {
		return response{}, errors.New("installed candidate changed during root credential qualification")
	}
	var result app.RootOCIQualificationResult
	if err := json.Unmarshal(output.Bytes(), &result, json.RejectUnknownMembers(true)); err != nil {
		return response{}, errors.New("installed candidate returned invalid root credential result")
	}
	if err := verifyRootCredentialResult(result, w, uint32(uid)); err != nil {
		return response{}, err
	}
	transcript := bytes.Clone(output.Bytes())
	host := release.RootCredentialBoundaryHost{Role: w.role, InstanceID: result.InstanceID, ImageOCID: result.ImageID, SourceRevision: w.sourceRevision, NamespaceSHA256: result.NamespaceSHA256, RootUID: result.RootUID, OrdinaryUID: result.PeerUID, RootOCIRead: "authenticated", OrdinaryUIDIMDS: "refused", OrdinaryUIDSigning: "refused", UnauthorizedIPC: "refused", Transcript: transcript, TranscriptSHA256: digest(transcript)}
	return response{RootCredentialBoundary: &host}, nil
}

func verifyRootCredentialResult(result app.RootOCIQualificationResult, w *worker, ordinaryUID uint32) error {
	if ordinaryUID == 0 || ordinaryUID == 2000 || result.SchemaVersion != 1 || result.InstanceID != w.identity.InstanceID || result.ImageID != w.identity.ImageOCID || result.BinarySHA256 != w.binaryHash || !shaPattern.MatchString(result.NamespaceSHA256) || !shaPattern.MatchString(result.SourceSHA256) || result.RootUID != 0 || result.PeerUID != ordinaryUID || result.Socket != rootCredentialSocket {
		return errors.New("installed root credential result identity or supervised peer mismatch")
	}
	for _, reader := range []app.RootOCIQualificationObservation{result.Readers.Inventory, result.Readers.LocalInstance, result.Readers.Fleet, result.Readers.Costs, result.Readers.Image, result.Readers.ReleaseChannel} {
		if !shaPattern.MatchString(reader.SHA256) || reader.Bytes <= 0 || reader.Bytes > 8<<20 {
			return errors.New("installed root credential result omitted an actual authenticated reader response")
		}
	}
	negative := result.Negative
	if !negative.SameUIDProcessDenied || !negative.ProtectedWriteDenied || !negative.RawSignDenied || !negative.IMDSDenied {
		return errors.New("installed root credential result omitted an actual ordinary-user refusal")
	}
	return nil
}
