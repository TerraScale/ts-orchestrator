package vmimage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
)

// TSNodeRecoveryCloudInit renders the verified public launch proof for a shape
// probe. Private credentials remain on the existing guest root disk; a provider
// RUNNING result does not establish replacement-host service admission.
func TSNodeRecoveryCloudInit(seed TSNodeBootstrap, artifacts []GuestArtifact) (string, error) {
	if seed.InitialGrant == nil {
		return "", errors.New("vmimage: recovery grant missing")
	}
	grant, err := hostagent.VerifyBootstrapGrant(seed.Config.NodeID, seed.InitialGrant.PublicKeyPEM, seed.InitialGrant.SignedGrant)
	if err != nil {
		return "", err
	}
	manifest, err := hostmanifest.CanonicalHostManifestJSON(grant.Manifest)
	if err != nil || !bytes.Equal(manifest, seed.DesiredHostManifest) {
		return "", errors.New("vmimage: recovery manifest differs from admitted grant")
	}
	digest := sha256.Sum256(seed.Binary)
	if len(seed.ReleasePublicKey) != ed25519.PublicKeySize || hex.EncodeToString(digest[:]) != seed.SHA256 || !ed25519.Verify(seed.ReleasePublicKey, seed.Binary, seed.Signature) {
		return "", errors.New("vmimage: recovery ts-node artifact is not signed by the admitted release key")
	}
	var artifact GuestArtifact
	for _, candidate := range artifacts {
		if candidate.Component == "ts-node" {
			artifact = candidate
		}
	}
	if artifact.Version != seed.Version || artifact.SHA256 != seed.SHA256 || artifact.Size != int64(len(seed.Binary)) {
		return "", errors.New("vmimage: recovery ts-node release differs from guest artifact")
	}
	publicFiles, err := TSNodePublicLaunchFiles(seed)
	if err != nil {
		return "", err
	}
	files := make([]ocireconcile.BootstrapHostFile, 0, len(publicFiles))
	for path, content := range publicFiles {
		files = append(files, ocireconcile.BootstrapHostFile{Path: path, Content: content, Private: true})
	}

	return ocireconcile.TSNodeCloudInit(seed.Version, seed.SHA256, artifact.Source, artifact.Source+".sig", hex.EncodeToString(seed.ReleasePublicKey), files)
}
