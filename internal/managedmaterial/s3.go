package managedmaterial

import (
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

// NativeOCIRoot selects native OCI Object Storage CAS for authoritative roots.
// S3 still stores immutable data in the same signed bucket and region.
type NativeOCIRoot struct {
	Namespace string `json:"namespace"`
}

// LiveS3Target binds the nonsecret ObjectDurable root location and the exact
// Vault version that can authenticate to it. Credentials are never encoded in
// the TerraBase config, preparation receipt, placement, or NATS desired state.
type LiveS3Target struct {
	Bucket        string                     `json:"bucket"`
	Region        string                     `json:"region"`
	Endpoint      string                     `json:"endpoint,omitempty"`
	Credential    oci.SecretVersionReference `json:"credential"`
	NativeOCIRoot *NativeOCIRoot             `json:"native_oci_root,omitempty"`
}
