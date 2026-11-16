package delivery

// ArtifactUse is an artifact a committed desired names. The collector never
// deletes it.
type ArtifactUse struct {
	Digest      string
	Role        string
	Environment string
}

// ArtifactCollection is what one collection pass removed.
type ArtifactCollection struct {
	Deleted []string `json:"deleted,omitempty"`
	Purged  []string `json:"purged,omitempty"`
}
