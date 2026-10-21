package region

// ContainerReleaseAuthorityIntent binds existing public release documents to
// an explicitly approved repository in the same root-signed foundation grant.
// It contains no signing key; migration bytes preserve their original floor.
type ContainerReleaseAuthorityIntent struct {
	Role                  string   `json:"role"`
	Environment           string   `json:"environment"`
	ImageRepository       string   `json:"imageRepository"`
	SourceRepository      string   `json:"sourceRepository"`
	Cells                 []string `json:"cells"`
	Architectures         []string `json:"architectures"`
	DelegationWire        []byte   `json:"delegationWire"`
	SequenceMigrationWire []byte   `json:"sequenceMigrationWire"`
}
