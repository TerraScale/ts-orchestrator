package app

// RootOCIQualificationResult records actual fixed-socket observations. A result
// is emitted only after all six readers and the separate process probes finish.
type RootOCIQualificationResult struct {
	SchemaVersion   uint64                      `json:"schema_version"`
	InstanceID      string                      `json:"instance_id"`
	ImageID         string                      `json:"image_id"`
	BinarySHA256    string                      `json:"binary_sha256"`
	NamespaceSHA256 string                      `json:"namespace_sha256"`
	SourceSHA256    string                      `json:"source_sha256"`
	RootUID         uint32                      `json:"root_uid"`
	PeerUID         uint32                      `json:"peer_uid"`
	Socket          string                      `json:"socket"`
	Readers         RootOCIQualificationReaders `json:"readers"`
	Negative        RootOCIQualificationDenials `json:"negative"`
}

type RootOCIQualificationObservation struct {
	SHA256   string `json:"sha256"`
	Bytes    int64  `json:"bytes"`
	Response []byte `json:"response,omitempty"`
}

type RootOCIQualificationReaders struct {
	Inventory      RootOCIQualificationObservation `json:"inventory"`
	LocalInstance  RootOCIQualificationObservation `json:"local_instance"`
	Fleet          RootOCIQualificationObservation `json:"fleet"`
	Costs          RootOCIQualificationObservation `json:"costs"`
	Image          RootOCIQualificationObservation `json:"image"`
	ReleaseChannel RootOCIQualificationObservation `json:"release_channel"`
}

type RootOCIQualificationDenials struct {
	SameUIDProcessDenied   bool `json:"same_uid_process_denied"`
	ProtectedWriteDenied   bool `json:"protected_write_denied"`
	RawSignDenied          bool `json:"raw_sign_denied"`
	PrincipalSigningDenied bool `json:"principal_signing_denied"`
	IMDSDenied             bool `json:"imds_denied"`
}
