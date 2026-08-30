package control

// OrchestratorOptions contains the regional NATS settings needed by the Go
// journal provisioner. More command-specific option groups should be added as
// their owning runtime components move to Go instead of flattening unrelated
// credentials into this type.
type OrchestratorOptions struct {
	Cell                       string
	NatsURL                    string
	Replicas                   int
	Instance                   string
	InfrastructureNatsNKeyFile *string
	InfrastructureNatsTls      *NatsTlsFiles
}
