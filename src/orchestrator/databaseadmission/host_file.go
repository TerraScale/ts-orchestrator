package databaseadmission

import "terrascale.tech/orchestrator/src/orchestrator/placementpublisher"

const HostFileEnvironment = "TS_ORCH_DATABASE_HOST_FILE"
const HostFilePath = "/etc/terrascale/database/host.json"

// HostFileConfig is the native database host material contract shared by issuer and consumer.
type HostFileConfig struct {
	Version           int                         `json:"version"`
	Cell              string                      `json:"cell"`
	Instance          string                      `json:"instance"`
	Environment       string                      `json:"environment"`
	MemberID          string                      `json:"memberId"`
	ServerIdentity    string                      `json:"serverIdentity"`
	CatalogPath       string                      `json:"catalogPath"`
	EngineSocket      string                      `json:"engineSocket"`
	EngineUID         uint32                      `json:"engineUid"`
	IngressSocket     string                      `json:"ingressSocket"`
	IngressUID        uint32                      `json:"ingressUid"`
	NATSURL           string                      `json:"natsUrl"`
	LifecycleNKeyFile string                      `json:"lifecycleNkeyFile"`
	NKeyFile          string                      `json:"nkeyFile"`
	TLS               placementpublisher.TLSFiles `json:"tls"`
}
