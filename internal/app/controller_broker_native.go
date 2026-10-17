package app

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// Native observations describe root's broker; they never grant root authority.
type controllerBrokerNative interface {
	ObserveCluster() (natscell.ClusterObservation, error)
	Meta() (natscell.MetaView, error)
	Observe(context.Context) (observability.NATSView, error)
	LocalStoreUsedBytes(context.Context) (uint64, error)
	StreamHealth(context.Context) ([]natscell.StreamState, error)
	ReadControllerAccount(context.Context) (natscell.ControllerAccountView, error)
	CredentialExpiries(context.Context) ([]observability.CredentialView, error)
	ProbeNetBirdController(context.Context, rootBrokerNetBirdProbeRequest) error
	WaitForCluster(context.Context, int) error
	FullClusterReady(int) bool
	Ready() bool
}

var controllerBrokerNativeProduction = openControllerBrokerNative

type rootBrokerOperation string

const (
	rootBrokerCluster      rootBrokerOperation = "cluster"
	rootBrokerMeta         rootBrokerOperation = "meta"
	rootBrokerMetrics      rootBrokerOperation = "metrics"
	rootBrokerStore        rootBrokerOperation = "store"
	rootBrokerStreams      rootBrokerOperation = "streams"
	rootBrokerAccount      rootBrokerOperation = "account"
	rootBrokerCredentials  rootBrokerOperation = "credentials"
	rootBrokerNetBirdProbe rootBrokerOperation = "netbird_probe"
)

type rootBrokerRequest struct {
	Operation    rootBrokerOperation            `json:"operation"`
	NetBirdProbe *rootBrokerNetBirdProbeRequest `json:"netbird_probe,omitzero"`
}

type rootBrokerNetBirdProbeRequest struct {
	Node   string `json:"node"`
	MeshIP string `json:"mesh_ip"`
	DNS    string `json:"dns"`
}

type rootBrokerNetBirdProbeResponse struct {
	Target     rootBrokerNetBirdProbeRequest `json:"target"`
	ServerName string                        `json:"server_name"`
	ExpiresAt  time.Time                     `json:"expires_at"`
}

type rootBrokerClusterView struct {
	Observation natscell.ClusterObservation `json:"observation"`
	QuorumReady bool                        `json:"quorum_ready"`
	FullReady   bool                        `json:"full_ready"`
}

type rootBrokerResponse struct {
	Cluster      *rootBrokerClusterView          `json:"cluster,omitzero"`
	Meta         *natscell.MetaView              `json:"meta,omitzero"`
	Metrics      *observability.NATSView         `json:"metrics,omitzero"`
	Store        *uint64                         `json:"store,omitzero"`
	Streams      *[]natscell.StreamState         `json:"streams,omitzero"`
	Account      *natscell.ControllerAccountView `json:"account,omitzero"`
	Credentials  *[]observability.CredentialView `json:"credentials,omitzero"`
	NetBirdProbe *rootBrokerNetBirdProbeResponse `json:"netbird_probe,omitzero"`
	Error        string                          `json:"error,omitempty"`
}
