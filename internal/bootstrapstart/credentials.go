package bootstrapstart

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

var ErrLiveCredentials = errors.New("live controller credentials are invalid")

// LiveCredentials checks the accepted material inventory at the fixed service
// directory. The root first-install process validates through the same binary
// under the dedicated service UID; restarts validate in the service process.
type LiveCredentials struct {
	Config                 natscell.Config
	ServiceUID             uint32
	ServiceGID             uint32
	ResponseKeyFile        string
	BrokerTicketKeyFile    string
	HostNATSIssuerSeedFile string
	HostTLSIssuerKeyFile   string
	HostTLSIssuerCertFile  string
	// TerraBaseCACertFile and TerraBaseCAKeyFile are the optional C# TerraBase
	// member CA; set both or neither.
	TerraBaseCACertFile    string
	TerraBaseCAKeyFile     string
	ValidateControllerKeys func() error
	directory              string
	allowUnsafeAncestors   bool
	runChild               func(context.Context, []byte, uint32, uint32) error
	// ControllerConfig is the loaded controller config's exact bytes, which an
	// adopted v1 generation pins; accepted restart checks them.
	ControllerConfig []byte
}

// CredentialChildRequest is the bounded service-user preflight request passed
// over stdin to the same executable. It carries file paths, never secrets.
type CredentialChildRequest struct {
	Config              natscell.Config `json:"config"`
	UID                 uint32          `json:"uid"`
	GID                 uint32          `json:"gid"`
	ResponseKeyFile     string          `json:"responseKeyFile"`
	BrokerTicketKeyFile string          `json:"brokerTicketKeyFile"`
}
