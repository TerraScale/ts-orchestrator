// Package hostagent defines the D-69 host agent of ts-node: the per-host
// systemd control of TerraScale. ts-node is the only thing that touches a
// host — it installs signed release binaries into version directories,
// writes hardened systemd SYSTEM units, flips the current symlink, and
// restarts components under an orchestrator-coordinated drain. There is no
// container runtime anywhere.
//
// # Control-plane RPC surface (consumed by the delivery lane, I-3b)
//
// The agent speaks request-reply JSON (camelCase, unknown fields rejected)
// on the embedded control NATS under the subject prefix
// ts.orch.v1.<cell>.agent.<agent-hash>.<family>.<leaf>, authenticated like
// every other control subject (NKey + TLS per the account model). The raw
// node identity is hashed before it enters a subject, so operator-controlled
// identity text cannot become a NATS token. The cell is the first token of a
// node identity (for example, gru in gru-1). The leaves are:
//
//	drain      DrainCommand     -> DrainReceipt       begin or release a drain
//	drain-status NodeStatusRequest -> NodeStatusReport  state, quiesce gate, facts
//	deploy     DeployCommand   -> DeployReceipt       flip + restart, quiesced only
//	rollback   RollbackCommand -> DeployReceipt       symlink back + restart, any state
//	apply-manifest ApplyManifestCommand -> ManifestReceipt durable desired-state CAS
//	heartbeat  (publish-only)  HostHeartbeat          facts every interval
//
// The rollout choreography the delivery lane drives: write the host's
// manifest (its desired components), watch heartbeats until the release is
// Installed, send drain, poll drain-status until Quiesced, send deploy,
// gate on health, then send drain{drain:false} to return the host to
// serving. A failed gate sends rollback.
package hostagent

import (
	"regexp"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
)

// InvalidOperationError reports an operation invalid for the current state.
type InvalidOperationError struct {
	Message string
}

func (e *InvalidOperationError) Error() string { return e.Message }

// InvalidDataError reports malformed observed or received data.
type InvalidDataError struct {
	Message string
}

func (e *InvalidDataError) Error() string { return e.Message }

var hostAgentTokenPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

const (
	hostAgentMaximumTokenLength  = 63
	hostAgentMaximumDetailLength = 512
)

// requireHostAgentToken enforces the bounded canonical token vocabulary
// shared by node identifiers and command identifiers.
func requireHostAgentToken(value, param, message string) (string, error) {
	if len(value) < 1 || len(value) > hostAgentMaximumTokenLength ||
		!hostAgentTokenPattern.MatchString(value) {
		return "", &errs.Argument{Param: param, Message: message}
	}
	return value, nil
}

// requireHostAgentDetail enforces a bounded, control-character-free detail
// string so receipts stay log-safe.
func requireHostAgentDetail(value, param string) (string, error) {
	if len(value) > hostAgentMaximumDetailLength || strings.ContainsFunc(value, isControlRune) {
		return "", &errs.Argument{
			Param:   param,
			Message: "Detail must be bounded and free of control characters.",
		}
	}
	return value, nil
}

func isControlRune(r rune) bool { return r < 0x20 || r == 0x7f }

// boundedReceiptDetail sanitizes one detail string into the bounded,
// control-free shape the receipts require.
func boundedReceiptDetail(detail string) string {
	var builder strings.Builder
	for _, symbol := range detail {
		if symbol == '\n' || symbol == '\r' || symbol == '\t' {
			symbol = ' '
		}
		if isControlRune(symbol) {
			continue
		}
		builder.WriteRune(symbol)
		if builder.Len() >= hostAgentMaximumDetailLength {
			break
		}
	}
	return builder.String()
}

// NodeId is a bounded canonical node token.
type NodeId struct {
	Value string
}

// NewNodeId validates the DNS-style node token.
func NewNodeId(value string) (NodeId, error) {
	if _, err := requireHostAgentToken(value, "value",
		"Node ID must be a lowercase DNS-style token."); err != nil {
		return NodeId{}, err
	}
	return NodeId{Value: value}, nil
}

func (id NodeId) String() string { return id.Value }

// NATS subject constants of the node transport. The drain, drain-status,
// deploy, and rollback leaves are request-reply; the heartbeat leaf is
// publish-only.
const (
	// NatsSubjectNodePrefix is the versioned prefix of every host-agent leaf.
	NatsSubjectNodePrefix = "ts.orch.v1"
	// NatsSubjectLeafDrain begins or releases a drain (request-reply).
	NatsSubjectLeafDrain = "drain"
	// NatsSubjectLeafDrainStatus reports state and the quiesce gate
	// (request-reply).
	NatsSubjectLeafDrainStatus = "drain-status"
	// NatsSubjectLeafDeploy performs the quiesced version switch
	// (request-reply).
	NatsSubjectLeafDeploy = "deploy"
	// NatsSubjectLeafRollback performs the emergency version switch
	// (request-reply).
	NatsSubjectLeafRollback = "rollback"
	// NatsSubjectLeafApplyManifest durably publishes desired host state.
	NatsSubjectLeafApplyManifest = "apply-manifest"
	// NatsSubjectLeafHeartbeat publishes periodic host facts.
	NatsSubjectLeafHeartbeat = "heartbeat"
)

// nodeCell derives the control-plane cell from the canonical node identity.
// Node identities are provisioned as <cell>-<slot>; an identity without a
// separator is accepted for local/test use and names its own cell.
func nodeCell(nodeId NodeId) (string, string, error) {
	validated, err := NewNodeId(nodeId.Value)
	if err != nil {
		return "", "", err
	}
	cell := validated.Value
	if separator := strings.IndexByte(cell, '-'); separator > 0 {
		cell = cell[:separator]
	}
	return cell, validated.Value, nil
}

// nodeCommandSubject builds one v1 command subject addressed to exactly one
// hashed host-agent identity.
func nodeCommandSubject(nodeId NodeId, leaf string) (string, error) {
	cell, identity, err := nodeCell(nodeId)
	if err != nil {
		return "", err
	}
	return natspolicy.NatsSubjectTaxonomy.HostAgentCommandSubject(cell, identity, leaf)
}

// nodeObservationSubject builds one v1 observation subject published by one
// hashed host-agent identity.
func nodeObservationSubject(nodeId NodeId, leaf string) (string, error) {
	cell, identity, err := nodeCell(nodeId)
	if err != nil {
		return "", err
	}
	return natspolicy.NatsSubjectTaxonomy.HostAgentObservationSubject(cell, identity, leaf)
}

// NodeDrainSubject builds the request-reply drain subject of a node.
func NodeDrainSubject(nodeId NodeId) (string, error) {
	return nodeCommandSubject(nodeId, NatsSubjectLeafDrain)
}

// NodeDrainStatusSubject builds the request-reply drain-status subject.
func NodeDrainStatusSubject(nodeId NodeId) (string, error) {
	return nodeCommandSubject(nodeId, NatsSubjectLeafDrainStatus)
}

// NodeDeploySubject builds the request-reply deploy subject.
func NodeDeploySubject(nodeId NodeId) (string, error) {
	return nodeCommandSubject(nodeId, NatsSubjectLeafDeploy)
}

// NodeRollbackSubject builds the request-reply rollback subject.
func NodeRollbackSubject(nodeId NodeId) (string, error) {
	return nodeCommandSubject(nodeId, NatsSubjectLeafRollback)
}

// NodeApplyManifestSubject builds the durable desired-manifest subject.
func NodeApplyManifestSubject(nodeId NodeId) (string, error) {
	return nodeCommandSubject(nodeId, NatsSubjectLeafApplyManifest)
}

// NodeHeartbeatSubject builds the publish-only heartbeat subject.
func NodeHeartbeatSubject(nodeId NodeId) (string, error) {
	return nodeObservationSubject(nodeId, NatsSubjectLeafHeartbeat)
}

// DrainCommand is the payload of the drain subject: drain=true stops the
// component units gracefully (the node answers drain-status while it
// drains), drain=false returns the node to serving.
type DrainCommand struct {
	CommandId string `json:"commandId"`
	Drain     bool   `json:"drain"`
}

// NewDrainCommand validates one drain command.
func NewDrainCommand(commandId string, drain bool) (DrainCommand, error) {
	validated, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return DrainCommand{}, err
	}
	return DrainCommand{CommandId: validated, Drain: drain}, nil
}

// DrainReceipt is the reply to one drain command.
type DrainReceipt struct {
	CommandId string `json:"commandId"`
	NodeId    string `json:"nodeId"`
	Draining  bool   `json:"draining"`
	Quiesced  bool   `json:"quiesced"`
	Detail    string `json:"detail"`
}

// NewDrainReceipt validates one drain receipt.
func NewDrainReceipt(commandId, nodeId string, draining, quiesced bool, detail string) (DrainReceipt, error) {
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return DrainReceipt{}, err
	}
	validatedNode, err := NewNodeId(nodeId)
	if err != nil {
		return DrainReceipt{}, err
	}
	validatedDetail, err := requireHostAgentDetail(detail, "detail")
	if err != nil {
		return DrainReceipt{}, err
	}
	return DrainReceipt{
		CommandId: validatedCommand,
		NodeId:    validatedNode.Value,
		Draining:  draining,
		Quiesced:  quiesced,
		Detail:    validatedDetail,
	}, nil
}

// NodeStatusRequest is the payload of the drain-status subject.
type NodeStatusRequest struct {
	CommandId string `json:"commandId"`
}

// NewNodeStatusRequest validates one status request.
func NewNodeStatusRequest(commandId string) (NodeStatusRequest, error) {
	validated, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return NodeStatusRequest{}, err
	}
	return NodeStatusRequest{CommandId: validated}, nil
}

// NodeStatusReport is the reply to one drain-status request: the lifecycle
// state, the quiesce gate, and the full host facts of one sample.
type NodeStatusReport struct {
	CommandId string    `json:"commandId"`
	NodeId    string    `json:"nodeId"`
	State     string    `json:"state"`
	Quiesced  bool      `json:"quiesced"`
	Facts     HostFacts `json:"facts"`
}

// NewNodeStatusReport validates one status report.
func NewNodeStatusReport(commandId, nodeId, state string, quiesced bool, facts HostFacts) (NodeStatusReport, error) {
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return NodeStatusReport{}, err
	}
	validatedNode, err := NewNodeId(nodeId)
	if err != nil {
		return NodeStatusReport{}, err
	}
	switch state {
	case NodeStateServing, NodeStateDraining, NodeStateQuiesced:
	default:
		return NodeStatusReport{}, &InvalidDataError{Message: "The state must be a known lifecycle state."}
	}
	return NodeStatusReport{
		CommandId: validatedCommand,
		NodeId:    validatedNode.Value,
		State:     state,
		Quiesced:  quiesced,
		Facts:     facts,
	}, nil
}

// DeployCommand is the payload of the deploy subject: flip one component's
// current symlink to an installed version and restart it. The node must be
// quiesced; the receipt refuses otherwise.
type DeployCommand struct {
	CommandId string `json:"commandId"`
	Component string `json:"component"`
	Version   string `json:"version"`
}

// NewDeployCommand validates one deploy command.
func NewDeployCommand(commandId, component, version string) (DeployCommand, error) {
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return DeployCommand{}, err
	}
	validatedComponent, err := requireHostAgentName(component, "component",
		"Component must be a lowercase token with dot or dash separators.")
	if err != nil {
		return DeployCommand{}, err
	}
	validatedVersion, err := requireHostAgentName(version, "version",
		"Version must be a lowercase token with dot or dash separators.")
	if err != nil {
		return DeployCommand{}, err
	}
	return DeployCommand{
		CommandId: validatedCommand,
		Component: validatedComponent,
		Version:   validatedVersion,
	}, nil
}

// RollbackCommand is the payload of the rollback subject: flip one
// component back to its previous version and restart it, from any state.
type RollbackCommand struct {
	CommandId string `json:"commandId"`
	Component string `json:"component"`
}

// ApplyManifestCommand publishes the complete canonical desired manifest if
// the currently durable manifest has the expected digest.
type ApplyManifestCommand struct {
	CommandId              string       `json:"commandId"`
	ExpectedManifestSha256 string       `json:"expectedManifestSha256"`
	Manifest               HostManifest `json:"manifest"`
}

// NewApplyManifestCommand validates one durable manifest compare-and-swap.
func NewApplyManifestCommand(commandId, expectedManifestSha256 string, manifest HostManifest) (ApplyManifestCommand, error) {
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return ApplyManifestCommand{}, err
	}
	if !hostAgentSha256Pattern.MatchString(expectedManifestSha256) {
		return ApplyManifestCommand{}, &errs.Argument{Param: "expectedManifestSha256", Message: "Expected manifest sha256 must be canonical lowercase hex."}
	}
	components, err := validateComponentSet(manifest.Components)
	if err != nil {
		return ApplyManifestCommand{}, err
	}
	return ApplyManifestCommand{
		CommandId:              validatedCommand,
		ExpectedManifestSha256: expectedManifestSha256,
		Manifest:               HostManifest{Components: components},
	}, nil
}

// NewRollbackCommand validates one rollback command.
func NewRollbackCommand(commandId, component string) (RollbackCommand, error) {
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return RollbackCommand{}, err
	}
	validatedComponent, err := requireHostAgentName(component, "component",
		"Component must be a lowercase token with dot or dash separators.")
	if err != nil {
		return RollbackCommand{}, err
	}
	return RollbackCommand{CommandId: validatedCommand, Component: validatedComponent}, nil
}

// DeployReceipt is the reply to one deploy or rollback command: whether the
// host accepted it and the component's current version after the attempt.
type DeployReceipt struct {
	CommandId string `json:"commandId"`
	NodeId    string `json:"nodeId"`
	Accepted  bool   `json:"accepted"`
	Current   string `json:"current"`
	Detail    string `json:"detail"`
}

// ManifestReceipt reports the durable manifest digest after one CAS.
type ManifestReceipt struct {
	CommandId      string `json:"commandId"`
	NodeId         string `json:"nodeId"`
	Accepted       bool   `json:"accepted"`
	ManifestSha256 string `json:"manifestSha256"`
	Detail         string `json:"detail"`
}

// NewManifestReceipt validates one apply-manifest receipt.
func NewManifestReceipt(commandId, nodeId string, accepted bool, manifestSha256, detail string) (ManifestReceipt, error) {
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return ManifestReceipt{}, err
	}
	validatedNode, err := NewNodeId(nodeId)
	if err != nil {
		return ManifestReceipt{}, err
	}
	if !hostAgentSha256Pattern.MatchString(manifestSha256) {
		return ManifestReceipt{}, &errs.Argument{Param: "manifestSha256", Message: "Manifest sha256 must be canonical lowercase hex."}
	}
	validatedDetail, err := requireHostAgentDetail(detail, "detail")
	if err != nil {
		return ManifestReceipt{}, err
	}
	return ManifestReceipt{CommandId: validatedCommand, NodeId: validatedNode.Value,
		Accepted: accepted, ManifestSha256: manifestSha256, Detail: validatedDetail}, nil
}

// NewDeployReceipt validates one deploy receipt.
func NewDeployReceipt(commandId, nodeId string, accepted bool, current, detail string) (DeployReceipt, error) {
	validatedCommand, err := requireHostAgentToken(commandId, "commandId",
		"Command ID must be a lowercase DNS-style token.")
	if err != nil {
		return DeployReceipt{}, err
	}
	validatedNode, err := NewNodeId(nodeId)
	if err != nil {
		return DeployReceipt{}, err
	}
	if current != "" {
		if _, err := requireHostAgentName(current, "current",
			"Current version must be a lowercase token with dot or dash separators."); err != nil {
			return DeployReceipt{}, err
		}
	}
	validatedDetail, err := requireHostAgentDetail(detail, "detail")
	if err != nil {
		return DeployReceipt{}, err
	}
	return DeployReceipt{
		CommandId: validatedCommand,
		NodeId:    validatedNode.Value,
		Accepted:  accepted,
		Current:   current,
		Detail:    validatedDetail,
	}, nil
}

// HostHeartbeat is one published heartbeat of a node agent.
type HostHeartbeat struct {
	NodeId      string    `json:"nodeId"`
	UnixSeconds int64     `json:"unixSeconds"`
	Facts       HostFacts `json:"facts"`
}

// NewHostHeartbeat validates one heartbeat at the trust boundary.
func NewHostHeartbeat(nodeId string, unixSeconds int64, facts HostFacts) (HostHeartbeat, error) {
	validatedNode, err := NewNodeId(nodeId)
	if err != nil {
		return HostHeartbeat{}, err
	}
	if unixSeconds <= 0 {
		return HostHeartbeat{}, &errs.ArgumentOutOfRangeError{
			Param:   "unixSeconds",
			Message: "Heartbeat timestamp must be a positive Unix epoch second.",
		}
	}
	return HostHeartbeat{NodeId: validatedNode.Value, UnixSeconds: unixSeconds, Facts: facts}, nil
}

// CommandEnvelopeError is the reply the transport sends when a command
// envelope itself cannot be validated, because no typed receipt carrying a
// bounded command identifier can be built for it.
type CommandEnvelopeError struct {
	Detail string `json:"detail"`
}

// NewCommandEnvelopeError builds one bounded, log-safe envelope error.
func NewCommandEnvelopeError(detail string) CommandEnvelopeError {
	return CommandEnvelopeError{Detail: boundedReceiptDetail(detail)}
}

// detailOf flattens one error (or the success wording) into a bounded,
// control-free receipt detail.
func detailOf(cause error, success string) string {
	if cause == nil {
		return boundedReceiptDetail(success)
	}
	return boundedReceiptDetail(cause.Error())
}
