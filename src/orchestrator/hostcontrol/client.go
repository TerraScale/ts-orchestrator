// Package hostcontrol calls admitted ts-node processes through authenticated
// NATS request/reply. The broker's account and subject permissions authenticate
// the host responder; the current ts-node wire contract carries no epoch fence.
package hostcontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nats-io/nats.go"
	"io"
	"reflect"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type Host struct {
	NodeID       hostagent.NodeId
	Region       string
	Architecture runtimeplan.HostArchitecture
}

type Config struct {
	SigningKey       *security.CommandSignatureSigner
	CommandAuthority func(context.Context, Host) (delivery.RegionalCommandAuthority, error)
	Region           string
	Connection       *nats.Conn
	// ResolveHost must read admitted membership, never discover a host from a reply.
	ResolveHost func(context.Context, string) (Host, error)
	// Authorize rechecks live control authority immediately before publication.
	// This does not provide receiver-side rejection of delayed stale commands.
	Authorize func(context.Context, Host) error
	Timeout   time.Duration
}

type Client struct{ config Config }

func New(config Config) (*Client, error) {
	if config.SigningKey == nil || config.Region == "" || config.Region != strings.ToUpper(config.Region) || config.Connection == nil || config.ResolveHost == nil || config.Authorize == nil || config.Timeout <= 0 || config.Timeout > 5*time.Minute {
		return nil, errors.New("hostcontrol: authenticated connection, admission, authority and bounded timeout are required")
	}
	c := &Client{config: config}
	if err := c.checkConnection(); err != nil {
		return nil, err
	}
	return c, nil
}
func (c *Client) checkConnection() error {
	connection := c.config.Connection
	if connection.Opts.AllowReconnect && connection.Opts.ReconnectBufSize >= 0 {
		return errors.New("hostcontrol: disable NATS reconnect publication buffering")
	}
	if !connection.IsConnected() || !connection.AuthRequired() || connection.Opts.SignatureCB == nil || (connection.Opts.Nkey == "" && connection.Opts.UserJWT == nil) {
		return errors.New("hostcontrol: connected NKey-authenticated NATS is required")
	}
	state, err := connection.TLSConnectionState()
	if err != nil || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 {
		return errors.New("hostcontrol: verified NATS TLS is required")
	}
	config := connection.Opts.TLSConfig
	if config == nil || config.InsecureSkipVerify || (len(config.Certificates) == 0 && config.GetClientCertificate == nil && connection.Opts.TLSCertCB == nil) {
		return errors.New("hostcontrol: NATS client TLS identity is required")
	}
	return nil
}
func (c *Client) AdmittedHost(ctx context.Context, host string) (Host, error) {
	if ctx == nil {
		return Host{}, errors.New("hostcontrol: context is required")
	}
	admitted, err := c.config.ResolveHost(ctx, host)
	if err != nil {
		return Host{}, fmt.Errorf("hostcontrol: host admission: %w", err)
	}
	node, err := hostagent.NewNodeId(admitted.NodeID.Value)
	if err != nil || node.Value != host || admitted.Region != c.config.Region || strings.SplitN(node.Value, "-", 2)[0] != strings.ToLower(admitted.Region) || (admitted.Architecture != runtimeplan.HostArchitectureArm64 && admitted.Architecture != runtimeplan.HostArchitectureX64) {
		return Host{}, errors.New("hostcontrol: admitted host, region or architecture mismatch")
	}
	return admitted, nil
}
func (c *Client) request(ctx context.Context, host string, mutating bool, subject func(hostagent.NodeId) (string, error), command any, response any, required ...string) error {
	if ctx == nil {
		return errors.New("hostcontrol: context is required")
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	admitted, err := c.AdmittedHost(ctx, host)
	if err != nil {
		return err
	}
	topic, err := subject(admitted.NodeID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(command)
	if err != nil {
		return err
	}
	if len(data) > ((1 << 20) + 4096) {
		return errors.New("hostcontrol: command exceeds bound")
	}
	if err := c.checkConnection(); err != nil {
		return err
	}
	if mutating {
		if err := c.config.Authorize(ctx, admitted); err != nil {
			return fmt.Errorf("hostcontrol: live authority refused mutation: %w", err)
		}
	}
	if mutating {
		data, err = c.signCommand(ctx, admitted, topic, data)
		if err != nil {
			return err
		}
		if err := c.config.Authorize(ctx, admitted); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// No internal mutation retries: a timeout has an indeterminate remote outcome.
	// A caller may recover using the same durable command ID and exact payload.
	reply, err := c.config.Connection.RequestWithContext(ctx, topic, data)
	if err != nil {
		return fmt.Errorf("hostcontrol: request/reply: %w", err)
	}
	if reply == nil || len(reply.Data) == 0 || len(reply.Data) > (1<<20) {
		return errors.New("hostcontrol: missing or oversized reply")
	}
	if err := strictReply(reply.Data, response, required...); err != nil {
		return fmt.Errorf("hostcontrol: invalid reply: %w", err)
	}
	return nil
}

// strictReply rejects duplicate and null fields at every depth, then applies
// the exact typed decoder and required top-level wire fields.
func strictReply(data []byte, out any, required ...string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 32 {
			return errors.New("reply nesting exceeds bound")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if token == nil {
			return errors.New("null reply field")
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate or invalid reply field")
				}
				seen[name] = true
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			token, err = decoder.Token()
			if err != nil || token != json.Delim('}') {
				return errors.New("incomplete reply object")
			}
		case json.Delim('['):
			for decoder.More() {
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			token, err = decoder.Token()
			if err != nil || token != json.Delim(']') {
				return errors.New("incomplete reply array")
			}
		}
		return nil
	}
	if err := scan(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing reply")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if len(fields) != len(required) {
		return errors.New("unexpected reply fields")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return errors.New("missing reply field")
		}
	}
	if err := requireTypedFields(data, reflect.TypeOf(out)); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}
func matchReceipt(actualID, actualHost, commandID, host string) error {
	if actualID != commandID || actualHost != host {
		return errors.New("hostcontrol: receipt command or admitted host mismatch")
	}
	return nil
}

func (c *Client) SetDrain(ctx context.Context, host, commandID string, drain bool) (hostagent.DrainReceipt, error) {
	command, err := hostagent.NewDrainCommand(commandID, drain)
	if err != nil {
		return hostagent.DrainReceipt{}, err
	}
	var receipt hostagent.DrainReceipt
	if err = c.request(ctx, host, true, hostagent.NodeDrainSubject, command, &receipt, "commandId", "nodeId", "draining", "quiesced", "detail"); err != nil {
		return receipt, err
	}
	if _, err = hostagent.NewDrainReceipt(receipt.CommandId, receipt.NodeId, receipt.Draining, receipt.Quiesced, receipt.Detail); err != nil {
		return receipt, err
	}
	if err = matchReceipt(receipt.CommandId, receipt.NodeId, commandID, host); err != nil {
		return receipt, err
	}
	if receipt.Draining != drain || (!drain && receipt.Quiesced) {
		return receipt, errors.New("hostcontrol: requested drain state was not established")
	}
	return receipt, nil
}

func (c *Client) Status(ctx context.Context, host string) (hostagent.NodeStatusReport, error) {
	// Observations use fresh IDs; they never reuse a persisted old sample.
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return hostagent.NodeStatusReport{}, err
	}
	command, err := hostagent.NewNodeStatusRequest("status-" + hex.EncodeToString(nonce[:]))
	if err != nil {
		return hostagent.NodeStatusReport{}, err
	}
	var report hostagent.NodeStatusReport
	if err = c.request(ctx, host, false, hostagent.NodeDrainStatusSubject, command, &report, "commandId", "nodeId", "state", "quiesced", "facts"); err != nil {
		return report, err
	}
	if _, err = hostagent.NewNodeStatusReport(report.CommandId, report.NodeId, report.State, report.Quiesced, report.Facts); err != nil {
		return report, err
	}
	if err = matchReceipt(report.CommandId, report.NodeId, command.CommandId, host); err != nil {
		return report, err
	}
	if report.Facts.State != report.State || (report.State == hostagent.NodeStateServing && report.Quiesced) || len(report.Facts.Components) > 1024 {
		return report, errors.New("hostcontrol: inconsistent host status")
	}
	if len(report.Facts.ManifestSha256) != 64 {
		return report, errors.New("hostcontrol: invalid observed manifest digest")
	}
	if _, err = hex.DecodeString(report.Facts.ManifestSha256); err != nil || report.Facts.ManifestSha256 != strings.ToLower(report.Facts.ManifestSha256) {
		return report, errors.New("hostcontrol: invalid observed manifest digest")
	}
	seen := map[string]bool{}
	for _, fact := range report.Facts.Components {
		if _, err := hostagent.NewDeployCommand("validate", fact.Name, "valid"); err != nil || seen[fact.Name] {
			return report, errors.New("hostcontrol: invalid or duplicate component facts")
		}
		seen[fact.Name] = true
		if report.Quiesced && fact.Name != hostmanifest.TsNodeComponentName && fact.UnitActive {
			return report, errors.New("hostcontrol: quiesced report contains an active component")
		}
		for _, version := range []string{fact.Version, fact.Desired} {
			if version != "" {
				if _, err := hostagent.NewDeployCommand("validate", fact.Name, version); err != nil {
					return report, errors.New("hostcontrol: invalid component version")
				}
			}
		}
	}
	return report, nil
}

func (c *Client) ApplyManifest(ctx context.Context, host, commandID, expectedSHA string, manifest hostmanifest.HostManifest) (hostagent.ManifestReceipt, error) {
	command, err := hostmanifest.NewApplyManifestCommand(commandID, expectedSHA, manifest)
	if err != nil {
		return hostagent.ManifestReceipt{}, err
	}
	digest, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil {
		return hostagent.ManifestReceipt{}, err
	}
	var receipt hostagent.ManifestReceipt
	if err = c.request(ctx, host, true, hostagent.NodeApplyManifestSubject, command, &receipt, "commandId", "nodeId", "accepted", "manifestSha256", "detail"); err != nil {
		return receipt, err
	}
	if _, err = hostagent.NewManifestReceipt(receipt.CommandId, receipt.NodeId, receipt.Accepted, receipt.ManifestSha256, receipt.Detail); err != nil {
		return receipt, err
	}
	if err = matchReceipt(receipt.CommandId, receipt.NodeId, commandID, host); err != nil {
		return receipt, err
	}
	if !receipt.Accepted || receipt.ManifestSha256 != digest {
		return receipt, errors.New("hostcontrol: host did not accept exact desired manifest")
	}
	return receipt, nil
}
func (c *Client) Deploy(ctx context.Context, host, commandID, component, version string) (hostagent.DeployReceipt, error) {
	command, err := hostagent.NewDeployCommand(commandID, component, version)
	if err != nil {
		return hostagent.DeployReceipt{}, err
	}
	return c.transition(ctx, host, commandID, version, hostagent.NodeDeploySubject, command)
}
func (c *Client) Rollback(ctx context.Context, host, commandID, component, expectedVersion string) (hostagent.DeployReceipt, error) {
	if _, err := hostagent.NewDeployCommand(commandID, component, expectedVersion); err != nil {
		return hostagent.DeployReceipt{}, err
	}
	command, err := hostagent.NewRollbackCommand(commandID, component)
	if err != nil {
		return hostagent.DeployReceipt{}, err
	}
	return c.transition(ctx, host, commandID, expectedVersion, hostagent.NodeRollbackSubject, command)
}
func (c *Client) transition(ctx context.Context, host, commandID, version string, subject func(hostagent.NodeId) (string, error), command any) (hostagent.DeployReceipt, error) {
	var receipt hostagent.DeployReceipt
	err := c.request(ctx, host, true, subject, command, &receipt, "commandId", "nodeId", "accepted", "current", "detail")
	if err != nil {
		return receipt, err
	}
	if _, err = hostagent.NewDeployReceipt(receipt.CommandId, receipt.NodeId, receipt.Accepted, receipt.Current, receipt.Detail); err != nil {
		return receipt, err
	}
	if err = matchReceipt(receipt.CommandId, receipt.NodeId, commandID, host); err != nil {
		return receipt, err
	}
	if !receipt.Accepted || receipt.Current != version {
		return receipt, errors.New("hostcontrol: host did not activate exact release version")
	}
	return receipt, nil
}

func requireTypedFields(data []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			tag := field.Tag.Get("json")
			parts := strings.Split(tag, ",")
			name := parts[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			raw, present := fields[name]
			if !present {
				if strings.Contains(tag, ",omitempty") {
					continue
				}
				return errors.New("missing typed reply field")
			}
			if err := requireTypedFields(raw, field.Type); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		for _, item := range items {
			if err := requireTypedFields(item, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
