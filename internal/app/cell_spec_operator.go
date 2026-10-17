package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go"
)

const serviceUsage = `Usage: ts-orch service <command> --config OPERATOR_JSON [flags]

  list                                          Print the cell spec (as ts-orch get)
  add    --role R --profile F [--spec F] [--releasers A,B] [--out F]  Plan adding a service; --out writes the unsigned candidate
  update --role R --profile F [--spec F] [--releasers A,B] [--out F]  Plan changing a service
  remove --role R [--out F]                     Plan removing a service (scale it to zero first)
  grant-host  --node N --private-ip IP --roles A,B --environment E [--out F]
                                                Plan letting a static host enroll with these roles
  revoke-host --node N [--out F]                Plan removing a host grant
  allow-image --image-id ID --receipt F --delegation F [--launch] [--out F]
                                                Plan letting managed hosts run a qualified image; --launch makes new hosts boot it
  revoke-image --image-id ID [--launch] [--out F]
                                                Plan removing an allowed host image (new hosts return to the pin if it was the launch image);
                                                --launch only stops new hosts booting it and keeps it allowed
  apply  --file SIGNED                          Apply a signed cell spec (as ts-orch apply -f)

Sign a candidate offline with ts-orch release sign-spec before apply.
`

const specUsage = `Usage: ts-orch <get|diff|apply> --config OPERATOR_JSON [-f FILE]

  get                 Print the cell's current spec
  diff -f FILE        Plan an unsigned candidate or a signed spec against the current spec
  apply -f SIGNED     Apply a spec signed with ts-orch release sign-spec
`

// runService maps ts-orch service <command> to the operator command, which
// owns the controller connection.
func runService(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(output, serviceUsage)
		return err
	}
	if !slices.Contains([]string{"list", "add", "update", "remove", "grant-host", "revoke-host", "allow-image", "revoke-image", "apply"}, args[0]) {
		return fmt.Errorf("unknown service command %q", args[0])
	}
	return runOperator(ctx, append([]string{"service-" + args[0]}, args[1:]...), output)
}

// runSpec maps ts-orch get|diff|apply to the operator command.
func runSpec(ctx context.Context, command string, args []string, output io.Writer) error {
	if len(args) > 0 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		_, err := io.WriteString(output, specUsage)
		return err
	}
	return runOperator(ctx, append([]string{"spec-" + command}, args...), output)
}

// requestCellSpec sends one signed cell spec request to the authority
// leader. Every request is idempotent, so a lost reply is safe to retry.
func requestCellSpec(ctx context.Context, cfg Config, runtime *natscell.Runtime, kind string, payload []byte,
) (specReply, error) {
	data, err := requestLeader(ctx, cfg, runtime, kind, "cell-spec", payload)
	if err != nil {
		return specReply{}, err
	}
	var reply specReply
	if err := protocol.DecodeStrict(data, &reply, 3*cellspec.MaxSpecBytes); err != nil {
		return specReply{}, fmt.Errorf("decode %s reply: %w", kind, err)
	}
	if reply.Error != "" {
		return specReply{}, errors.New(reply.Error)
	}
	return reply, nil
}

// requestLeader sends one operator request, signed by the operator's command
// key for the current authority epoch, on the host registration subject,
// where only the authority leader answers. It returns the raw reply. Every
// such request is idempotent, so a lost reply is retried.
func requestLeader(ctx context.Context, cfg Config, runtime *natscell.Runtime, kind, operation string, payload []byte,
) ([]byte, error) {
	return requestAuthority(ctx, cfg, runtime, cfg.NATS.Cell, kind, operation, payload)
}

// requestAuthority is requestLeader for the leader of scope: the cell's
// authority, or the global authority in the global home region.
func requestAuthority(ctx context.Context, cfg Config, runtime *natscell.Runtime, scope, kind, operation string,
	payload []byte,
) ([]byte, error) {
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return nil, err
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return nil, err
	}
	epoch, err := observeOperatorAuthority(ctx, func(attempt context.Context) (authority.Snapshot, error) {
		return authority.Observe(attempt, runtime.JetStream(), scope)
	})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: cfg.NATS.Cell, Kind: kind,
		Actor: cfg.Operator.Actor, OperationID: entityid.NewAt(now), Generation: 1, Epoch: epoch,
	}, now, now.Add(time.Minute), codec.PrivateKey)
	if err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return nil, err
	}
	if len(wire) > maxRegistrationWireBytes {
		return nil, fmt.Errorf("%s request exceeds the controller request bound", kind)
	}
	for attempt := range 3 {
		requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		message, requestErr := runtime.Conn().RequestWithContext(requestCtx, hostRegistrationSubject(cfg.NATS.Cell), wire)
		cancel()
		if requestErr == nil {
			return message.Data, nil
		}
		if !errors.Is(requestErr, nats.ErrTimeout) && !errors.Is(requestErr, context.DeadlineExceeded) &&
			!errors.Is(requestErr, nats.ErrNoResponders) || attempt == 2 {
			return nil, fmt.Errorf("request %s: %w", kind, requestErr)
		}
	}
	return nil, fmt.Errorf("%s request exhausted", kind)
}

func operatorSpecGet(ctx context.Context, cfg Config, runtime *natscell.Runtime, output io.Writer) error {
	reply, err := requestCellSpec(ctx, cfg, runtime, cellSpecGetKind, []byte("{}"))
	if err != nil {
		return err
	}
	return printJSON(output, reply.Spec)
}

type specPlanOutput struct {
	cellspec.Plan
	Status    string `json:"status"`
	Candidate string `json:"candidate,omitempty"`
}

// operatorSpecDiff plans a file against the cell's current spec on the
// leader, which applies the cell's rules and names what needs a root. The
// file's signatures are not checked: apply does that.
func operatorSpecDiff(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, output io.Writer) error {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return err
	}
	candidate, err := cellspec.Candidate(data)
	if err != nil {
		return err
	}
	payload, err := cellspec.Encode(candidate)
	if err != nil {
		return err
	}
	reply, err := requestCellSpec(ctx, cfg, runtime, cellSpecDiffKind, payload)
	if err != nil {
		return err
	}
	if reply.Plan == nil {
		return errors.New("cell spec diff reply has no plan")
	}
	return printJSON(output, specPlanOutput{Plan: *reply.Plan, Status: reply.Status})
}

// operatorServiceChange plans the next generation from the current spec. It
// prints the leader's plan and, with out, writes the unsigned candidate for
// signing. A change that leaves the spec as it is plans nothing.
func operatorServiceChange(ctx context.Context, cfg Config, runtime *natscell.Runtime, action, role,
	profilePath, specPath, releasers, out string, output io.Writer,
) error {
	if role == "" || action != "remove" && profilePath == "" || action == "remove" && (profilePath != "" || specPath != "" || releasers != "") {
		return fmt.Errorf("service %s requires --role%s", action, map[bool]string{true: "", false: " and --profile [--spec]"}[action == "remove"])
	}
	var service cellspec.Service
	if action != "remove" {
		profile, err := readReleaseProfile(profilePath)
		if err != nil {
			return err
		}
		service = cellspec.Service{Role: role, Profile: profile}
		if specPath != "" {
			data, err := readBoundedConfigFile(specPath)
			if err != nil {
				return err
			}
			var spec workload.ServiceSpec
			if err := json.Unmarshal(data, &spec, json.RejectUnknownMembers(true)); err != nil {
				return fmt.Errorf("parse service spec: %w", err)
			}
			service.Spec = &spec
		}
		if releasers != "" {
			service.Releasers = splitList(releasers)
		}
	}
	reply, err := requestCellSpec(ctx, cfg, runtime, cellSpecGetKind, []byte("{}"))
	if err != nil {
		return err
	}
	current := reply.Spec
	existing, found := current.Find(role)
	if action == "update" && releasers == "" {
		service.Releasers = existing.Releasers
	}
	next := current
	next.Generation++
	next.Services = slices.DeleteFunc(slices.Clone(current.Services), func(s cellspec.Service) bool { return s.Role == role })
	switch action {
	case "add":
		if found && !sameService(existing, service) {
			return fmt.Errorf("service %q exists; use service update", role)
		}
	case "update":
		if !found {
			return fmt.Errorf("service %q does not exist; use service add", role)
		}
	}
	if action != "remove" {
		next.Services = append(next.Services, service)
		slices.SortFunc(next.Services, func(a, b cellspec.Service) int { return strings.Compare(a.Role, b.Role) })
	}
	return planSpec(ctx, cfg, runtime, current, next, out, output)
}

// operatorServiceHostGrant plans the next generation with the host grant of
// grant.Node set (grant) or removed.
func operatorServiceHostGrant(ctx context.Context, cfg Config, runtime *natscell.Runtime, set bool,
	grant cellspec.HostGrant, out string, output io.Writer,
) error {
	if grant.Node == "" || set != (grant.PrivateIP != "" && len(grant.Roles) != 0 && grant.Environment != "") {
		return errors.New("service grant-host requires --node, --private-ip, --roles and --environment; revoke-host only --node")
	}
	reply, err := requestCellSpec(ctx, cfg, runtime, cellSpecGetKind, []byte("{}"))
	if err != nil {
		return err
	}
	current := reply.Spec
	next := current
	next.Generation++
	// A grant at another node's address replaces that node's grant: the
	// host there is renamed (TS-609).
	next.HostGrants = slices.DeleteFunc(slices.Clone(current.HostGrants), func(g cellspec.HostGrant) bool {
		return g.Node == grant.Node || set && g.PrivateIP == grant.PrivateIP
	})
	if set {
		next.HostGrants = append(next.HostGrants, grant)
		slices.SortFunc(next.HostGrants, func(a, b cellspec.HostGrant) int { return strings.Compare(a.Node, b.Node) })
	}
	return planSpec(ctx, cfg, runtime, current, next, out, output)
}

// operatorServiceHostImage plans the next generation with the host image of
// imageID allowed from the receipt and delegation files (allow), with launch
// also as the launch image. Revoking removes it, or with launch only stops
// new hosts booting it, the rollback for a bad launch image. The leader
// checks that the receipt qualifies exactly imageID for the cell now.
func operatorServiceHostImage(ctx context.Context, cfg Config, runtime *natscell.Runtime, allow, launch bool, imageID,
	receiptPath, delegationPath, out string, output io.Writer,
) error {
	if imageID == "" || allow != (receiptPath != "") || allow != (delegationPath != "") {
		return errors.New("service allow-image requires --image-id, --receipt and --delegation; revoke-image only --image-id")
	}
	image := cellspec.HostImage{ImageID: imageID}
	if allow {
		var err error
		if image.Receipt, err = readCanonicalEnvelope(receiptPath); err != nil {
			return fmt.Errorf("read image receipt: %w", err)
		}
		if image.Delegation, err = readCanonicalEnvelope(delegationPath); err != nil {
			return fmt.Errorf("read image delegation: %w", err)
		}
	}
	reply, err := requestCellSpec(ctx, cfg, runtime, cellSpecGetKind, []byte("{}"))
	if err != nil {
		return err
	}
	current := reply.Spec
	next := current
	next.Generation++
	if !allow && launch {
		if current.LaunchImage != imageID {
			return fmt.Errorf("image %s is not the launch image", imageID)
		}
		next.LaunchImage = ""
		return planSpec(ctx, cfg, runtime, current, next, out, output)
	}
	next.HostImages = slices.DeleteFunc(slices.Clone(current.HostImages), func(i cellspec.HostImage) bool { return i.ImageID == imageID })
	if allow {
		next.HostImages = append(next.HostImages, image)
		slices.SortFunc(next.HostImages, func(a, b cellspec.HostImage) int { return strings.Compare(a.ImageID, b.ImageID) })
	}
	switch {
	case launch:
		next.LaunchImage = imageID
	case !allow && next.LaunchImage == imageID:
		next.LaunchImage = ""
	}
	return planSpec(ctx, cfg, runtime, current, next, out, output)
}

// operatorAtlasAddRegion plans the next generation of the global home's spec
// with cell's catalog region listed in its atlas section. Any atlas change
// needs a root signature (cellspec.AuthorityChanges).
func operatorAtlasAddRegion(ctx context.Context, cfg Config, runtime *natscell.Runtime, cell, out string,
	output io.Writer,
) error {
	if cell == "" {
		return errors.New("atlas add-region requires --cell")
	}
	reply, err := requestCellSpec(ctx, cfg, runtime, cellSpecGetKind, []byte("{}"))
	if err != nil {
		return err
	}
	current := reply.Spec
	if current.Atlas == nil {
		return fmt.Errorf("cell %s publishes no atlas section; use the global home's operator config", cfg.NATS.Cell)
	}
	section, _, err := current.Atlas.AddRegion(cell)
	if err != nil {
		return err
	}
	next := current
	next.Generation++
	next.Atlas = &section
	return planSpec(ctx, cfg, runtime, current, next, out, output)
}

// readCanonicalEnvelope reads a signed envelope file, which a spec holds
// byte for byte and so must be canonical, as the release tools write it.
func readCanonicalEnvelope(path string) ([]byte, error) {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return nil, err
	}
	if _, err := trust.DecodeEnvelope(data); err != nil {
		return nil, err
	}
	return data, nil
}

// planSpec prints the leader's plan from current to next and, with out,
// writes next as the unsigned candidate. A next that changes nothing plans
// nothing.
func planSpec(ctx context.Context, cfg Config, runtime *natscell.Runtime, current, next cellspec.Spec, out string,
	output io.Writer,
) error {
	next.RequiresBinary = next.Level()
	encoded, err := cellspec.Encode(next)
	if err != nil {
		return err
	}
	planned, err := requestCellSpec(ctx, cfg, runtime, cellSpecDiffKind, encoded)
	if err != nil {
		return err
	}
	if planned.Plan == nil {
		return errors.New("cell spec diff reply has no plan")
	}
	plan := *planned.Plan
	if plan.Empty() {
		plan.To = current.Generation
		return printJSON(output, specPlanOutput{Plan: plan, Status: "unchanged"})
	}
	if out != "" {
		file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return fmt.Errorf("write cell spec candidate: %w", err)
		}
		_, writeErr := file.Write(encoded)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			_ = os.Remove(out)
			return fmt.Errorf("write cell spec candidate: %w", err)
		}
	}
	return printJSON(output, specPlanOutput{Plan: plan, Status: planned.Status, Candidate: out})
}

// splitList returns the sorted entries of a comma-separated flag.
func splitList(value string) []string {
	if value == "" {
		return nil
	}
	entries := strings.Split(value, ",")
	slices.Sort(entries)
	return entries
}

func sameService(a, b cellspec.Service) bool {
	left, leftErr := protocol.EncodeJSON(a)
	right, rightErr := protocol.EncodeJSON(b)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func operatorSpecApply(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, output io.Writer) error {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return err
	}
	if len(data) > cellspec.MaxSignedBytes {
		return errors.New("signed cell spec exceeds its size bound")
	}
	// A spec for another region goes through the global home region.
	if target, _, err := relayTarget(data); err == nil && target != cfg.NATS.Cell {
		return operatorSpecRelay(ctx, cfg, runtime, target, data, output)
	}
	reply, err := requestCellSpec(ctx, cfg, runtime, cellSpecApplyKind, data)
	if err != nil {
		return err
	}
	roles := make([]string, 0, len(reply.Spec.Services))
	for _, service := range reply.Spec.Services {
		roles = append(roles, service.Role)
	}
	return printJSON(output, struct {
		Status         string   `json:"status"`
		Generation     uint64   `json:"generation"`
		RequiresBinary uint64   `json:"requires_binary"`
		Roles          []string `json:"roles"`
	}{reply.Status, reply.Spec.Generation, reply.Spec.RequiresBinary, roles})
}
