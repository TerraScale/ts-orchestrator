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
	"uuid"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/serviceset"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/workload"
	"github.com/nats-io/nats.go"
)

const serviceUsage = `Usage: ts-orch service <command> --config OPERATOR_JSON [flags]

  list                                          Print the cell's current service set
  add    --role R --profile F [--spec F] [--out F]  Plan adding a service; --out writes the unsigned candidate
  update --role R --profile F [--spec F] [--out F]  Plan changing a service
  remove --role R [--out F]                     Plan removing a service (scale it to zero first)
  apply  --file SIGNED                          Apply a set signed with ts-orch release sign-service-set

Sign a candidate offline with ts-orch release sign-service-set before apply.
`

// runService maps ts-orch service <command> to the operator command, which
// owns the controller connection.
func runService(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(output, serviceUsage)
		return err
	}
	if !slices.Contains([]string{"list", "add", "update", "remove", "apply"}, args[0]) {
		return fmt.Errorf("unknown service command %q", args[0])
	}
	return runOperator(ctx, append([]string{"service-" + args[0]}, args[1:]...), output)
}

// requestServiceSet sends one signed service set request to the authority
// leader. Apply is idempotent, so a lost reply is safe to retry.
func requestServiceSet(ctx context.Context, cfg Config, runtime *natscell.Runtime, kind string, payload []byte,
) (serviceSetReply, error) {
	policy, err := buildSignerPolicy(cfg)
	if err != nil {
		return serviceSetReply{}, err
	}
	codec, err := policy.withOperator(cfg.Operator)
	if err != nil {
		return serviceSetReply{}, err
	}
	epoch, err := observeOperatorAuthority(ctx, func(attempt context.Context) (authority.Snapshot, error) {
		return authority.Observe(attempt, runtime.JetStream(), cfg.NATS.Cell)
	})
	if err != nil {
		return serviceSetReply{}, err
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: cfg.NATS.Cell, Kind: kind,
		Actor: cfg.Operator.Actor, OperationID: "service-set." + uuid.New().String(), Generation: 1, Epoch: epoch,
	}, now, now.Add(time.Minute), codec.PrivateKey)
	if err != nil {
		return serviceSetReply{}, err
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		return serviceSetReply{}, err
	}
	if len(wire) > maxRegistrationWireBytes {
		return serviceSetReply{}, errors.New("service set request exceeds the controller request bound")
	}
	for attempt := range 3 {
		requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		message, requestErr := runtime.Conn().RequestWithContext(requestCtx, hostRegistrationSubject(cfg.NATS.Cell), wire)
		cancel()
		if requestErr == nil {
			var reply serviceSetReply
			if err := protocol.DecodeStrict(message.Data, &reply, 2*serviceset.MaxSetBytes); err != nil {
				return serviceSetReply{}, fmt.Errorf("decode service set reply: %w", err)
			}
			if reply.Error != "" {
				return serviceSetReply{}, errors.New(reply.Error)
			}
			return reply, nil
		}
		if !errors.Is(requestErr, nats.ErrTimeout) && !errors.Is(requestErr, context.DeadlineExceeded) &&
			!errors.Is(requestErr, nats.ErrNoResponders) || attempt == 2 {
			return serviceSetReply{}, fmt.Errorf("request service set: %w", requestErr)
		}
	}
	return serviceSetReply{}, errors.New("service set request exhausted")
}

func operatorServiceList(ctx context.Context, cfg Config, runtime *natscell.Runtime, output io.Writer) error {
	reply, err := requestServiceSet(ctx, cfg, runtime, serviceSetListKind, []byte("{}"))
	if err != nil {
		return err
	}
	return printJSON(output, reply.Set)
}

// operatorServiceChange plans the next generation from the current set. It
// prints the plan and, with out, writes the unsigned candidate for signing.
// A change that leaves the set as it is plans nothing.
func operatorServiceChange(ctx context.Context, cfg Config, runtime *natscell.Runtime, action, role,
	profilePath, specPath, out string, output io.Writer,
) error {
	if role == "" || action != "remove" && profilePath == "" || action == "remove" && (profilePath != "" || specPath != "") {
		return fmt.Errorf("service %s requires --role%s", action, map[bool]string{true: "", false: " and --profile [--spec]"}[action == "remove"])
	}
	var service serviceset.Service
	if action != "remove" {
		profile, err := readReleaseProfile(profilePath)
		if err != nil {
			return err
		}
		service = serviceset.Service{Role: role, Profile: profile}
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
	}
	reply, err := requestServiceSet(ctx, cfg, runtime, serviceSetListKind, []byte("{}"))
	if err != nil {
		return err
	}
	current := reply.Set
	existing, found := current.Find(role)
	next := current
	next.Generation++
	next.Services = slices.DeleteFunc(slices.Clone(current.Services), func(s serviceset.Service) bool { return s.Role == role })
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
		slices.SortFunc(next.Services, func(a, b serviceset.Service) int { return strings.Compare(a.Role, b.Role) })
	}
	plan, err := serviceset.Diff(current, next)
	if err != nil {
		return err
	}
	if plan.Empty() {
		plan.To = current.Generation
		return printJSON(output, servicePlanOutput{Plan: plan, Status: "unchanged"})
	}
	encoded, err := serviceset.Encode(next)
	if err != nil {
		return err
	}
	if out != "" {
		file, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return fmt.Errorf("write service set candidate: %w", err)
		}
		_, writeErr := file.Write(encoded)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			_ = os.Remove(out)
			return fmt.Errorf("write service set candidate: %w", err)
		}
	}
	return printJSON(output, servicePlanOutput{Plan: plan, Status: "planned", Candidate: out})
}

type servicePlanOutput struct {
	serviceset.Plan
	Status    string `json:"status"`
	Candidate string `json:"candidate,omitempty"`
}

func sameService(a, b serviceset.Service) bool {
	left, leftErr := protocol.EncodeJSON(a)
	right, rightErr := protocol.EncodeJSON(b)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func operatorServiceApply(ctx context.Context, cfg Config, runtime *natscell.Runtime, path string, output io.Writer) error {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return err
	}
	if len(data) > serviceset.MaxSignedBytes {
		return errors.New("signed service set exceeds its size bound")
	}
	reply, err := requestServiceSet(ctx, cfg, runtime, serviceSetApplyKind, data)
	if err != nil {
		return err
	}
	return printJSON(output, struct {
		Status     string   `json:"status"`
		Generation uint64   `json:"generation"`
		Roles      []string `json:"roles"`
	}{reply.Status, reply.Set.Generation, serviceRoles(reply.Set)})
}

func serviceRoles(set serviceset.Set) []string {
	roles := make([]string, 0, len(set.Services))
	for _, service := range set.Services {
		roles = append(roles, service.Role)
	}
	return roles
}
