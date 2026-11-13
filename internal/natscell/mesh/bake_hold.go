package mesh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const bakeFailureSubject = "ts.mesh.bake.failed."

type bakeReplacement struct {
	Generation int64      `json:"generation"`
	Release    Deployment `json:"release"`
}

type bakeFailure struct {
	Service    string           `json:"service"`
	Generation int64            `json:"generation"`
	Region     string           `json:"region"`
	Reason     string           `json:"reason"`
	ReplacedBy *bakeReplacement `json:"replacedBy,omitempty"`
}

func (v bakeFailure) key() string {
	return fmt.Sprintf("%s/%d/%s", v.Service, v.Generation, v.Region)
}

func (n *Node) loadBakeFailures() error {
	n.bakeFailures = map[string]bakeFailure{}
	data, err := os.ReadFile(filepath.Join(n.cfg.dir, "bake-holds.json"))
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return err
	}
	if len(data) != 0 {
		if err := protocol.DecodeTolerant(data, &n.bakeFailures, maxWire); err != nil {
			return err
		}
	}
	if n.bakeFailures == nil {
		return errors.New("bake holds must be an object")
	}
	files, err := os.ReadDir(n.cfg.dir)
	if err != nil {
		return err
	}
	for _, file := range files {
		name, generation, ok := parseBakeFile(file.Name())
		if !ok {
			continue
		}
		record, err := n.readBake(name, generation)
		if err != nil {
			return err
		}
		if record.Bake.Reason != "" {
			failure := bakeFailure{Service: name, Generation: generation, Region: n.cfg.region, Reason: record.Bake.Reason}
			if _, exists := n.bakeFailures[failure.key()]; !exists {
				n.bakeFailures[failure.key()] = failure
				n.bakeFailuresDirty = true
			}
		}
	}
	return nil
}

func (n *Node) saveBakeFailures() error {
	data, err := protocol.EncodeJSON(n.bakeFailures)
	if err != nil {
		return err
	}
	err = writePrivate(filepath.Join(n.cfg.dir, "bake-holds.json"), data)
	if err == nil {
		n.bakeFailuresDirty = false
	}
	return err
}

func (n *Node) bakeFailureSnapshot() map[string]bakeFailure {
	n.bakeFailureMu.Lock()
	defer n.bakeFailureMu.Unlock()
	return maps.Clone(n.bakeFailures)
}

func (n *Node) receiveBakeFailure(message *nats.Msg) {
	var verdict bakeFailure
	if err := protocol.DecodeTolerant(message.Data, &verdict, maxWire); err != nil ||
		!serviceName.MatchString(verdict.Service) || verdict.Generation <= 0 || verdict.Region == "" || verdict.Reason == "" {
		return
	}
	verdict.ReplacedBy = nil
	n.bakeFailureMu.Lock()
	if _, exists := n.bakeFailures[verdict.key()]; !exists {
		n.bakeFailures[verdict.key()] = verdict
		n.bakeFailuresDirty = true
	}
	err := n.saveBakeFailures()
	n.bakeFailureMu.Unlock()
	if err != nil {
		slog.Error("received bake failure not saved", "service", verdict.Service, "generation", verdict.Generation, "error", err)
		return
	}
	n.respond(message, Reply{Region: n.cfg.region, Result: "failed verdict saved"})
}

func (n *Node) mergeBakeFailures(states map[string]stateReply) error {
	n.bakeFailureMu.Lock()
	defer n.bakeFailureMu.Unlock()

	for _, state := range states {
		for _, failure := range n.bakeFailures {
			if failure.Region == state.Region && state.Ready[failure.Service] == failure.Generation {
				slog.Warn("passed bake refused after sticky failure", "service", failure.Service, "generation", failure.Generation, "region", failure.Region)
			}
		}
		for _, failure := range state.Holds {
			if _, exists := n.bakeFailures[failure.key()]; !exists {
				failure.ReplacedBy = nil
				n.bakeFailures[failure.key()] = failure
				n.bakeFailuresDirty = true
			}
		}
	}
	if n.bakeFailuresDirty {
		return n.saveBakeFailures()
	}
	return nil
}

func (n *Node) stickyFailure(name string, generation int64, region string) bool {
	n.bakeFailureMu.Lock()
	defer n.bakeFailureMu.Unlock()
	_, exists := n.bakeFailures[(bakeFailure{Service: name, Generation: generation, Region: region}).key()]
	return exists
}

func (n *Node) heldBakeGeneration(name string) int64 {
	current := n.desired[name].entry()
	var held int64
	n.bakeFailureMu.Lock()
	for _, failure := range n.bakeFailures {
		if failure.Service == name && (n.bakeFailuresDirty || failure.ReplacedBy == nil || current.Generation < failure.ReplacedBy.Generation) {
			held = max(held, failure.Generation)
		}
	}
	n.bakeFailureMu.Unlock()
	if record, err := n.readBake(name, current.Generation); err == nil && record.Bake.Reason != "" {
		held = max(held, current.Generation)
	}
	if record := n.bakeUnsaved[n.bakePath(name, current.Generation)]; record.Bake.Reason != "" {
		held = max(held, current.Generation)
	}
	return held
}

func (n *Node) checkBakeAdmission(name string, entry Entry) error {
	held := n.heldBakeGeneration(name)
	if held == 0 {
		return nil
	}
	if entry.Deployment == nil || entry.Generation <= held {
		return fmt.Errorf("%s held at failed generation %d; repair the cause and dispatch the signed release workflow with the same digest or a corrected image", name, held)
	}
	return nil
}

func (n *Node) acceptBakeReplacement(name string, entry Entry) error {
	if err := n.checkBakeAdmission(name, entry); err != nil {
		return err
	}
	if entry.Deployment == nil {
		return nil
	}
	n.bakeFailureMu.Lock()
	defer n.bakeFailureMu.Unlock()

	for key, failure := range n.bakeFailures {
		if failure.Service == name && failure.Generation < entry.Generation && (failure.ReplacedBy == nil || n.desired[name].entry().Generation < failure.ReplacedBy.Generation) {
			failure.ReplacedBy = &bakeReplacement{Generation: entry.Generation, Release: *entry.Deployment}
			n.bakeFailures[key] = failure
			n.bakeFailuresDirty = true
		}
	}
	if n.bakeFailuresDirty {
		return n.saveBakeFailures()
	}
	return nil
}

func (n *Node) retainBakeFailure(ctx context.Context, name, key string, record bakeRecord) error {
	verdict := bakeFailure{Service: name, Generation: record.Generation, Region: n.cfg.region, Reason: record.Bake.Reason}
	n.bakeFailureMu.Lock()
	if _, exists := n.bakeFailures[verdict.key()]; !exists {
		n.bakeFailures[verdict.key()] = verdict
		n.bakeFailuresDirty = true
	}
	n.bakeFailureMu.Unlock()
	record.Bake.Unsaved = true
	n.mu.Lock()
	if n.bakeUnsaved == nil {
		n.bakeUnsaved = map[string]bakeRecord{}
	}
	n.bakeUnsaved[key] = record
	n.mu.Unlock()
	payload, err := protocol.EncodeJSON(verdict)
	if err != nil {
		return err
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		regions := n.regions()
		results := make(chan bool, len(regions)+1)
		go func() {
			n.mu.Lock()
			localErr := n.saveBake(key, record)
			n.mu.Unlock()
			n.bakeFailureMu.Lock()
			ledgerErr := n.saveBakeFailures()
			n.bakeFailureMu.Unlock()
			results <- localErr == nil || ledgerErr == nil
		}()
		count := 1
		for _, region := range regions {
			if region == n.cfg.region {
				continue
			}
			count++
			go func() {
				request, cancel := context.WithTimeout(ctx, stateWait)
				defer cancel()
				message, err := n.conn.RequestWithContext(request, bakeFailureSubject+region, payload)
				var reply Reply
				results <- err == nil && protocol.DecodeTolerant(message.Data, &reply, maxWire) == nil && reply.Region == region && reply.Result == "failed verdict saved"
			}()
		}
		handled := false
		for range count {
			handled = <-results || handled
		}
		if handled {
			record.Bake.Unsaved = false
			n.mu.Lock()
			_ = n.saveBake(key, record)
			n.mu.Unlock()
			return nil
		}
		slog.Error("regional bake failed, unsaved", "service", name, "generation", record.Generation)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
