package delivery

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type pipelineSource struct {
	repository string
	commit     string
	tree       string
	protected  bool
	archive    []byte
	mu         sync.Mutex
	resolves   int
	polls      int
	files      int
	archives   int
}

func (s *pipelineSource) Resolve(context.Context, string) (ResolvedRevision, error) {
	s.mu.Lock()
	s.resolves++
	s.mu.Unlock()
	return ResolvedRevision{Repository: s.repository, Commit: s.commit, Tree: s.tree}, nil
}
func (s *pipelineSource) PollBranch(_ context.Context, branch string) (BranchObservation, error) {
	s.mu.Lock()
	s.polls++
	s.mu.Unlock()
	return BranchObservation{Branch: branch, Protected: s.protected, Revision: ResolvedRevision{Repository: s.repository, Commit: s.commit, Tree: s.tree}}, nil
}
func (s *pipelineSource) ReadFile(context.Context, string, string, int) (SourceFile, error) {
	s.mu.Lock()
	s.files++
	s.mu.Unlock()
	content := []byte(`{"apiVersion":"terrascale.ci/v3","repository":"` + s.repository + `"}`)
	return SourceFile{Repository: s.repository, Commit: s.commit, Path: CIDescriptorPath, Blob: strings.Repeat("b", 40), ContentSHA256: contentDigest(content), Content: content}, nil
}
func (s *pipelineSource) ReadArchive(context.Context, ResolvedRevision) (SourceArchive, error) {
	s.mu.Lock()
	s.archives++
	s.mu.Unlock()
	return SourceArchive{Revision: ResolvedRevision{Repository: s.repository, Commit: s.commit, Tree: s.tree}, ContentSHA256: contentDigest(s.archive), Content: append([]byte(nil), s.archive...)}, nil
}

type pipelineHandoff struct {
	mu    sync.Mutex
	count int
	err   error
	plans []*DeliveryPlan
}

func (h *pipelineHandoff) Handoff(_ context.Context, plan *DeliveryPlan) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count++
	if h.err != nil {
		return h.err
	}
	h.plans = append(h.plans, plan)
	return nil
}

func pipelineGraph(t *testing.T) (*RepositorySourceGraph, *pipelineSource, *pipelineSource) {
	t.Helper()
	root := &pipelineSource{repository: "acme/root", commit: strings.Repeat("a", 40), tree: strings.Repeat("c", 40), protected: true, archive: []byte("root archive")}
	dependency := &pipelineSource{repository: "acme/dependency", commit: strings.Repeat("d", 40), tree: strings.Repeat("e", 40), protected: true, archive: []byte("dependency archive")}
	graph, err := NewSourceGraph(root.repository, map[string]RepositorySource{root.repository: root, dependency.repository: dependency})
	if err != nil {
		t.Fatal(err)
	}
	return graph, root, dependency
}

func pipelineEvent(root *pipelineSource) *WebhookEnvelope {
	return &WebhookEnvelope{DeliveryID: "f6266f16-1bf3-46a5-9ea4-602e06ead473", Kind: WebhookPush, Action: "push", Repository: root.repository, SourceRepository: root.repository, BaseRevision: strings.Repeat("0", 40), Revision: root.commit, SourceRef: "refs/heads/develop", PayloadSHA256: strings.Repeat("1", 64)}
}

func TestDeliveryProcessorUsesGraphAndArchivesRootOnly(t *testing.T) {
	graph, root, dependency := pipelineGraph(t)
	handoff := &pipelineHandoff{}
	processor := NewDeliveryProcessor(graph, NewMemoryLedger(), handoff, nil)
	receipt, err := processor.Process(context.Background(), pipelineEvent(root))
	if err != nil || receipt.Disposition != DeliveryRecorded {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	if root.files != 1 || dependency.files != 1 || root.archives != 1 || dependency.archives != 0 {
		t.Fatalf("unexpected graph calls root files=%d archives=%d dependency files=%d archives=%d", root.files, root.archives, dependency.files, dependency.archives)
	}
	if handoff.count != 1 || len(handoff.plans[0].Descriptors) != 2 || len(handoff.plans[0].Archives) != 1 {
		t.Fatalf("incomplete handoff plan: %+v", handoff.plans)
	}
}

func TestDeliveryProcessorReplayIsNoOp(t *testing.T) {
	graph, root, _ := pipelineGraph(t)
	handoff := &pipelineHandoff{}
	processor := NewDeliveryProcessor(graph, NewMemoryLedger(), handoff, nil)
	event := pipelineEvent(root)
	if _, err := processor.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	receipt, err := processor.Process(context.Background(), event)
	if err != nil || receipt.Disposition != DeliveryDuplicate || handoff.count != 1 {
		t.Fatalf("replay receipt=%+v err=%v handoffs=%d", receipt, err, handoff.count)
	}
}

func TestDeliveryProcessorCancellationAndHandoffFailure(t *testing.T) {
	graph, root, _ := pipelineGraph(t)
	handoff := &pipelineHandoff{err: errors.New("handoff failed")}
	processor := NewDeliveryProcessor(graph, NewMemoryLedger(), handoff, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := processor.Process(ctx, pipelineEvent(root)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation err=%v", err)
	}
	if _, err := processor.Process(context.Background(), pipelineEvent(root)); err == nil {
		t.Fatal("handoff failure must be returned")
	}
	handoff.err = nil
	if receipt, err := processor.Process(context.Background(), pipelineEvent(root)); err != nil || receipt.Disposition != DeliveryRecorded {
		t.Fatalf("retry receipt=%+v err=%v", receipt, err)
	}
}

func TestDeliveryProcessorFencesAuthorityChange(t *testing.T) {
	graph, root, _ := pipelineGraph(t)
	handoff := &pipelineHandoff{}
	calls := 0
	processor := NewDeliveryProcessor(graph, NewMemoryLedger(), handoff, func() AuthoritySnapshot {
		calls++
		if calls > 1 {
			return AuthoritySnapshot{Ready: true, Leader: true, Epoch: 2}
		}
		return AuthoritySnapshot{Ready: true, Leader: true, Epoch: 1}
	})
	if _, err := processor.Process(context.Background(), pipelineEvent(root)); !errors.Is(err, ErrDeliveryFenced) {
		t.Fatalf("fencing err=%v", err)
	}
	if handoff.count != 0 {
		t.Fatal("fenced delivery reached handoff")
	}
}

func TestNewSourceGraphRejectsHostileRepositoryBound(t *testing.T) {
	sources := make(map[string]RepositorySource, MaximumGraphRepositories+1)
	for i := 0; i < MaximumGraphRepositories+1; i++ {
		sources["owner/repo"+strings.Repeat("x", i)] = &pipelineSource{repository: "owner/repo" + strings.Repeat("x", i)}
	}
	if _, err := NewSourceGraph("owner/repo", sources); err == nil {
		t.Fatal("oversized graph accepted")
	}
}
