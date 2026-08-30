package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func NewPoller(client *SourceClient, journal *SourceJournal, authority func() AuthoritySnapshot, interval time.Duration) *Poller {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Poller{Client: client, Journal: journal, Authority: authority, Interval: interval, completion: make(chan struct{})}
}

func NewGraphPoller(graph *RepositorySourceGraph, journal *SourceJournal, processor *DeliveryProcessor, authority func() AuthoritySnapshot, interval time.Duration) *Poller {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Poller{Graph: graph, Journal: journal, Processor: processor, Authority: authority, Interval: interval, completion: make(chan struct{})}
}
func (p *Poller) Start(ctx context.Context) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.closed || p.started {
		p.mu.Unlock()
		return
	}
	if p.completion == nil {
		p.completion = make(chan struct{})
	}
	p.started = true
	if ctx == nil {
		p.closed = true
		close(p.completion)
		p.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.mu.Unlock()
	go func() {
		defer close(p.completion)
		ticker := time.NewTicker(p.Interval)
		defer ticker.Stop()
		for {
			_ = p.PollOnce(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
func (p *Poller) Completion() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.completion
}
func (p *Poller) PollOnce(ctx context.Context) error {
	if p == nil || ctx == nil || p.Journal == nil || p.Authority == nil {
		return errors.New("poller dependencies are missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.Graph != nil {
		return p.pollGraph(ctx)
	}
	if p.Client == nil {
		return errors.New("poller dependencies are missing")
	}
	lease := p.Authority()
	if !lease.Ready || !lease.Leader {
		return nil
	}
	for _, branch := range []string{"develop", "main"} {
		o, e := p.Client.PollBranch(ctx, branch)
		if e != nil {
			return e
		}
		confirmed := p.Authority()
		if !confirmed.Ready || !confirmed.Leader || confirmed.Epoch != lease.Epoch {
			return nil
		}
		r, e := p.Journal.Observe(ctx, o, lease.Epoch, time.Now().UnixNano())
		if e != nil {
			return e
		}
		if r.Disposition == SourceStaleAuthority || r.Disposition == SourceStaleSequence {
			return nil
		}
		if r.Disposition == SourceUnprotectedBranch || r.Disposition == SourceIdentityConflict || r.Disposition == SourceUnspecified {
			return errors.New("unsafe Forgejo source observation")
		}
	}
	return nil
}

func (p *Poller) pollGraph(ctx context.Context) error {
	if p.Graph == nil || p.Processor == nil || p.Graph.Sources[p.Graph.Root] == nil {
		return errors.New("graph poller dependencies are missing")
	}
	lease := p.Authority()
	if !lease.Ready || !lease.Leader || lease.Epoch <= 0 {
		return nil
	}
	for _, branch := range []string{"develop", "main"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		root, err := p.Graph.Sources[p.Graph.Root].PollBranch(ctx, branch)
		if err != nil {
			return err
		}
		if err := ensureAuthority(p.Authority, lease); err != nil {
			return nil
		}
		if r, err := p.Journal.Observe(ctx, root, lease.Epoch, p.nextSequence()); err != nil {
			return err
		} else if r.Disposition == SourceStaleAuthority || r.Disposition == SourceStaleSequence {
			return nil
		} else if r.Disposition == SourceUnprotectedBranch || r.Disposition == SourceIdentityConflict || r.Disposition == SourceUnspecified {
			return errors.New("unsafe Forgejo source observation")
		}
		event := pollEvent(p.Graph.Root, branch, root.Revision.Commit)
		if branch == "develop" {
			snapshot, err := p.Graph.Snapshot(ctx, &event, branch, true)
			if err != nil {
				return err
			}
			for _, observation := range snapshot.Observations {
				if err := ensureAuthority(p.Authority, lease); err != nil {
					return nil
				}
				if r, err := p.Journal.Observe(ctx, observation, lease.Epoch, p.nextSequence()); err != nil {
					return err
				} else if r.Disposition == SourceStaleAuthority || r.Disposition == SourceStaleSequence {
					return nil
				} else if r.Disposition == SourceUnprotectedBranch || r.Disposition == SourceIdentityConflict || r.Disposition == SourceUnspecified {
					return errors.New("unsafe Forgejo source observation")
				}
			}
			if _, err := p.Processor.ProcessSnapshot(ctx, &event, snapshot); err != nil {
				return err
			}
		} else {
			if _, err := p.Processor.Process(ctx, &event); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *Poller) nextSequence() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UnixNano()
	if now <= p.sequence {
		now = p.sequence + 1
	}
	p.sequence = now
	return now
}

func pollEvent(repository, branch, commit string) WebhookEnvelope {
	identity := sha256.Sum256([]byte(repository + "\n" + branch + "\n" + strings.ToLower(commit)))
	digest := hex.EncodeToString(identity[:])
	return WebhookEnvelope{DeliveryID: digest[:8] + "-" + digest[8:12] + "-" + digest[12:16] + "-" + digest[16:20] + "-" + digest[20:32], Kind: WebhookPush, Action: "push", Repository: repository, SourceRepository: repository, BaseRevision: strings.Repeat("0", 40), Revision: strings.ToLower(commit), SourceRef: "refs/heads/" + branch, PayloadSHA256: digest}
}
func (p *Poller) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		cancel := p.cancel
		started := p.started
		if p.completion == nil {
			p.completion = make(chan struct{})
		}
		if !started {
			close(p.completion)
		}
		p.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	})
	if p.completion != nil {
		select {
		case <-p.completion:
		case <-time.After(10 * time.Second):
			return errors.New("poller shutdown timed out")
		}
	}
	if p.Client != nil {
		_ = p.Client.Close()
	}
	if p.Graph != nil {
		_ = p.Graph.Close()
	}
	return nil
}

type RuntimeConfig struct {
	Webhook      WebhookConfig
	Source       SourceConfig
	Graph        SourceGraphConfig
	HTTPClient   *http.Client
	PollInterval time.Duration
	Authority    func() AuthoritySnapshot
	Ledger       Ledger
	Publisher    EventPublisher
	Handoff      DeliveryHandoff
	Reconciler   DeliveryReconciler
}
type RuntimeDependencies struct {
	Ledger     Ledger
	Publisher  EventPublisher
	HTTPClient *http.Client
	Handoff    DeliveryHandoff
	Reconciler DeliveryReconciler
}
type Runtime struct {
	handler      *WebhookHandler
	server       *http.Server
	poller       *Poller
	completion   chan struct{}
	closeOnce    sync.Once
	closeErr     error
	completeOnce sync.Once
	mu           sync.Mutex
}

func Start(ctx context.Context, cfg RuntimeConfig, deps RuntimeDependencies) (*Runtime, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	ledger := cfg.Ledger
	if ledger == nil {
		ledger = deps.Ledger
	}
	if ledger == nil {
		return nil, errors.New("delivery ledger is required")
	}
	publisher := cfg.Publisher
	if publisher == nil {
		publisher = deps.Publisher
	}
	handoff := cfg.Handoff
	if handoff == nil {
		handoff = deps.Handoff
	}
	reconciler := cfg.Reconciler
	if reconciler == nil {
		reconciler = deps.Reconciler
	}
	if handoff == nil && reconciler != nil {
		handoff = reconcilerHandoff{reconciler: reconciler}
	}
	var graph *RepositorySourceGraph
	var processor *DeliveryProcessor
	if cfg.Source.Server != nil || len(cfg.Graph.Repositories) > 0 {
		if cfg.Source.Server == nil || !ValidRepository(cfg.Source.Repository) || len(cfg.Graph.Repositories) == 0 || len(cfg.Graph.Repositories) > MaximumGraphRepositories {
			return nil, errors.New("delivery source graph configuration is incomplete")
		}
		if cfg.Authority == nil || handoff == nil {
			return nil, errors.New("delivery source graph requires authority and handoff")
		}
		if _, err := cfg.Source.token(); err != nil {
			return nil, err
		}
		sources := make(map[string]RepositorySource, len(cfg.Graph.Repositories))
		seen := map[string]struct{}{}
		for _, repository := range cfg.Graph.Repositories {
			if !ValidRepository(repository) {
				_ = (&RepositorySourceGraph{Sources: sources}).Close()
				return nil, errors.New("delivery source graph repository is invalid")
			}
			if _, ok := seen[repository]; ok {
				_ = (&RepositorySourceGraph{Sources: sources}).Close()
				return nil, errors.New("delivery source graph repository is duplicated")
			}
			seen[repository] = struct{}{}
			sourceConfig, err := cfg.Source.ForRepository(repository)
			if err != nil {
				_ = (&RepositorySourceGraph{Sources: sources}).Close()
				return nil, err
			}
			client, err := NewSourceClient(sourceConfig, cfg.HTTPClient)
			if err != nil {
				_ = (&RepositorySourceGraph{Sources: sources}).Close()
				return nil, err
			}
			sources[repository] = client
		}
		var graphErr error
		graph, graphErr = NewSourceGraph(cfg.Source.Repository, sources)
		if graphErr != nil {
			_ = (&RepositorySourceGraph{Sources: sources}).Close()
			return nil, graphErr
		}
		processor = NewDeliveryProcessor(graph, ledger, handoff, cfg.Authority)
		publisher = &processingPublisher{processor: processor, next: publisher}
	}
	journal := NewWebhookJournal(ledger, publisher)
	handler, e := NewWebhookHandler(cfg.Webhook, journal)
	if e != nil {
		if graph != nil {
			_ = graph.Close()
		}
		return nil, e
	}
	r := &Runtime{handler: handler, completion: make(chan struct{})}
	if cfg.Webhook.ListenAddress != "" {
		listenURL, parseErr := url.Parse(cfg.Webhook.ListenAddress)
		if parseErr != nil || listenURL.Host == "" {
			handler.Close()
			if graph != nil {
				_ = graph.Close()
			}
			return nil, errors.New("webhook listen address is invalid")
		}
		r.server = &http.Server{Addr: listenURL.Host, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
		go func() {
			e := r.server.ListenAndServe()
			if e != nil && e != http.ErrServerClosed {
				r.mu.Lock()
				r.closeErr = e
				r.mu.Unlock()
			}
			r.complete()
		}()
	}
	if graph != nil {
		sj := NewSourceJournal(ledger)
		r.poller = NewGraphPoller(graph, sj, processor, cfg.Authority, cfg.PollInterval)
		r.poller.Start(ctx)
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = r.Close()
		case <-r.pollerCompletion():
			_ = r.Close()
		case <-r.completion:
			_ = r.Close()
		}
	}()
	return r, nil
}

type processingPublisher struct {
	processor *DeliveryProcessor
	next      EventPublisher
}

func (p *processingPublisher) Publish(ctx context.Context, event *WebhookEnvelope) error {
	if p == nil || p.processor == nil {
		return errors.New("delivery processor is missing")
	}
	if _, err := p.processor.Process(ctx, event); err != nil {
		return err
	}
	if p.next != nil {
		return p.next.Publish(ctx, event)
	}
	return nil
}
func (r *Runtime) Completion() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.completion
}
func (r *Runtime) complete() { r.completeOnce.Do(func() { close(r.completion) }) }
func (r *Runtime) pollerCompletion() <-chan struct{} {
	if r.poller == nil {
		return make(chan struct{})
	}
	return r.poller.Completion()
}
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.poller != nil {
			if err := r.poller.Close(); err != nil {
				r.mu.Lock()
				if r.closeErr == nil {
					r.closeErr = err
				}
				r.mu.Unlock()
			}
		}
		if r.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if e := r.server.Shutdown(ctx); e != nil {
				r.mu.Lock()
				if r.closeErr == nil {
					r.closeErr = e
				}
				r.mu.Unlock()
			}
		}
		if r.handler != nil {
			r.handler.Close()
		}
		select {
		case <-r.completion:
		default:
			r.complete()
		}
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeErr
}

// Starter adapts Runtime to control.GlobalNatsRuntimeComponentStarter without importing control.
type Starter func(context.Context, RuntimeDependencies) (interface {
	Completion() <-chan struct{}
	Close() error
}, error)

func NewStarter(cfg RuntimeConfig) Starter {
	return func(ctx context.Context, deps RuntimeDependencies) (interface {
		Completion() <-chan struct{}
		Close() error
	}, error) {
		return Start(ctx, cfg, deps)
	}
}
