package delivery

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

func NewPoller(client *SourceClient, journal *SourceJournal, authority func() AuthoritySnapshot, interval time.Duration) *Poller {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Poller{Client: client, Journal: journal, Authority: authority, Interval: interval, completion: make(chan struct{})}
}
func (p *Poller) Start(ctx context.Context) {
	if p == nil {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
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
	if p == nil || p.Client == nil || p.Journal == nil || p.Authority == nil {
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
func (p *Poller) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		if p.cancel != nil {
			p.cancel()
		}
	})
	if p.completion != nil {
		select {
		case <-p.completion:
		case <-time.After(10 * time.Second):
			return errors.New("poller shutdown timed out")
		}
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
}
type RuntimeDependencies struct {
	Ledger     Ledger
	Publisher  EventPublisher
	HTTPClient *http.Client
}
type Runtime struct {
	handler    *WebhookHandler
	server     *http.Server
	poller     *Poller
	completion chan struct{}
	closeOnce  sync.Once
	closeErr   error
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
	journal := NewWebhookJournal(ledger, publisher)
	handler, e := NewWebhookHandler(cfg.Webhook, journal)
	if e != nil {
		return nil, e
	}
	r := &Runtime{handler: handler, completion: make(chan struct{})}
	if cfg.Webhook.ListenAddress != "" {
		r.server = &http.Server{Addr: cfg.Webhook.ListenAddress, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
		go func() {
			e := r.server.ListenAndServe()
			if e != nil && e != http.ErrServerClosed {
				r.closeErr = e
			}
			close(r.completion)
		}()
	}
	if cfg.Source.Server != nil {
		client, e := NewSourceClient(cfg.Source, cfg.HTTPClient)
		if e != nil {
			handler.Close()
			return nil, e
		}
		sj := NewSourceJournal(ledger)
		r.poller = NewPoller(client, sj, cfg.Authority, cfg.PollInterval)
		r.poller.Start(ctx)
	}
	return r, nil
}
func (r *Runtime) Completion() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.completion
}
func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.poller != nil {
			_ = r.poller.Close()
		}
		if r.server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if e := r.server.Shutdown(ctx); e != nil && r.closeErr == nil {
				r.closeErr = e
			}
		}
		if r.handler != nil {
			r.handler.Close()
		}
		select {
		case <-r.completion:
		default:
			if r.server == nil {
				close(r.completion)
			}
		}
	})
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
