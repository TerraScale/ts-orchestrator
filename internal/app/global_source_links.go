package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

type globalSourceLinks struct {
	root *rootoci.Client
	home *globalControl
}

func newGlobalSourceLinks(root *rootoci.Client, home *globalControl) *globalSourceLinks {
	return &globalSourceLinks{root: root, home: home}
}

func (links *globalSourceLinks) Run(ctx context.Context) error {
	if links == nil || links.root == nil || links.home == nil {
		return rootoci.ErrUnauthorized
	}
	if links.home.authority == nil {
		<-ctx.Done()
		return nil
	}
	// Root authenticates catalogue locators; heartbeats cannot precede a Link.
	regions := catalog.Entries()
	failures := make([]failureLog, len(regions))
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		var requests sync.WaitGroup
		slots := make(chan struct{}, 3)
		for index, entry := range regions {
			if entry.Cell == catalog.GRU {
				continue
			}
			select {
			case <-ctx.Done():
				requests.Wait()
				return nil
			case slots <- struct{}{}:
			}
			requests.Go(func() {
				defer func() { <-slots }()
				err := links.ensure(ctx, entry.Cell)
				if err != nil {
					err = fmt.Errorf("regional Link %s: %w", entry.Cell, err)
				}
				failures[index].report("global Link delivery pending", err)
			})
		}
		requests.Wait()
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
	return nil
}

func (links *globalSourceLinks) ensure(ctx context.Context, cell string) error {
	// SourceFounder and HomeIAM fence source writes independently of R3 leaders.
	attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	receipt, err := links.root.EnsureSource(attempt, rootoci.SourceRequest{
		Cell: catalog.GRU, Kind: rootoci.SourceSpokeLink, RecipientCell: cell,
	})
	if err != nil {
		return err
	}
	if receipt.Cell != catalog.GRU || receipt.Kind != rootoci.SourceSpokeLink || receipt.RecipientCell != cell ||
		receipt.GrantDigest == "" || receipt.Generation == 0 || receipt.ObjectKey == "" {
		return rootoci.ErrInvalid
	}
	return attempt.Err()
}
