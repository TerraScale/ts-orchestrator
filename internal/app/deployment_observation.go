package app

import (
	"context"
	"strconv"

	"github.com/TerraScale/ts-orchestrator/internal/apppull"
	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/ocirelease"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
)

func observeDeploymentTargets(ctx context.Context, h *releasepush.Handler, region string) map[string]releasepush.DeploymentTarget {
	type answer struct {
		service string
		target  releasepush.DeploymentTarget
	}
	deployed := appregistry.Deployed()
	answers := make(chan answer, len(deployed)+1)
	count := 1
	go func() {
		target := releasepush.DeploymentTarget{}
		registry, err := h.Registry(ctx)
		if err == nil {
			signed, _, readErr := ocirelease.Read(ctx, registry, ocirelease.Stable)
			err = readErr
			if err == nil {
				channel, verifyErr := h.Attest.Channel(signed)
				err = verifyErr
				target.Revision, target.RunID, target.PublishedAt = channel.SHA, channel.Run, channel.PublishedAt
				target.Seq = channel.Seq
			}
		}
		if err != nil {
			target.Error = "signed release channel unreadable: " + secretpreflight.Scrub(err.Error())
		}
		answers <- answer{"ts-orchestrator", target}
	}()
	for _, app := range deployed {
		count++
		go func() {
			source := apppull.Source{Registry: func(ctx context.Context) (*appregistry.Client, error) { return appregistry.Regional(ctx, region) }}
			selection, err := source.Pull(ctx, app)
			target := releasepush.DeploymentTarget{Revision: selection.Claims.SHA, RunID: selection.Claims.RunID, Image: selection.Image}
			if err == nil {
				target.Attempt, err = strconv.ParseUint(selection.Claims.RunAttempt, 10, 64)
			}
			if err != nil {
				target.Error = "signed application release selection unreadable: " + secretpreflight.Scrub(err.Error())
			}
			answers <- answer{app.Service, target}
		}()
	}
	targets := map[string]releasepush.DeploymentTarget{}
	for range count {
		result := <-answers
		targets[result.service] = result.target
	}
	return targets
}
