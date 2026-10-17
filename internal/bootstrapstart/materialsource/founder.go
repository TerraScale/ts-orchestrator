package materialsource

import (
	"context"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

func (source *ColdStartMaterial) currentActor() materialSourceActor {
	return materialSourceActor{InstanceID: source.actor.InstanceID(), GrantDigest: source.actor.GrantDigest(), TemplateDigest: source.actor.TemplateDigest()}
}

func (source *ColdStartMaterial) guard(ctx context.Context) error {
	if source == nil || source.actor == nil || !source.grant.IsVerified() || !time.Now().Before(source.grant.ExpiresAt()) || ctx.Err() != nil || source.actor.GrantDigest() != digestWire(source.grant.FoundationGrantWire()) {
		return ErrMaterialSource
	}
	proof := source.actor.Founder()
	if proof.InstallationID() != source.grant.InstallationID() || proof.Generation() != source.grant.Generation() || source.actor.SourceStorageDomain() != source.grant.StorageDomain() {
		return ErrMaterialSource
	}
	if source.link == nil || source.link.recipient == nil {
		if proof.PlanDigest() != source.grant.PlanDigest() {
			return ErrMaterialSource
		}
	} else {
		home := source.link.home
		if home == nil || home.actor == nil || source.actor.InstanceID() != home.actor.InstanceID() || source.actor.TemplateDigest() != home.actor.TemplateDigest() || proof.PlanDigest() != home.grant.PlanDigest() {
			return ErrMaterialSource
		}
	}
	if err := source.actor.Guard(ctx); err != nil {
		return err
	}
	if !time.Now().Before(source.grant.ExpiresAt()) {
		return ErrMaterialSource
	}
	if err := bootstrapmaterial.GuardPublication(ctx); err != nil {
		return err
	}
	if !time.Now().Before(source.grant.ExpiresAt()) {
		return ErrMaterialSource
	}
	return ctx.Err()
}

func (source *ColdStartMaterial) authorize(ctx context.Context) error {
	if err := source.guard(ctx); err != nil {
		return err
	}
	if source.link != nil && source.link.recipient != nil {
		if err := source.link.verify(ctx); err != nil {
			return err
		}
		return source.actor.AuthorizeLinkObject(ctx, *source.link.recipient, source.key)
	}
	return source.actor.AuthorizeSourceObject(ctx, source.key)
}

func (source *ColdStartMaterial) guardPublication(ctx context.Context) error {
	state, etag, err := source.read(ctx)
	defer clear(state.Journal)
	if err != nil {
		return err
	}
	if etag != source.etag || state.Reference != source.state.Reference || state.Actor != source.state.Actor {
		return ErrMaterialSource
	}
	return source.guard(ctx)
}
