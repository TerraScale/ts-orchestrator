package materialsource

import (
	"context"
	"time"
)

func (source *ColdStartMaterial) currentActor() materialSourceActor {
	return materialSourceActor{InstanceID: source.actor.InstanceID(), GrantDigest: source.actor.GrantDigest(), TemplateDigest: source.actor.TemplateDigest()}
}

func (source *ColdStartMaterial) guard(ctx context.Context) error {
	if source == nil || source.actor == nil || !source.grant.IsVerified() || !time.Now().Before(source.grant.ExpiresAt()) || ctx.Err() != nil || source.actor.GrantDigest() != digestWire(source.grant.FoundationGrantWire()) {
		return ErrMaterialSource
	}
	proof := source.actor.Founder()
	if proof.InstallationID() != source.grant.InstallationID() || proof.Generation() != source.grant.Generation() || proof.StorageDomain() != source.grant.StorageDomain() {
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
	return source.actor.Guard(ctx)
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
