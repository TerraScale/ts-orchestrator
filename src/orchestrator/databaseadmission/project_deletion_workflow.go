package databaseadmission

import "context"

type ProjectFenceJournal interface {
	LoadProjectDeletion(context.Context, string) (ProjectDeletion, bool, error)
	LoadProjectFenceReceipt(context.Context, ProjectDeletion, ProjectAdmissionTarget) (HostFenceReceipt, bool, error)
	RecordProjectFenceReceipt(context.Context, ProjectDeletion, ProjectAdmissionTarget, HostFenceReceipt) error
}

type ProjectDeletionFenceWorkflow struct {
	Journal              ProjectFenceJournal
	Fencer               ProjectAdmissionFencer
	CheckEffectAuthority func(context.Context) error
}

// FencePlannedHosts advances only the host-fence phase. A receipt is progress
// evidence; it never marks a project deletion complete.
func (w *ProjectDeletionFenceWorkflow) FencePlannedHosts(ctx context.Context, project ProjectDeletion) error {
	if w == nil || w.Journal == nil || w.Fencer == nil || w.CheckEffectAuthority == nil || project.FenceRevision == 0 {
		return ErrInvalid
	}
	for _, database := range project.Targets {
		for _, target := range database.PlannedHosts {
			if err := w.CheckEffectAuthority(ctx); err != nil {
				return err
			}
			if _, found, err := w.Journal.LoadProjectFenceReceipt(ctx, project, target); err != nil {
				return err
			} else if found {
				continue
			}
			receipt, err := w.Fencer.FenceProjectAdmission(ctx, project, target)
			if err != nil {
				return err
			}
			if err := w.Journal.RecordProjectFenceReceipt(ctx, project, target, receipt); err != nil {
				return err
			}
		}
	}
	return nil
}
