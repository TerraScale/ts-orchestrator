package rootoci

import "context"

func (client *Client) ReconcileVolumeBackups(ctx context.Context) (VolumeBackupReport, error) {
	var report VolumeBackupReport
	err := client.invoke(ctx, OperationReconcileVolumeBackups, struct{}{}, &report)
	return report, err
}
