package region

func netBirdOriginalBinding(launch NetBirdManagerLaunch) NetBirdManagerBinding {
	return NetBirdManagerBinding{InstanceID: launch.InstanceID, BootVolumeID: launch.BootVolumeID, RecipeSHA256: launch.RecipeSHA256, PhysicalScopeSHA256: launch.PhysicalScopeSHA256}
}
