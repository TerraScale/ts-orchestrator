package runtimepriority

import (
	"time"
)

type MemoryValidation struct {
	Identity                                                     Object
	GuestRole, ServiceCgroup, BootID, SystemdVersion, CgroupRoot string
	NotBefore, NotAfter                                          time.Time
}
