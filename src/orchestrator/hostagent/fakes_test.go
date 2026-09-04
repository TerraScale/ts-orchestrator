package hostagent

import (
	"context"
	"sync"
)

// fakeSystemd is the recording fake of SystemdController: it tracks the
// active set and every operation in order, so lifecycle tests assert the
// exact systemctl choreography without a live systemd.
type fakeSystemd struct {
	mutex      sync.Mutex
	active     map[string]bool
	operations []string
	// failOn makes one named operation fail: "stop", "start", "restart",
	// "daemon-reload", "enable".
	failOn map[string]string
}

func newFakeSystemd(active ...string) *fakeSystemd {
	activeSet := make(map[string]bool, len(active))
	for _, unit := range active {
		activeSet[unit] = true
	}
	return &fakeSystemd{active: activeSet, failOn: map[string]string{}}
}

func (f *fakeSystemd) record(operation, unit string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.operations = append(f.operations, operation+":"+unit)
	if failing, present := f.failOn[operation]; present && failing == unit {
		return &InvalidOperationError{Message: "injected failure: " + operation}
	}
	return nil
}

func (f *fakeSystemd) DaemonReload(ctx context.Context) error {
	return f.record("daemon-reload", "")
}

func (f *fakeSystemd) EnableUnit(ctx context.Context, unit string) error {
	return f.record("enable", unit)
}

func (f *fakeSystemd) DisableUnit(ctx context.Context, unit string) error {
	return f.record("disable", unit)
}

func (f *fakeSystemd) StartUnit(ctx context.Context, unit string) error {
	if err := f.record("start", unit); err != nil {
		return err
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.active[unit] = true
	return nil
}

func (f *fakeSystemd) StopUnit(ctx context.Context, unit string) error {
	if err := f.record("stop", unit); err != nil {
		return err
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.active[unit] = false
	return nil
}

func (f *fakeSystemd) RestartUnit(ctx context.Context, unit string) error {
	if err := f.record("restart", unit); err != nil {
		return err
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.active[unit] = true
	return nil
}

func (f *fakeSystemd) UnitActive(ctx context.Context, unit string) (bool, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.active[unit], nil
}

func (f *fakeSystemd) ops() []string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return append([]string(nil), f.operations...)
}

// isActive reports one unit's activity under the fake's lock.
func (f *fakeSystemd) isActive(unit string) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.active[unit]
}

// fakeUsers is the recording fake of UserProvisioner.
type fakeUsers struct {
	mutex   sync.Mutex
	ensured map[string]int
	owned   map[string]string
}

func newFakeUsers() *fakeUsers {
	return &fakeUsers{ensured: map[string]int{}, owned: map[string]string{}}
}

func (f *fakeUsers) EnsureUser(ctx context.Context, user string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.ensured[user]++
	return nil
}

func (f *fakeUsers) OwnDirectory(ctx context.Context, user, path string) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.owned[user] = path
	return nil
}
