package vmqual

import "testing"

func TestUnifiedCgroupPath(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		want string
	}{
		{name: "root", data: "0::/\n", want: "/"},
		{name: "nested", data: "12:cpu:/legacy\n0::/user.slice/user-1000.slice/session.scope\n", want: "/user.slice/user-1000.slice/session.scope"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := unifiedCgroupPath(test.data)
			if err != nil || got != test.want {
				t.Fatalf("unifiedCgroupPath() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	for _, data := range []string{"0:cpu:/x\n", "0::../escape\n", "0::/a/../b\n", "0::/a//b\n"} {
		if _, err := unifiedCgroupPath(data); err == nil {
			t.Fatalf("unifiedCgroupPath(%q) accepted unsafe or absent path", data)
		}
	}
}

func TestUnifiedCgroupMount(t *testing.T) {
	data := "36 29 0:32 / /run/cgroup2 rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n"
	if got, err := unifiedCgroupMount(data); err != nil || got != "/run/cgroup2" {
		t.Fatalf("unifiedCgroupMount() = %q, %v", got, err)
	}
	data = "36 29 0:32 / /run/cgroup\\040v2 rw - cgroup2 cgroup rw\n"
	if got, err := unifiedCgroupMount(data); err != nil || got != "/run/cgroup v2" {
		t.Fatalf("escaped unifiedCgroupMount() = %q, %v", got, err)
	}
	if _, err := unifiedCgroupMount("36 29 0:32 / /run/cgroup2 rw - tmpfs tmpfs rw\n"); err == nil {
		t.Fatal("non-cgroup2 mount accepted")
	}
}

func TestCgroupSubtreeRejectsTraversal(t *testing.T) {
	if got, err := cgroupSubtree("/run/cgroup2", "/user.slice/worker.scope"); err != nil || got != "/run/cgroup2/user.slice/worker.scope" {
		t.Fatalf("cgroupSubtree() = %q, %v", got, err)
	}
	for _, mount := range []string{"relative", "/run/cgroup2/.."} {
		if _, err := cgroupSubtree(mount, "/worker.scope"); err == nil {
			t.Fatalf("cgroupSubtree(%q) accepted unsafe mount", mount)
		}
	}
	for _, cgroup := range []string{"relative", "/../escape", "/worker/../escape"} {
		if _, err := cgroupSubtree("/run/cgroup2", cgroup); err == nil {
			t.Fatalf("cgroupSubtree(%q) accepted unsafe cgroup", cgroup)
		}
	}
}
