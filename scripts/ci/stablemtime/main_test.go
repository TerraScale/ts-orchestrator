package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", dir}, args...)...)
	command.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// checkout commits files into a fresh repository, the way CI's checkout
// leaves a clean tree whose every time is "now".
func checkout(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	gitIn(t, dir, "init", "--quiet")
	for path, data := range files {
		writeFile(t, filepath.Join(dir, path), data)
	}
	if err := os.Symlink("deploy/image/build.sh", filepath.Join(dir, "build")); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "--quiet", "-m", "fixture")
	return dir
}

func modTime(t *testing.T, path string) time.Time {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.ModTime().UTC()
}

func TestStampDerivesEveryTrackedTimeFromItsObject(t *testing.T) {
	files := map[string]string{"go.mod": "module fixture\n", "deploy/image/build.sh": "#!/bin/sh\n", "deploy/systemd/a.service": "[Unit]\n"}
	first, second := checkout(t, files), checkout(t, files)
	untracked := filepath.Join(first, "dist", "binary")
	writeFile(t, untracked, "built\n")
	before := modTime(t, untracked)
	for _, dir := range []string{first, second} {
		stamped, err := Stamp(dir)
		if err != nil {
			t.Fatal(err)
		}
		// The root, two directories under deploy plus deploy itself, three
		// files and the symlink.
		if stamped != 8 {
			t.Fatalf("stamped %d paths, want 8", stamped)
		}
	}
	for _, path := range []string{".", "deploy", "deploy/image", "deploy/image/build.sh", "deploy/systemd/a.service", "go.mod", "build"} {
		got, other := modTime(t, filepath.Join(first, path)), modTime(t, filepath.Join(second, path))
		if !got.Equal(other) {
			t.Errorf("%s: two checkouts of one tree got %v and %v", path, got, other)
		}
		if got.Year() < 1980 || got.Year() > 2014 {
			t.Errorf("%s: stamp %v is outside the window", path, got)
		}
		object := gitIn(t, first, "rev-parse", "HEAD:"+strings.TrimPrefix(path, "."))
		if want, err := Time(object); err != nil || !got.Equal(want) {
			t.Errorf("%s: stamp %v, want %v from object %s (%v)", path, got, want, object, err)
		}
	}
	if !modTime(t, untracked).Equal(before) {
		t.Error("an untracked file was stamped")
	}
	if modTime(t, filepath.Join(first, "build")).Equal(modTime(t, filepath.Join(first, "deploy/image/build.sh"))) {
		t.Error("the symlink was followed instead of stamped itself")
	}
}

func TestStampSeparatesChangedContent(t *testing.T) {
	old := checkout(t, map[string]string{"deploy/image/build.sh": "#!/bin/sh\necho a\n", "deploy/same": "same\n"})
	changed := checkout(t, map[string]string{"deploy/image/build.sh": "#!/bin/sh\necho b\n", "deploy/same": "same\n"})
	for _, dir := range []string{old, changed} {
		if _, err := Stamp(dir); err != nil {
			t.Fatal(err)
		}
	}
	// Same size, different content: only the time can tell them apart.
	for _, path := range []string{"deploy/image/build.sh", "deploy/image", "deploy", "."} {
		if modTime(t, filepath.Join(old, path)).Equal(modTime(t, filepath.Join(changed, path))) {
			t.Errorf("%s kept its stamp although its content changed", path)
		}
	}
	if !modTime(t, filepath.Join(old, "deploy/same")).Equal(modTime(t, filepath.Join(changed, "deploy/same"))) {
		t.Error("unchanged file got a different stamp")
	}
}

func TestStampRefusesModifiedTrackedFiles(t *testing.T) {
	dir := checkout(t, map[string]string{"deploy/image/build.sh": "#!/bin/sh\n"})
	writeFile(t, filepath.Join(dir, "deploy/image/build.sh"), "#!/bin/sh\nexit 1\n")
	before := modTime(t, filepath.Join(dir, "deploy/image/build.sh"))
	if _, err := Stamp(dir); err == nil || !strings.Contains(err.Error(), "differ from HEAD") {
		t.Fatalf("stamped a modified checkout: %v", err)
	}
	if !modTime(t, filepath.Join(dir, "deploy/image/build.sh")).Equal(before) {
		t.Error("a refused stamp changed a file")
	}
}

func TestTimeRejectsMalformedObjectIDs(t *testing.T) {
	for _, object := range []string{"", "abc", "zz00000000000000", strings.Repeat("0", 14)} {
		if _, err := Time(object); err == nil {
			t.Errorf("accepted object id %q", object)
		}
	}
	at, err := Time(strings.Repeat("f", 40))
	if err != nil || at.After(time.Date(2014, 2, 1, 0, 0, 0, 0, time.UTC)) || at.Nanosecond() >= 1e9 {
		t.Fatalf("largest object id stamps %v, %v", at, err)
	}
}
