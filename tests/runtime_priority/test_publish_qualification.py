from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = "a" * 40
TREE = "b" * 40


class D15PublisherReadbackTests(unittest.TestCase):
    def run_publisher(self, *, permanently_wrong: bool) -> tuple[subprocess.CompletedProcess[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "scripts/ci").mkdir(parents=True)
        (root / "tests/runtime_priority").mkdir(parents=True)
        (root / "dist").mkdir()
        (root / "bin").mkdir()
        shutil.copy2(ROOT / "scripts/ci/publish-qualification.sh",
                     root / "scripts/ci/publish-qualification.sh")
        shutil.copy2(ROOT / "tests/runtime_priority/qualify.py",
                     root / "tests/runtime_priority/qualify.py")
        (root / "go.mod").write_text("module fixture\n", encoding="utf-8")
        (root / "go.sum").write_text("fixture\n", encoding="utf-8")
        for architecture in ("amd64", "arm64"):
            (root / f"dist/terrascale-orchestrator-linux-{architecture}").write_bytes(
                f"fixture {architecture}\n".encode()
            )
        commands = {
            "git": '''#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'rev-parse HEAD') printf '%s\\n' "$GITHUB_SHA" ;;
  'rev-parse HEAD^{tree}') printf '%s\\n' "$FIXTURE_TREE" ;;
  *) exit 2 ;;
esac
''',
            "go": '''#!/usr/bin/env bash
[[ "$*" == 'env GOVERSION' ]] && printf 'go1.27.1\\n'
''',
            "sleep": "#!/usr/bin/env bash\nexit 0\n",
            "fj": '''#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == 'auth add-token' ]]; then
  cat >/dev/null
  exit 0
fi
if [[ "$1 $2" == 'release create' ]]; then
  printf 'release-created\\n' >> "$FAKE_FJ_EVENTS"
  exit 0
fi
if [[ "$1 $2 $3" == 'release asset download' ]]; then
  name=$5
  output=$7
  [[ ! -e $output ]] || exit 3
  count_file="$FAKE_FJ_STATE/$name.count"
  count=0
  [[ ! -f $count_file ]] || count=$(cat "$count_file")
  count=$((count + 1))
  printf '%s\\n' "$count" > "$count_file"
  if [[ $FAKE_FJ_PERMANENT == yes || ( $name == terrascale-d15-qualify.py && $count == 1 ) ]]; then
    printf 'transient wrong attachment body\\n' > "$output"
  else
    cp -- "$FAKE_REPO/dist/$name" "$output"
  fi
  exit 0
fi
if [[ "$1 $2 $3" == 'release asset create' ]]; then
  printf 'qualification-created\\n' >> "$FAKE_FJ_EVENTS"
  exit 0
fi
exit 4
''',
        }
        for name, source in commands.items():
            path = root / "bin" / name
            path.write_text(source, encoding="utf-8")
            path.chmod(0o755)
        env = os.environ.copy()
        env.update({
            "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_NUMBER": "7",
            "GITHUB_SHA": SOURCE, "FIXTURE_TREE": TREE,
            "FORGEJO_TOKEN": "fixture-token", "FORGEJO_SERVER_URL": "https://fixture.invalid",
            "FAKE_FJ_STATE": str(root), "FAKE_FJ_EVENTS": str(root / "events"),
            "FAKE_FJ_PERMANENT": "yes" if permanently_wrong else "no",
            "FAKE_REPO": str(root),
        })
        result = subprocess.run(
            ["bash", str(root / "scripts/ci/publish-qualification.sh")],
            cwd=root, env=env, text=True, capture_output=True, check=False, timeout=30,
        )
        return result, root

    def test_transient_wrong_fj_attachment_is_retried_on_fresh_path(self) -> None:
        result, root = self.run_publisher(permanently_wrong=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((root / "terrascale-d15-qualify.py.count").read_text(), "2\n")
        self.assertEqual((root / "terrascale-d15-probe.json.count").read_text(), "1\n")
        self.assertEqual((root / "events").read_text(), "release-created\nqualification-created\n")
        self.assertIn("TS_D15_PROBE_PUBLICATION_V1", result.stdout)

    def test_persistent_wrong_fj_attachment_never_publishes_completion_marker(self) -> None:
        result, root = self.run_publisher(permanently_wrong=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((root / "terrascale-d15-qualify.py.count").read_text(), "6\n")
        self.assertEqual((root / "events").read_text(), "release-created\n")
        self.assertNotIn("TS_D15_PROBE_PUBLICATION_V1", result.stdout)
        self.assertIn("never matched", result.stderr)


if __name__ == "__main__":
    unittest.main()
