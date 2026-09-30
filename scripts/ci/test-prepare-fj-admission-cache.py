#!/usr/bin/env python3
"""Exercise the optional final-fj cache without cloning or compiling fj."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
EXPECTED_BINARY_SHA256 = "2f6f4c0392ec8ad8a46ca1b96b856abf9b8a5583f044044e9776989eec51c4e4"
UPSTREAM_LOCK_SHA256 = "4de42ee153468f31e6f0f0062777fa684cc519a122e5e7139020428a9da72651"


def write_executable(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


class AdmissionCacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="fj-admission-cache-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        scripts = self.repo / "scripts" / "ci"
        scripts.mkdir(parents=True)
        shutil.copy2(SCRIPT_DIR / "fj-run-detail.patch", scripts / "fj-run-detail.patch")
        (scripts / "test-fj-attachment-probe.py").write_text("# mocked process fixture\n")

        self.lock = self.root / "Cargo.lock"
        self.lock.write_bytes(b"pinned fixture lock\n")
        self.binary = self.root / "fixture-fj"
        write_executable(
            self.binary,
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >> \"$MOCK_EXEC_LOG\"\n"
            "[[ $1 == actions && $3 == --help ]]\n",
        )
        self.binary_digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        source = (SCRIPT_DIR / "prepare-fj-admission.sh").read_text()
        source = source.replace(EXPECTED_BINARY_SHA256, self.binary_digest)
        source = source.replace(
            UPSTREAM_LOCK_SHA256, hashlib.sha256(self.lock.read_bytes()).hexdigest()
        )
        self.assertNotIn(EXPECTED_BINARY_SHA256, source)
        self.assertNotIn(UPSTREAM_LOCK_SHA256, source)
        self.script = scripts / "prepare-fj-admission.sh"
        self.script.write_text(source)

        self.mock_bin = self.root / "mock-bin"
        self.mock_bin.mkdir()
        write_executable(
            self.mock_bin / "fj",
            "#!/usr/bin/env bash\n"
            "[[ $* == 'repo clone -H https://codeberg.org forgejo-contrib/forgejo-cli '* ]] || exit 7\n"
            "printf 'clone\\n' >> \"$MOCK_BUILD_LOG\"\n"
            "destination=${!#}\n"
            "mkdir -p \"$destination\"\n"
            "cp \"$MOCK_LOCK\" \"$destination/Cargo.lock\"\n",
        )
        write_executable(
            self.mock_bin / "git",
            "#!/usr/bin/env bash\n"
            "if [[ $* == *'rev-parse HEAD' ]]; then\n"
            "  printf '%s\\n' '7f44ff1a1587a406b627ac45f0a2485b970c6379'\n"
            "fi\n",
        )
        write_executable(
            self.mock_bin / "nix",
            "#!/usr/bin/env bash\n"
            "case $1 in\n"
            "  flake) printf '%s\\n' '{\"locked\":{\"narHash\":\"sha256-ZKhUe/2IJUq1JhKxKMu8rbkgSGmPP2ZCqlIPn40aGCM=\"}}' ;;\n"
            "  eval) printf '%s\\n' '/mock/openssl-dev' ;;\n"
            "  shell)\n"
            "    while [[ $1 != --command ]]; do shift; done\n"
            "    shift\n"
            "    exec \"$@\" ;;\n"
            "  *) exit 8 ;;\n"
            "esac\n",
        )
        write_executable(
            self.mock_bin / "jq",
            "#!/usr/bin/env bash\n"
            "[[ $* == '-r .locked.narHash' ]] || exit 9\n"
            "printf '%s\\n' 'sha256-ZKhUe/2IJUq1JhKxKMu8rbkgSGmPP2ZCqlIPn40aGCM='\n",
        )
        write_executable(
            self.mock_bin / "rustup",
            "#!/usr/bin/env bash\n"
            "case $1 in\n"
            "  toolchain) printf 'toolchain\\n' >> \"$MOCK_BUILD_LOG\" ;;\n"
            "  run)\n"
            "    printf 'compile\\n' >> \"$MOCK_BUILD_LOG\"\n"
            "    mkdir -p \"$CARGO_TARGET_DIR/release\"\n"
            "    cp \"$MOCK_BINARY\" \"$CARGO_TARGET_DIR/release/fj\" ;;\n"
            "  *) exit 10 ;;\n"
            "esac\n",
        )
        write_executable(
            self.mock_bin / "python3",
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" >> \"$MOCK_PROBE_LOG\"\n",
        )
        self.build_log = self.root / "build.log"
        self.exec_log = self.root / "exec.log"
        self.probe_log = self.root / "probe.log"
        self.cache = self.root / "cache"
        runner_temp = self.root / "runner-temp"
        runner_temp.mkdir()
        self.environment = os.environ.copy()
        self.environment.update(
            {
                "PATH": f"{self.mock_bin}:{os.environ['PATH']}",
                "RUNNER_TEMP": str(runner_temp),
                "TS_FJ_ADMISSION_CACHE_DIR": str(self.cache),
                "MOCK_LOCK": str(self.lock),
                "MOCK_BINARY": str(self.binary),
                "MOCK_BUILD_LOG": str(self.build_log),
                "MOCK_EXEC_LOG": str(self.exec_log),
                "MOCK_PROBE_LOG": str(self.probe_log),
            }
        )

    def run_prepare(self, label: str) -> subprocess.CompletedProcess[str]:
        output = self.root / label
        result = subprocess.run(
            ["bash", str(self.script), str(output)],
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(hashlib.sha256((output / "fj").read_bytes()).hexdigest(), self.binary_digest)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        return result

    def test_miss_hit_and_tamper_fallback(self) -> None:
        miss = self.run_prepare("miss-output")
        self.assertIn("cache=build", miss.stdout)
        self.assertEqual(self.build_log.read_text().count("compile\n"), 1)
        cached = list(self.cache.glob("*/fj"))
        self.assertEqual(len(cached), 1)
        self.assertEqual(hashlib.sha256(cached[0].read_bytes()).hexdigest(), self.binary_digest)

        hit = self.run_prepare("hit-output")
        self.assertIn("cache=hit", hit.stdout)
        self.assertEqual(self.build_log.read_text().count("compile\n"), 1)
        self.assertEqual(len(self.probe_log.read_text().splitlines()), 2)
        self.assertEqual(len(self.exec_log.read_text().splitlines()), 6)

        write_executable(
            cached[0],
            "#!/usr/bin/env bash\n"
            f"printf 'tampered\\n' >> '{self.root / 'tamper-executed'}'\n",
        )
        tamper = self.run_prepare("tamper-output")
        self.assertIn("cache entry failed verification", tamper.stderr)
        self.assertIn("cache=build", tamper.stdout)
        self.assertEqual(self.build_log.read_text().count("compile\n"), 2)
        self.assertFalse((self.root / "tamper-executed").exists())
        self.assertEqual(hashlib.sha256(cached[0].read_bytes()).hexdigest(), self.binary_digest)
        self.assertEqual(len(self.probe_log.read_text().splitlines()), 3)

    def test_toolchain_identity_changes_cache_key(self) -> None:
        self.run_prepare("first-output")
        first_key = next(self.cache.iterdir()).name
        self.script.write_text(self.script.read_text().replace("rust_toolchain=1.98.1", "rust_toolchain=1.98.2"))
        changed = self.run_prepare("changed-output")
        self.assertIn("cache=build", changed.stdout)
        self.assertEqual(self.build_log.read_text().count("compile\n"), 2)
        self.assertEqual(len(list(self.cache.iterdir())), 2)
        self.assertIn(first_key, [path.name for path in self.cache.iterdir()])


if __name__ == "__main__":
    unittest.main()
