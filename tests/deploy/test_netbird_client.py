import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("netbird_client", ROOT / "deploy/netbird/client.py")
CLIENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLIENT)
INSTALLER = ROOT / "deploy/netbird/install-client.py"


def elf(architecture: str = "arm64", body: bytes = b"test NetBird") -> bytes:
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", header, 16, 2)
    struct.pack_into("<H", header, 18, {"arm64": 183, "amd64": 62}[architecture])
    struct.pack_into("<I", header, 20, 1)
    struct.pack_into("<H", header, 52, 64)
    return bytes(header) + body


class NetBirdClientTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="ts-netbird-client-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive = self.root / "upstream.tar.gz"
        self.binary = elf()
        self.make_archive()
        self.pin = json.loads((ROOT / "deploy/image/image-inputs.json").read_text())["netbird"]
        self.pin["archives"]["arm64"].update({
            "bytes": self.archive.stat().st_size, "sha256": CLIENT.sha256(self.archive),
            "binary_sha256": hashlib.sha256(self.binary).hexdigest(),
        })
        self.output = self.root / "result/netbird"
        self.cache = self.root / "cache"

    def make_archive(self, binary_kind: bytes = tarfile.REGTYPE, duplicate: bool = False) -> None:
        with tarfile.open(self.archive, "w:gz") as archive:
            traversal = tarfile.TarInfo("../../escape")
            traversal.size = 4
            archive.addfile(traversal, io.BytesIO(b"evil"))
            member = tarfile.TarInfo("netbird")
            member.type = binary_kind
            member.linkname = "../../escape" if binary_kind != tarfile.REGTYPE else ""
            member.size = len(self.binary) if binary_kind == tarfile.REGTYPE else 0
            archive.addfile(member, io.BytesIO(self.binary) if member.size else None)
            if duplicate:
                archive.addfile(member, io.BytesIO(self.binary))

    def response(self, payload: bytes | None = None):
        return io.BytesIO(self.archive.read_bytes() if payload is None else payload)

    def test_fetch_checks_archive_and_installs_only_binary(self) -> None:
        with patch.object(CLIENT.urllib.request, "urlopen", return_value=self.response()) as request:
            CLIENT.fetch(self.pin, "arm64", self.output, self.cache)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(self.output.read_bytes(), self.binary)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o755)
        self.assertFalse((self.root / "escape").exists())
        self.assertEqual((self.cache / self.pin["archives"]["arm64"]["sha256"]).read_bytes(), self.archive.read_bytes())

    def test_verified_cache_reuses_download_but_rechecks_bytes(self) -> None:
        self.cache.mkdir()
        cached = self.cache / self.pin["archives"]["arm64"]["sha256"]
        cached.write_bytes(self.archive.read_bytes())
        with patch.object(CLIENT.urllib.request, "urlopen", side_effect=AssertionError("unexpected download")):
            CLIENT.fetch(self.pin, "arm64", self.output, self.cache)
        cached.write_bytes(b"corrupt cached archive")
        with patch.object(CLIENT.urllib.request, "urlopen", return_value=self.response()) as request:
            CLIENT.fetch(self.pin, "arm64", self.output, self.cache)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(self.output.read_bytes(), self.binary)

    def test_wrong_archive_digest_cannot_replace_existing_client(self) -> None:
        self.output.parent.mkdir()
        self.output.write_bytes(b"existing client")
        corrupt = bytearray(self.archive.read_bytes())
        corrupt[-1] ^= 1
        with patch.object(CLIENT.urllib.request, "urlopen", return_value=self.response(bytes(corrupt))):
            with self.assertRaisesRegex(ValueError, "pinned SHA-256"):
                CLIENT.fetch(self.pin, "arm64", self.output, self.cache)
        self.assertEqual(self.output.read_bytes(), b"existing client")
        self.assertFalse(self.cache.exists())

    def test_archive_links_and_duplicate_binaries_are_rejected(self) -> None:
        for kind, duplicate in ((tarfile.SYMTYPE, False), (tarfile.LNKTYPE, False), (tarfile.REGTYPE, True)):
            with self.subTest(kind=kind, duplicate=duplicate):
                self.make_archive(kind, duplicate)
                self.pin["archives"]["arm64"].update({"bytes": self.archive.stat().st_size, "sha256": CLIENT.sha256(self.archive)})
                with patch.object(CLIENT.urllib.request, "urlopen", return_value=self.response()):
                    with self.assertRaisesRegex(ValueError, "one regular root-level"):
                        CLIENT.fetch(self.pin, "arm64", self.output)
                self.assertFalse(self.output.exists())

    def test_extracted_binary_digest_and_architecture_are_checked(self) -> None:
        for digest, architecture, message in (("0" * 64, "arm64", "pinned SHA-256"),
                                               (hashlib.sha256(self.binary).hexdigest(), "amd64", "amd64 executable")):
            with self.subTest(digest=digest, architecture=architecture):
                destination = self.root / "binary"
                pin = dict(self.pin["archives"]["arm64"], binary_sha256=digest)
                with self.assertRaisesRegex(ValueError, message):
                    CLIENT.extract(self.archive, destination, pin, architecture)
                destination.unlink(missing_ok=True)

    def test_additive_installer_preserves_orchestrator_and_enables_both_services(self) -> None:
        stage = self.root / "server"
        (stage / "usr/local/bin").mkdir(parents=True)
        old_binary = stage / "usr/local/bin/terrascale-orchestrator"
        old_binary.write_bytes(b"currently running orchestrator")
        old_config = stage / "etc/terrascale-orchestrator/controller.json"
        old_config.parent.mkdir(parents=True)
        old_config.parent.chmod(0o700)
        old_config.write_bytes(b"existing controller configuration")
        client_binary = self.root / "client"
        client_binary.write_bytes(self.binary)
        enroll_binary = self.root / "enroll"
        enroll_binary.write_bytes(elf(body=b"new enrollment command"))
        config = self.root / "netbird.json"
        config.write_text(json.dumps({"management_url": "https://netbird.terrascale.tech",
                                      "management_ip": "10.250.10.155", "region": "sa-saopaulo-1",
                                      "setup_key_secret_id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.test"}))
        inputs = self.root / "inputs.json"
        inputs.write_text(json.dumps({"netbird": self.pin}))
        result = subprocess.run((sys.executable, str(INSTALLER), "--root", str(stage), "--architecture", "arm64",
                                 "--inputs", str(inputs), "--client-binary", str(client_binary),
                                 "--enroll-binary", str(enroll_binary), "--enroll-sha256", CLIENT.sha256(enroll_binary),
                                 "--config", str(config)), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(old_binary.read_bytes(), b"currently running orchestrator")
        self.assertEqual(old_config.read_bytes(), b"existing controller configuration")
        self.assertEqual(stat.S_IMODE(old_config.parent.stat().st_mode), 0o700)
        self.assertEqual((stage / "usr/local/bin/netbird").read_bytes(), self.binary)
        self.assertEqual((stage / "usr/local/lib/terrascale-orchestrator/netbird-enroll").read_bytes(), enroll_binary.read_bytes())
        for name in ("netbird.service", "terrascale-netbird-enroll.service"):
            self.assertTrue((stage / "etc/systemd/system/multi-user.target.wants" / name).is_symlink())
        override = (stage / "etc/systemd/system/terrascale-netbird-enroll.service.d/command.conf").read_text()
        self.assertIn("/usr/local/lib/terrascale-orchestrator/netbird-enroll netbird-enroll", override)
        self.assertEqual(stat.S_IMODE((stage / "var/lib/netbird").stat().st_mode), 0o700)

    def test_units_retry_and_do_not_gate_orchestrator_startup(self) -> None:
        daemon = (ROOT / "deploy/systemd/netbird.service").read_text()
        enrollment = (ROOT / "deploy/systemd/terrascale-netbird-enroll.service").read_text()
        self.assertIn("service run --config /var/lib/netbird/config.json --log-file console", daemon)
        self.assertIn("CAP_NET_ADMIN", daemon)
        self.assertIn("DeviceAllow=/dev/net/tun rw", daemon)
        self.assertIn("StateDirectoryMode=0700", daemon)
        self.assertIn("Restart=on-failure", enrollment)
        self.assertIn("StartLimitIntervalSec=0", enrollment)
        self.assertIn("TimeoutStartSec=180s", enrollment)
        self.assertIn("ConditionPathExists=/etc/terrascale-orchestrator/netbird.json", enrollment)
        self.assertIn("UnsetEnvironment=OCI_GO_SDK_DEBUG", enrollment)
        for role in ("controller", "host"):
            unit = (ROOT / f"deploy/systemd/terrascale-orchestrator-{role}.service").read_text()
            self.assertNotIn("netbird", unit)

    def test_public_config_rejects_foreign_origin_public_ip_and_wrong_secret_region(self) -> None:
        config = {"management_url": "https://netbird.terrascale.tech", "management_ip": "10.250.10.155",
                  "region": "sa-saopaulo-1", "setup_key_secret_id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.test"}
        path = self.root / "config.json"
        cases = (("management_url", "https://other.example"), ("management_ip", "8.8.8.8"),
                 ("management_ip", "127.0.0.1"), ("management_ip", "::ffff:10.250.10.155"),
                 ("setup_key_secret_id", "ocid1.vaultsecret.oc1.us-ashburn-1.test"),
                 ("setup_key_secret_id", "REQUIRED_SECRET_OCID"))
        for field, value in cases:
            with self.subTest(field=field, value=value):
                path.write_text(json.dumps(dict(config, **{field: value})))
                with self.assertRaises(ValueError):
                    CLIENT.validate_config(path)


if __name__ == "__main__":
    unittest.main()
