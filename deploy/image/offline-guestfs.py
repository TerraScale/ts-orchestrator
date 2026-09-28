#!/usr/bin/env python3
"""Complete a TerraScale image with filesystem-only libguestfs operations."""

import argparse
import hashlib
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile


BOOTSTRAP = "/etc/terrascale-orchestrator/bootstrap"
APP = "/etc/terrascale-orchestrator"
APP_LIB = "/usr/local/lib/terrascale-orchestrator"
NATIVE = "/usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server"
TIME_CONFIG = "/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf"
TIME_DROPIN = "/etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf"
PROFILE = APP + "/runtime-priority.json"
HELPER = "/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py"
VOLUME_INIT_STATE = "/var/lib/terrascale-orchestrator-volume-init"
DROPINS = (
    "/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf",
    "/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf",
    "/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf",
)
UNITS = (
    "systemd-timesyncd.service",
    "systemd-time-wait-sync.service",
    "terrascale-orchestrator-controller.service",
    "terrascale-orchestrator-host.service",
)
HOST_UNITS = (
    "terrascale-orchestrator-host-setup.service",
    "terrascale-orchestrator-host-setup.timer",
    "terrascale-orchestrator-host-volume-init.socket",
)
HOST_UNIT_FILES = (
    *HOST_UNITS,
    "terrascale-orchestrator-host-volume-init.service",
)
HOST_VOLUME_PACKAGES = {
    "e2fsprogs": "1.47.0-2.4~exp1ubuntu4.1",
    "util-linux": "2.39.3-9ubuntu6.6",
}
HOST_VOLUME_TOOLS = (
    "/usr/sbin/mkfs.ext4",
    "/usr/sbin/blkid",
    "/usr/sbin/wipefs",
    "/usr/bin/mount",
)


def run(*args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(args, env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args[:2])} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


class Guest:
    def __init__(self, image: str):
        # --listen keeps one appliance alive. Neither inspection nor mutation runs guest code.
        # The persistent guestfish child can inherit stderr. A captured stderr pipe
        # would keep subprocess.run waiting for EOF after the launcher exits.
        self.errors = tempfile.TemporaryFile(mode="w+b")
        try:
            result = subprocess.run(
                ("guestfish", "--listen", "--format=qcow2", "-a", image, "-i"),
                stdout=subprocess.PIPE, stderr=self.errors, text=True, check=False,
            )
            if result.returncode:
                raise RuntimeError(
                    f"guestfish --listen failed: {self.error_tail() or result.stdout.strip()}"
                )
            output = result.stdout.strip()
            match = re.search(r"\bGUESTFISH_PID=(\d+)\b", output)
            if not match:
                raise RuntimeError(f"guestfish did not return a remote PID: {output}; stderr: {self.error_tail()}")
            self.pid = int(match.group(1))
            self.env = dict(os.environ, GUESTFISH_PID=match.group(1))
        except BaseException:
            self.errors.close()
            raise

    def error_tail(self) -> str:
        descriptor = self.errors.fileno()
        size = os.fstat(descriptor).st_size
        return os.pread(descriptor, min(size, 16384), max(0, size - 16384)).decode(
            "utf-8", errors="replace"
        ).strip()

    def daemon_state(self) -> str:
        try:
            return Path(f"/proc/{self.pid}/stat").read_text().rsplit(")", 1)[1].strip().split()[0]
        except (OSError, IndexError):
            return "exited"

    def call(self, command: str, *args: str) -> str:
        try:
            return run("guestfish", "--remote", command, *args, env=self.env)
        except RuntimeError as error:
            raise RuntimeError(
                f"{error}; guestfish listener pid={self.pid} state={self.daemon_state()}; "
                f"listener stderr: {self.error_tail() or '(empty)'}"
            ) from error

    def close(self, *, ignore_remote_error: bool = False) -> None:
        try:
            self.call("exit")
        except RuntimeError:
            if not ignore_remote_error:
                raise
        finally:
            self.errors.close()

    def kind(self, path: str) -> str | None:
        # A failed lstatns can terminate a guestfish remote listener. Probe
        # absence with commands that return booleans, including dangling links.
        exists = self.call("exists", path)
        if exists == "false":
            symlink = self.call("is-symlink", path)
            if symlink == "true":
                return "symlink"
            if symlink == "false":
                return None
            raise RuntimeError(f"guestfish returned an invalid is-symlink result for {path}: {symlink}")
        if exists != "true":
            raise RuntimeError(f"guestfish returned an invalid exists result for {path}: {exists}")
        mode = self.metadata(path)["st_mode"]
        if stat.S_ISLNK(mode):
            return "symlink"
        if stat.S_ISDIR(mode):
            return "dir"
        if stat.S_ISREG(mode):
            return "file"
        return "other"

    def metadata(self, path: str) -> dict[str, int]:
        fields = {}
        for line in self.call("lstatns", path).splitlines():
            key, _, value = line.partition(":")
            if key.startswith("st_"):
                fields[key] = int(value.strip())
        for key in ("st_mode", "st_uid", "st_gid", "st_nlink"):
            if key not in fields:
                raise RuntimeError(f"guestfish omitted {key} for {path}")
        return fields

    def read(self, path: str, target: Path) -> bytes:
        self.call("download", path, str(target))
        return target.read_bytes()

    def list(self, path: str) -> list[str]:
        kind = self.kind(path)
        if kind is None:
            return []
        if kind != "dir":
            raise RuntimeError(f"expected guest directory: {path}")
        names = self.call("ls", path).splitlines()
        if any(name in ("", ".", "..") or "/" in name for name in names):
            raise RuntimeError(f"unsafe directory entry under {path}")
        return names

    def assert_absent(self, path: str, label: str) -> None:
        if self.kind(path) is not None:
            raise RuntimeError(f"base image has a conflicting {label}: {path}")

    def assert_direct_parents(self, path: str) -> None:
        parent = Path(path).parent
        for directory in (*reversed(parent.parents), parent):
            kind = self.kind(str(directory))
            if kind != "dir":
                raise RuntimeError(f"guest artifact parent is not a direct directory: {directory}")

    def directory(self, path: str, uid: int = 0, gid: int = 0, mode: int = 0o755) -> None:
        for parent in (*reversed(Path(path).parent.parents), Path(path).parent):
            kind = self.kind(str(parent))
            if kind is not None and kind != "dir":
                raise RuntimeError(f"guest directory parent is not a direct directory: {parent}")
        kind = self.kind(path)
        if kind is not None and kind != "dir":
            raise RuntimeError(f"guest directory is not a direct directory: {path}")
        if kind is None:
            self.call("mkdir-p", path)
        self.assert_direct_parents(path)
        self.call("chown", str(uid), str(gid), path)
        self.call("chmod", f"0{mode:o}", path)

    def upload(self, source: Path, path: str, mode: int = 0o644) -> None:
        self.assert_direct_parents(path)
        self.assert_absent(path, "image artifact")
        self.call("upload", str(source), path)
        self.call("chown", "0", "0", path)
        self.call("chmod", f"0{mode:o}", path)
        self.assert_file(path, 0, 0, mode)
        self.assert_bytes(path, source)

    def assert_bytes(self, path: str, source: Path) -> None:
        with tempfile.TemporaryDirectory(prefix="ts-image-readback-") as directory:
            readback = Path(directory) / "readback"
            self.call("download", path, str(readback))
            if readback.stat().st_size != source.stat().st_size or file_sha256(readback) != file_sha256(source):
                raise RuntimeError(f"installed image bytes differ from staged input: {path}")

    def assert_file(self, path: str, uid: int, gid: int, mode: int, links: int = 1) -> None:
        if self.kind(path) != "file":
            raise RuntimeError(f"installed image path is not a regular file: {path}")
        meta = self.metadata(path)
        if (meta["st_uid"], meta["st_gid"], stat.S_IMODE(meta["st_mode"]), meta["st_nlink"]) != (uid, gid, mode, links):
            raise RuntimeError(f"installed image file has unexpected metadata: {path}")


def require_direct_parents(guest: Guest, path: str) -> None:
    for parent in ("/", "/usr", "/usr/local", "/usr/local/lib", APP_LIB):
        kind = guest.kind(parent)
        if kind is None and parent == APP_LIB:
            continue
        if kind != "dir":
            raise RuntimeError(
                f"native verifier parent must be a root-owned nonwritable directory: "
                f"{parent} (kind={kind or 'absent'})"
            )
        meta = guest.metadata(parent)
        if meta["st_uid"] != 0 or stat.S_IMODE(meta["st_mode"]) & 0o022:
            raise RuntimeError(
                f"native verifier parent must be a root-owned nonwritable directory: {parent} "
                f"(uid={meta['st_uid']} gid={meta['st_gid']} mode=0{stat.S_IMODE(meta['st_mode']):o})"
            )
    guest.assert_absent(path, "managed-material verifier directory")


def file_sha256(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.digest()


def audit_systemd_version(guest: Guest, work: Path) -> None:
    status = guest.read("/var/lib/dpkg/status", work / "base-dpkg-status").decode("utf-8")
    packages = [dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
                for block in status.split("\n\n")]
    versions = [package.get("Version") for package in packages if package.get("Package") == "systemd"]
    if len(versions) != 1 or not versions[0].startswith("255."):
        raise RuntimeError("base image must contain the audited Noble systemd 255 package")
    host = run("systemctl", "--version").splitlines()[0]
    print(f"offline unit enablement: guest systemd={versions[0]} host tool={host}")


def audit_host_volume_tools(guest: Guest, work: Path) -> None:
    status = guest.read("/var/lib/dpkg/status", work / "volume-tools-dpkg-status").decode("utf-8")
    packages = [dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
                for block in status.split("\n\n")]
    for name, version in HOST_VOLUME_PACKAGES.items():
        installed = [package for package in packages
                     if package.get("Package") == name and package.get("Status") == "install ok installed"]
        if len(installed) != 1 or installed[0].get("Version") != version:
            observed = ", ".join(package.get("Version", "unknown") for package in installed) or "absent"
            raise RuntimeError(
                f"host base image must contain pinned {name} {version} (observed {observed})"
            )
    for path in HOST_VOLUME_TOOLS:
        current = path
        visited = set()
        for _ in range(40):
            if current in visited:
                raise RuntimeError(f"host base image volume tool has a symlink loop: {path}")
            visited.add(current)
            kind = guest.kind(current)
            if kind == "file":
                mode = guest.metadata(current)["st_mode"]
                if not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                    raise RuntimeError(f"host base image volume tool is not executable: {path}")
                break
            if kind != "symlink":
                raise RuntimeError(f"host base image is missing required volume tool: {path}")
            target = guest.call("readlink", current)
            if not target or "\x00" in target:
                raise RuntimeError(f"host base image volume tool has an invalid symlink: {path}")
            resolved = target if target.startswith("/") else posixpath.join(posixpath.dirname(current), target)
            current = posixpath.normpath(resolved)
            if not current.startswith("/") or current == "/" or current.startswith("/../"):
                raise RuntimeError(f"host base image volume tool escapes its root: {path}")
        else:
            raise RuntimeError(f"host base image volume tool has too many symlinks: {path}")
    print("offline host volume tools verified packages=e2fsprogs,util-linux tools=" + ",".join(HOST_VOLUME_TOOLS))


def active_time_setting(data: bytes) -> bool:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError(f"could not inspect systemd timesyncd config: {error}") from error
    section = ""
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line[1:].split("]", 1)[0].strip()
        elif section == "Time" and re.match(
            r"^(?:NTP|FallbackNTP|PollIntervalMinSec|PollIntervalMaxSec)\s*=", line
        ):
            return True
    return False


def audit_time_config(guest: Guest, work: Path) -> None:
    main = "/etc/systemd/timesyncd.conf"
    if guest.kind(main) is None:
        main = "/usr/lib/systemd/timesyncd.conf"
    candidates = [main] if guest.kind(main) is not None else []
    seen = set()
    for directory in (
        "/etc/systemd/timesyncd.conf.d", "/run/systemd/timesyncd.conf.d",
        "/usr/local/lib/systemd/timesyncd.conf.d", "/usr/lib/systemd/timesyncd.conf.d",
    ):
        for name in sorted(guest.list(directory)):
            if not name.endswith(".conf") or name in seen:
                continue
            seen.add(name)
            candidates.append(f"{directory}/{name}")
    for index, path in enumerate(candidates):
        if guest.kind(path) == "symlink" and guest.call("readlink", path) == "/dev/null":
            continue
        try:
            data = guest.read(path, work / f"timesyncd-base-{index}.conf")
        except RuntimeError as error:
            raise RuntimeError(f"unresolvable systemd timesyncd config symlink: {path}") from error
        if active_time_setting(data):
            raise RuntimeError(f"base image has active NTP/FallbackNTP or poll interval configuration: {path}")
    guest.assert_absent(TIME_CONFIG, "timesyncd config")


def accounts(guest: Guest, work: Path, config: Path) -> tuple[int, int, list[tuple[Path, str, int]]]:
    root = work / "account-root"
    etc = root / "etc"
    (etc / "sysusers.d").mkdir(parents=True)
    account_files = []
    for name in ("passwd", "group", "shadow", "gshadow"):
        path = f"/etc/{name}"
        source = etc / name
        if guest.kind(path) != "file":
            raise RuntimeError(f"base image lacks regular {path}")
        mode = stat.S_IMODE(guest.metadata(path)["st_mode"])
        guest.read(path, source)
        account_files.append((source, path, mode))
    passwd = parse_accounts((etc / "passwd").read_text(), "passwd")
    groups = parse_accounts((etc / "group").read_text(), "group")
    if any(name in ("terrascale-workload", "2000") or number == 2000 for name, number in passwd + groups):
        raise RuntimeError("base image already uses the reserved managed workload UID, GID, or name")
    (etc / "sysusers.d/terrascale-orchestrator.conf").write_bytes(config.read_bytes())
    run("systemd-sysusers", f"--root={root}", str(etc / "sysusers.d/terrascale-orchestrator.conf"))
    passwd = dict(parse_accounts((etc / "passwd").read_text(), "passwd"))
    groups = dict(parse_accounts((etc / "group").read_text(), "group"))
    if passwd.get("terrascale-workload") != 2000 or groups.get("terrascale-workload") != 2000:
        raise RuntimeError("managed workload identity was not created as UID/GID 2000:2000")
    fields = next(line.split(":") for line in (etc / "passwd").read_text().splitlines() if line.startswith("terrascale-workload:"))
    if int(fields[3]) != 2000 or "terrascale-orchestrator" not in passwd or "terrascale-orchestrator" not in groups:
        raise RuntimeError("orchestrator or managed workload account was not created")
    orchestrator = next(line.split(":") for line in (etc / "passwd").read_text().splitlines()
                        if line.startswith("terrascale-orchestrator:"))
    uid, gid = int(orchestrator[2]), int(orchestrator[3])
    if groups["terrascale-orchestrator"] != gid or uid in (0, 2000) or gid in (0, 2000):
        raise RuntimeError("orchestrator account has an invalid UID/GID or primary group")
    print(f"offline accounts: workload=2000:2000 orchestrator={uid}:{gid}")
    return uid, gid, account_files


def parse_accounts(data: str, kind: str) -> list[tuple[str, int]]:
    position = 2 if kind == "passwd" else 2
    result = []
    for line in data.splitlines():
        fields = line.split(":")
        if len(fields) < 4:
            raise RuntimeError(f"invalid base /etc/{kind} record")
        result.append((fields[0], int(fields[position])))
    return result


def install_links(guest: Guest, work: Path, source_root: Path, host: bool) -> None:
    stage = work / "systemd-root"
    (stage / "etc/systemd").mkdir(parents=True)
    (stage / "usr/lib/systemd").mkdir(parents=True)
    (stage / "lib").symlink_to("usr/lib")
    guest.call("copy-out", "/etc/systemd/system", str(stage / "etc/systemd"))
    guest.call("copy-out", "/usr/lib/systemd/system", str(stage / "usr/lib/systemd"))
    etc_units = stage / "etc/systemd/system"
    for name in (
        "terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service",
        *(HOST_UNIT_FILES if host else ()),
    ):
        shutil.copyfile(source_root / "deploy/systemd" / name, etc_units / name)
    names = (*UNITS, *(HOST_UNITS if host else ()))
    files = (*names, *(tuple(name for name in HOST_UNIT_FILES if name not in names) if host else ()))
    for name in files:
        for directory in ("/run/systemd/system", "/usr/local/lib/systemd/system"):
            guest.assert_absent(f"{directory}/{name}", "systemd unit override")
    for name in files:
        unit = etc_units / name
        if unit.is_symlink() and os.readlink(unit) == "/dev/null":
            raise RuntimeError(f"required systemd unit is masked: {name}")
        if not unit.exists() and not (stage / "usr/lib/systemd/system" / name).exists():
            raise RuntimeError(f"missing a required systemd unit: {name}")
    expected = expected_install_links(stage, names)
    before = collect_links(etc_units)
    env = dict(os.environ, SYSTEMD_OFFLINE="1")
    run("systemctl", f"--root={stage}", "enable", *names, env=env)
    for name in names:
        state = run("systemctl", f"--root={stage}", "is-enabled", name, env=env)
        if state != "enabled":
            raise RuntimeError(f"required systemd unit is not enabled: {name} ({state})")
    after = collect_links(etc_units)
    if set(after) - set(before) != set(expected) - set(before):
        raise RuntimeError("host systemctl generated a different set of enablement links than guest unit [Install] metadata")
    for link, unit in expected.items():
        target = after.get(link)
        if target is None or resolve_link(link, target) != unit:
            raise RuntimeError(f"systemd enablement link does not point to its required unit: {link}")
    for link, target in after.items():
        if link in before:
            if before[link] != target:
                raise RuntimeError(f"systemctl changed a preexisting unit link: {link}")
            continue
        guest_path = "/etc/systemd/system/" + link
        guest.assert_absent(guest_path, "systemd enablement link")
        guest.directory(str(Path(guest_path).parent))
        guest.call("ln-s", target, guest_path)
    for link, target in after.items():
        if link not in expected:
            continue
        guest_path = "/etc/systemd/system/" + link
        if guest.kind(guest_path) != "symlink" or guest.call("readlink", guest_path) != target:
            raise RuntimeError(f"systemd enablement link readback differs: {guest_path}")
    print(f"offline systemd enablement links verified={len(expected)}")


def expected_install_links(stage: Path, names: tuple[str, ...]) -> dict[str, str]:
    expected = {}
    for name in names:
        etc = stage / "etc/systemd/system" / name
        vendor = stage / "usr/lib/systemd/system" / name
        unit = etc if etc.exists() else vendor
        if unit.is_symlink() or not unit.is_file():
            raise RuntimeError(f"required systemd unit is not a direct regular file: {name}")
        source = "/etc/systemd/system/" + name if unit == etc else "/usr/lib/systemd/system/" + name
        section = ""
        found = False
        for raw in unit.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1]
                continue
            if section != "Install":
                continue
            key, separator, value = line.partition("=")
            if not separator or key not in ("WantedBy", "RequiredBy", "Alias", "Also"):
                raise RuntimeError(f"unsupported systemd [Install] entry in {name}: {line}")
            if key == "Also":
                # Every unit requested by these files is named in the enable invocation.
                if any(other not in names for other in value.split()):
                    raise RuntimeError(f"unsupported systemd Also unit in {name}")
                continue
            for item in value.split():
                if not re.fullmatch(r"[A-Za-z0-9_.@:-]+", item):
                    raise RuntimeError(f"invalid systemd [Install] name in {name}: {item}")
                if key == "Alias":
                    link = item
                else:
                    relationship = {"WantedBy": "wants", "RequiredBy": "requires"}[key]
                    link = f"{item}.{relationship}/{name}"
                if link in expected and expected[link] != source:
                    raise RuntimeError(f"conflicting systemd enablement link: {link}")
                expected[link] = source
                found = True
        if not found:
            raise RuntimeError(f"required systemd unit has no enablement links: {name}")
    return expected


def resolve_link(link: str, target: str) -> str:
    if target.startswith("/"):
        resolved = os.path.normpath(target)
    else:
        resolved = os.path.normpath("/etc/systemd/system/" + os.path.dirname(link) + "/" + target)
    if resolved.startswith("/lib/systemd/system/"):
        resolved = "/usr" + resolved
    return resolved


def collect_links(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): os.readlink(path)
        for directory, dirs, files in os.walk(root, followlinks=False)
        for path in (Path(directory) / name for name in dirs + files)
        if path.is_symlink()
    }


def build(args: argparse.Namespace) -> None:
    work = Path(args.work)
    source_root = Path(__file__).resolve().parents[2]
    guest = Guest(args.image)
    try:
        # All checks precede writes, so a base collision cannot leave a plausible candidate.
        require_direct_parents(guest, str(Path(NATIVE).parent))
        audit_systemd_version(guest, work)
        audit_time_config(guest, work)
        if args.host_enrollment_public:
            audit_host_volume_tools(guest, work)
        for path in (PROFILE, HELPER, *DROPINS):
            guest.assert_absent(path, "runtime-priority profile artifact")
        guest.assert_absent(APP + "/host-enrollment-public.json", "host enrollment public bundle")
        for path in (
            BOOTSTRAP + "/anchor.json", BOOTSTRAP + "/identity.json",
            *(f"{BOOTSTRAP}/trust-roots/{index:03d}.pem" for index in range(1, len(args.bootstrap_root) + 1)),
        ):
            guest.assert_absent(path, "bootstrap artifact")
        if guest.list(BOOTSTRAP + "/trust-roots"):
            raise RuntimeError("base image has a conflicting bootstrap trust-root directory")
        for path in (
            "/var/lib/terrascale-orchestrator-bootstrap",
            "/var/lib/terrascale-orchestrator-secrets",
            "/var/lib/terrascale-orchestrator-controller",
        ):
            guest.assert_absent(path, "orchestrator state root")
        if args.host_enrollment_public:
            if guest.kind("/srv") != "dir":
                raise RuntimeError("base /srv must be a direct root:root 0755 directory")
            meta = guest.metadata("/srv")
            if (meta["st_uid"], meta["st_gid"], stat.S_IMODE(meta["st_mode"])) != (0, 0, 0o755):
                raise RuntimeError("base /srv must be a direct root:root 0755 directory")
            guest.assert_absent("/srv/ts-managed", "managed root")
            guest.assert_absent(VOLUME_INIT_STATE, "managed volume initialization state root")
        orchestrator_uid, orchestrator_gid, account_files = accounts(guest, work, Path(args.sysusers))

        directories = (
            APP, BOOTSTRAP, BOOTSTRAP + "/trust-roots", "/etc/sysusers.d",
            "/etc/systemd", "/etc/systemd/system", "/etc/systemd/timesyncd.conf.d",
            "/etc/systemd/system/system.slice.d", "/etc/systemd/system/terrascale-orchestrator-host.service.d",
            "/etc/systemd/system/terrascale-orchestrator-controller.service.d",
            str(Path(TIME_DROPIN).parent), "/usr/local/bin", str(Path(HELPER).parent),
            str(Path(NATIVE).parent),
            "/var/lib/terrascale-orchestrator-bootstrap",
        )
        if guest.kind(APP_LIB) is None:
            guest.directory(APP_LIB)
            meta = guest.metadata(APP_LIB)
            if (guest.kind(APP_LIB), meta["st_uid"], meta["st_gid"], stat.S_IMODE(meta["st_mode"])) != (
                "dir", 0, 0, 0o755,
            ):
                raise RuntimeError(f"installed application library parent has unexpected metadata: {APP_LIB}")
        for directory in directories:
            guest.directory(directory)
        guest.directory("/var/lib/terrascale-orchestrator-secrets", orchestrator_uid, orchestrator_gid, 0o700)
        guest.directory("/var/lib/terrascale-orchestrator-controller", orchestrator_uid, orchestrator_gid, 0o700)
        if args.host_enrollment_public:
            guest.directory("/srv/ts-managed", 0, 2000, 0o750)
            guest.directory(VOLUME_INIT_STATE, 0, 0, 0o700)

        uploads = [
            (Path(args.sysusers), "/etc/sysusers.d/terrascale-orchestrator.conf", 0o644),
            *((source_root / "deploy/systemd" / name, "/etc/systemd/system/" + name, 0o644)
              for name in (
                  "terrascale-orchestrator-bootstrap.service", "terrascale-orchestrator-controller-install.service",
                  "terrascale-orchestrator-controller.service", "terrascale-orchestrator-host.service",
                  *(HOST_UNIT_FILES if args.host_enrollment_public else ()),
              )),
            (Path(args.profile), PROFILE, 0o644),
            *((Path(args.priority_root) / path.lstrip("/"), path, 0o644) for path in DROPINS),
            (source_root / "tests/runtime_priority/qualify.py", HELPER, 0o755),
            (Path(args.binary), "/usr/local/bin/terrascale-orchestrator", 0o755),
            (Path(args.native_verifier), NATIVE, 0o755),
            (Path(args.timesyncd_config), TIME_CONFIG, 0o644),
            (Path(args.bootstrap_anchor), BOOTSTRAP + "/anchor.json", 0o444),
            (Path(args.bootstrap_identity), BOOTSTRAP + "/identity.json", 0o444),
            *((Path(path), f"{BOOTSTRAP}/trust-roots/{index:03d}.pem", 0o444)
              for index, path in enumerate(args.bootstrap_root, 1)),
        ]
        if args.host_enrollment_public:
            uploads.append((Path(args.host_enrollment_public), APP + "/host-enrollment-public.json", 0o444))
        timeout = work / "terrascale-timeout.conf"
        timeout.write_text("[Service]\nTimeoutStartSec=300s\n", encoding="ascii")
        uploads.append((timeout, TIME_DROPIN, 0o644))
        for source, destination, mode in uploads:
            guest.upload(source, destination, mode)
        for source, destination, mode in account_files:
            guest.call("upload", str(source), destination)
            guest.call("chown", "0", "0", destination)
            guest.call("chmod", f"0{mode:o}", destination)
            guest.assert_file(destination, 0, 0, mode)
            guest.assert_bytes(destination, source)
        install_links(guest, work, source_root, bool(args.host_enrollment_public))
        if args.host_enrollment_public:
            meta = guest.metadata("/srv/ts-managed")
            if (meta["st_uid"], meta["st_gid"], stat.S_IMODE(meta["st_mode"])) != (0, 2000, 0o750):
                raise RuntimeError("installed managed root has unexpected metadata")
        guest.assert_file(NATIVE, 0, 0, 0o755)
    finally:
        guest.close(ignore_remote_error=sys.exc_info()[0] is not None)


def main() -> None:
    parser = argparse.ArgumentParser()
    for option in (
        "image", "work", "sysusers", "profile", "priority-root", "binary", "native-verifier",
        "timesyncd-config", "bootstrap-anchor", "bootstrap-identity",
    ):
        parser.add_argument("--" + option, required=True)
    parser.add_argument("--bootstrap-root", action="append", required=True)
    parser.add_argument("--host-enrollment-public")
    args = parser.parse_args()
    try:
        build(args)
    except RuntimeError as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
