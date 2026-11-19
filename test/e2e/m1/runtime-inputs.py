import argparse
import json
import platform
import re
import shlex
from pathlib import Path

repo = Path(__file__).resolve().parents[3]
image = repo / "deploy/image/debian"
base = json.loads((image / "base.json").read_text())
provision = (image / "provision.sh").read_text()
versions = {
    name: re.search(rf"^{name}_version=(\S+)$", provision, re.MULTILINE)[1]
    for name in ("containerd", "runc")
}


def replace_pin(pattern, value, text):
    result, count = re.subn(pattern, value, text, flags=re.MULTILINE | re.DOTALL)
    if count != 1:
        raise SystemExit(f"expected one deployment pin matching {pattern}")
    return result


parser = argparse.ArgumentParser()
parser.add_argument("--check", action="store_true")
parser.add_argument("--write", action="store_true")
args = parser.parse_args()
if args.check or args.write:
    path = repo / "deploy/m1/host-runtime.sh"
    original = path.read_text()
    updated = original
    for name, version in versions.items():
        updated = replace_pin(
            rf"^{name}_version=\S+$", f"{name}_version={version}", updated
        )
        for machine, arch in (("aarch64", "arm64"), ("x86_64", "amd64")):
            updated = replace_pin(
                rf"(^\s*{machine}\).*?\n\s*{name}_sha256=)[0-9a-f]+",
                rf"\g<1>{base[name + '_sha256'][arch]}",
                updated,
            )
    if args.write:
        path.write_text(updated)
    elif updated != original:
        raise SystemExit(
            "host-runtime.sh differs from the image pins: run python3 test/e2e/m1/runtime-inputs.py --write"
        )
    manager = (repo / "internal/netbird/manager/server_cli.go").read_text()
    if f'client.Pin{{Version: "{base["netbird"]["version"]}"}}' not in manager:
        raise SystemExit("NetBird manager version differs from the image")
    for arch, field in (("arm64", "Arm64"), ("amd64", "AMD64")):
        archive = re.search(
            rf"p.Archives.{field} = client.Archive{{(.*?)}}", manager, re.DOTALL
        )[1]
        for key, value in (
            ("URL", base["netbird"]["url"].replace("<arch>", arch)),
            ("SHA256", base["netbird"]["sha256"][arch]),
        ):
            if not re.search(
                rf"\b{key}: {re.escape(json.dumps(value))}(?:,|\s|$)", archive
            ):
                raise SystemExit(f"NetBird manager {arch} {key} differs from the image")
    print("host runtime pins match the Debian image")
else:
    arch = {"aarch64": "arm64", "x86_64": "amd64"}[platform.machine()]
    values = {
        "arch": arch,
        "containerd_version": versions["containerd"],
        "runc_version": versions["runc"],
        "containerd_sha256": base["containerd_sha256"][arch],
        "runc_sha256": base["runc_sha256"][arch],
        "netbird_version": base["netbird"]["version"],
        "netbird": base["netbird"]["url"].replace("<arch>", arch),
        "netbird_sha256": base["netbird"]["sha256"][arch],
    }
    print("\n".join(f"{key}={shlex.quote(value)}" for key, value in values.items()))
