import argparse
import json
import platform
import re
import shlex
import subprocess
from pathlib import Path

repo = Path(__file__).resolve().parents[3]
image = repo / "deploy/image/debian"
base = json.loads((image / "base.json").read_text())
provision = (image / "provision.sh").read_text()
versions = {
    name: re.search(rf"^{name}_version=(\S+)$", provision, re.MULTILINE)[1]
    for name in ("containerd", "runc")
}


def pins(arch):
    return {
        "arch": arch,
        "containerd_version": versions["containerd"],
        "runc_version": versions["runc"],
        "containerd_sha256": base["containerd_sha256"][arch],
        "runc_sha256": base["runc_sha256"][arch],
        "netbird_version": base["netbird"]["version"],
        "netbird": base["netbird"]["url"].replace("<arch>", arch),
        "netbird_sha256": base["netbird"]["sha256"][arch],
        "netbird_binary_sha256": base["netbird"]["binary_sha256"][arch],
    }


def assignments(values):
    return "\n".join(f"{key}={shlex.quote(value)}" for key, value in values.items())


def generated():
    shell = ["case $(uname -m) in"]
    go = [
        'package manager\n\nimport "github.com/TerraScale/ts-orchestrator/internal/netbird/client"\n',
        "var clientPin = func() client.Pin {",
        f'\tp := client.Pin{{Version: "{base["netbird"]["version"]}"}}',
    ]
    for arch, machine, field in (
        ("arm64", "aarch64", "Arm64"),
        ("amd64", "x86_64", "AMD64"),
    ):
        values = pins(arch)
        shell += [f"{machine})", assignments(values), ";;"]
        go += [
            f"\tp.Archives.{field} = client.Archive{{URL: {json.dumps(values['netbird'])},",
            f'\t\tBytes: {base["netbird"]["bytes"][arch]}, SHA256: "{values["netbird_sha256"]}",',
            f'\t\tBinarySHA256: "{values["netbird_binary_sha256"]}"}}',
        ]
    shell += [
        '*) echo "host runtime pins support arm64 and amd64 only" >&2; exit 1 ;;',
        "esac",
    ]
    template = (repo / "deploy/m1/host-runtime.sh.in").read_text()
    if template.count("@runtime_pins@") != 1:
        raise SystemExit(
            "host-runtime.sh.in must contain exactly one runtime pin insertion"
        )
    go += ["\treturn p", "}()\n"]
    return {
        repo / "deploy/m1/host-runtime.sh": template.replace(
            "@runtime_pins@", "\n".join(shell)
        ),
        repo / "internal/netbird/manager/client_pin.go": subprocess.check_output(
            ["gofmt"], input="\n".join(go), text=True
        ),
    }


parser = argparse.ArgumentParser()
mode = parser.add_mutually_exclusive_group()
mode.add_argument("--check", action="store_true")
mode.add_argument("--write", action="store_true")
args = parser.parse_args()
if args.check or args.write:
    for path, expected in generated().items():
        if args.write:
            path.write_text(expected)
        elif not path.exists() or path.read_text() != expected:
            raise SystemExit(f"{path.relative_to(repo)} is stale: run make generate")
    print("host runtime pins generated from the Debian image inputs")
else:
    print(
        assignments(pins({"aarch64": "arm64", "x86_64": "amd64"}[platform.machine()]))
    )
