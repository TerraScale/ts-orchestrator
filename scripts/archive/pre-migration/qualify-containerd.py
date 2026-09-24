#!/usr/bin/env python3
"""Run ContainerdLiveTests in a private Linux network and mount namespace.

Invoke the already-built TUnit executable; this script never builds as root.
The registry serves a synthetic busybox image, not a TerraScale service image.
All daemon state is temporary. Logs and the test receipt remain in the printed
lab directory. See docs/operations/containerd-qualification.md.
"""

import argparse
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, separators=(",", ":")).encode()


def fixture_image(busybox):
    # Require a real static busybox with the fixture's applets before creating
    # daemon state; a tiny init-only VM fixture is not a usable container image.
    subprocess.run([str(busybox), "sleep", "0"], check=True, timeout=5)
    layer_stream = io.BytesIO()
    with tarfile.open(fileobj=layer_stream, mode="w") as archive:
        for name in ("bin", "etc", "tmp", "run"):
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            archive.addfile(entry)
        entry = tarfile.TarInfo("bin/busybox")
        content = busybox.read_bytes()
        entry.size = len(content)
        entry.mode = 0o755
        archive.addfile(entry, io.BytesIO(content))
    layer = layer_stream.getvalue()
    config = json_bytes({
        "architecture": "amd64", "os": "linux",
        "config": {"Entrypoint": ["/bin/busybox", "sleep", "600"]},
        "rootfs": {"type": "layers", "diff_ids": [sha256(layer)]},
    })
    manifest = json_bytes({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": sha256(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": sha256(layer), "size": len(layer)}],
    })
    return manifest, {sha256(config): config, sha256(layer): layer}


def registry_handler(manifest, blobs):
    class Registry(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.respond(body=True)

        def do_HEAD(self):
            self.respond(body=False)

        def respond(self, body):
            path = self.path.split("?", 1)[0]
            data, media_type = b"{}", "application/json"
            if "/manifests/" in path:
                if path.rsplit("/", 1)[1] != sha256(manifest):
                    self.send_error(404)
                    return
                data = manifest
                media_type = "application/vnd.oci.image.manifest.v1+json"
            elif "/blobs/" in path:
                data = blobs.get(path.rsplit("/", 1)[1])
                if data is None:
                    self.send_error(404)
                    return
                media_type = "application/octet-stream"
            elif path != "/v2/":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", media_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Docker-Content-Digest", sha256(data))
            self.end_headers()
            if body:
                self.wfile.write(data)

        def log_message(self, *_):
            pass

    return Registry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("test", "nerdctl", "containerd", "runc", "cni", "busybox"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.machine() != "x86_64":
        parser.error("This qualification lane requires root on Linux x64.")
    for namespace in ("net", "mnt"):
        if os.readlink(f"/proc/self/ns/{namespace}") == os.readlink(f"/proc/1/ns/{namespace}"):
            parser.error("Use unshare --net --mount --propagation private; shared namespaces are refused.")
    for name in ("test", "nerdctl", "containerd", "runc", "busybox"):
        value = getattr(args, name).resolve(strict=True)
        if not value.is_file() or not os.access(value, os.X_OK):
            parser.error(f"--{name} must name an executable")
        setattr(args, name, value)
    args.cni = args.cni.resolve(strict=True)
    manifest, blobs = fixture_image(args.busybox)
    root = Path(tempfile.mkdtemp(prefix="ts-oci-containerd-"))
    print(f"lab={root}", flush=True)
    os.environ["PATH"] = f"{args.containerd.parent}:{args.runc.parent}:" + os.environ["PATH"]
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=5)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), registry_handler(manifest, blobs))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    hosts = root / "certs" / "registry.terrascale.internal"
    hosts.mkdir(parents=True)
    (hosts / "hosts.toml").write_text(f'server = "http://127.0.0.1:{server.server_port}"\n')
    (root / "cni").mkdir()
    (root / "cni" / "10-lab.conflist").write_bytes(json_bytes({
        "cniVersion": "1.0.0", "name": "bridge",
        "plugins": [{"type": "bridge", "bridge": "tslab0", "isGateway": True,
                     "ipMasq": False, "ipam": {"type": "host-local",
                     "ranges": [[{"subnet": "10.88.250.0/24"}]], "dataDir": str(root / "ipam")}}],
    }))
    socket_path = str(root / "containerd.sock")
    config = root / "config.toml"
    config.write_text(
        f'version = 3\nroot = "{root / "root"}"\nstate = "{root / "state"}"\n'
        'disabled_plugins = ["io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]\n'
        f'[grpc]\naddress = "{socket_path}"\n'
    )
    command = [str(args.nerdctl), "--address", socket_path,
               "--data-root", str(root / "nerdctl-data"), "--hosts-dir", str(root / "certs"),
               "--cni-path", str(args.cni), "--cni-netconfpath", str(root / "cni")]
    wrapper = root / "nerdctl"
    # Record diagnostics only for this secret-free fixture. Production's client
    # redacts command errors; this wrapper is never installed on a workload host.
    wrapper.write_text(
        f"#!{sys.executable}\nimport subprocess,sys\n"
        f"result=subprocess.run({command!r}+sys.argv[1:],stderr=subprocess.PIPE)\n"
        f"with open({str(root / 'client.log')!r},'ab') as log:log.write(result.stderr)\n"
        "sys.stderr.buffer.write(result.stderr)\nraise SystemExit(result.returncode)\n"
    )
    wrapper.chmod(0o700)
    code, clean = 1, False
    with (root / "containerd.log").open("w") as log:
        daemon = subprocess.Popen([str(args.containerd), "--config", str(config)],
                                  stdout=log, stderr=log, start_new_session=True)
        try:
            for _ in range(150):
                if Path(socket_path).exists():
                    break
                if daemon.poll() is not None:
                    raise RuntimeError("containerd exited during startup")
                time.sleep(0.1)
            else:
                raise TimeoutError("containerd did not create its private socket")
            env = os.environ.copy()
            env.update(TS_ORCH_LIVE_CONTAINERD="1", TS_ORCH_LAB_NERDCTL=str(wrapper),
                       TS_ORCH_LAB_IMAGE_DIGEST=sha256(manifest)[7:],
                       TESTINGPLATFORM_TELEMETRY_OPTOUT="1")
            test = subprocess.Popen([
                str(args.test), "--treenode-filter", "/*/*/ContainerdLiveTests/*",
                "--results-directory", str(root / "results"), "--no-ansi",
            ], env=env, start_new_session=True)
            try:
                code = test.wait(timeout=180)
            except subprocess.TimeoutExpired:
                os.killpg(test.pid, signal.SIGKILL)
                test.wait()
                raise
        finally:
            try:
                subprocess.run(command + ["--namespace", "terrascale", "rm", "-f", "terrascale-oci-lab-auth"],
                               capture_output=True, timeout=30)
                remaining = subprocess.run(command + ["--namespace", "terrascale", "ps", "-aq"],
                                           capture_output=True, text=True, timeout=15)
                clean = remaining.returncode == 0 and not remaining.stdout.strip()
                print(f"cleanup-verified={clean}", flush=True)
            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()
                server.shutdown()
                server.server_close()
    receipt = {"schemaVersion": 1, "exitCode": code, "cleanupVerified": clean,
               "fixtureDigest": sha256(manifest), "tools": {name: str(getattr(args, name))
               for name in ("nerdctl", "containerd", "runc", "cni", "busybox")}}
    (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    # Failed cleanup retains state for inspection. Namespace exit removes the
    # private bridge; no network or runtime state in the host is overwritten.
    if clean:
        for directory in ("root", "state", "nerdctl-data", "ipam"):
            shutil.rmtree(root / directory, ignore_errors=True)
    return code if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
