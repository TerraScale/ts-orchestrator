import copy
import json
import secrets
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

script = Path(__file__).resolve().parents[4] / "deploy/observability/production/rollback-policy.py"
groups = [{"name": name + "-servers", "id": name} for name in ("gru", "sjc", "fra")]
policies = {}
writes = []


def policy(name, protocol, ports, sources):
    return {"id": name, "name": name, "description": name, "enabled": True, "source_posture_checks": [], "rules": [{
        "name": name, "description": name, "enabled": True, "action": "accept", "bidirectional": False, "protocol": protocol,
        "ports": ports, "sources": [{"id": value} for value in sources], "destinations": [{"id": g["id"]} for g in groups],
    }]}


canonical = policy("servers-to-servers-metrics", "tcp", ["9108", "9091", "9093", "9095"], ["gru", "sjc", "fra"])
gossip = policy("servers-monitoring-gossip", "udp", ["9095"], ["gru", "sjc", "fra"])
old = policy("gru-servers-to-servers-metrics", "tcp", ["9108", "9091"], ["gru"])


class Management(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, value):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(value).encode())

    def do_GET(self):
        if self.path == "/api/groups":
            self.respond(groups)
        elif self.path == "/api/policies":
            self.respond(list(policies.values()))
        else:
            raise RuntimeError(self.path)

    def do_PUT(self):
        key = self.path.removeprefix("/api/policies/")
        policies[key] = json.loads(self.rfile.read(int(self.headers["Content-Length"]))) | {"id": key}
        writes.append(("PUT", key))
        self.respond(None)

    def do_DELETE(self):
        key = self.path.removeprefix("/api/policies/")
        del policies[key]
        writes.append(("DELETE", key))
        self.respond(None)


server = ThreadingHTTPServer(("127.0.0.1", 0), Management)
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    with tempfile.TemporaryDirectory() as directory:
        pat = Path(directory) / "pat"
        pat.write_text(secrets.token_urlsafe(32))
        pat.chmod(0o600)
        command = [sys.executable, str(script), str(pat), f"http://127.0.0.1:{server.server_port}"]
        for duplicate in (False, True):
            policies.clear()
            policies.update({p["id"]: copy.deepcopy(p) for p in (canonical, gossip)})
            if duplicate:
                policies[old["id"]] = copy.deepcopy(old)
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            assert len(policies) == 1, policies
            restored = next(iter(policies.values()))
            assert restored["name"] == old["name"]
            assert set(restored["rules"][0]["ports"]) == {"9108", "9091"}
            assert {v["id"] if isinstance(v, dict) else v for v in restored["rules"][0]["sources"]} == {"gru"}
            before = copy.deepcopy(policies)
            subprocess.run(command, capture_output=True, text=True, check=True)
            assert policies == before
        policies.clear()
        customized = copy.deepcopy(canonical)
        customized["rules"][0]["ports"].append("443")
        policies[customized["id"]] = customized
        writes.clear()
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        assert result.returncode != 0 and not writes, result
    print("monitoring: rollback restores one GRU-only policy, removes gossip/duplicates, is idempotent and refuses customized grants before writing")
finally:
    server.shutdown()
    server.server_close()
