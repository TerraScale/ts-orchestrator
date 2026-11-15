import copy
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise RuntimeError("NetBird management redirect refused")


token = Path(sys.argv[1]).read_text().strip()
origin = sys.argv[2] if len(sys.argv) == 3 else "https://netbird.terrascale.tech"
parsed = urlparse(origin)
if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost")):
    raise SystemExit("NetBird management origin must use HTTPS")
if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
    raise SystemExit("NetBird management origin required")
client = build_opener(NoRedirect)


def api(method, path, body=None):
    request = Request(origin.rstrip("/") + "/api" + path, method=method,
                      headers={"Authorization": "Token " + token, "Content-Type": "application/json"},
                      data=None if body is None else json.dumps(body).encode())
    with client.open(request, timeout=10) as response:
        data = response.read()
        return json.loads(data) if data else None


groups = {g["name"]: g["id"] for g in api("GET", "/groups")}
server_ids = {value for name, value in groups.items() if re.fullmatch(r"[a-z]{3}-servers", name)}
policies = api("GET", "/policies")
named = {}
for policy in policies:
    if policy["name"] in ("servers-to-servers-metrics", "gru-servers-to-servers-metrics", "servers-monitoring-gossip"):
        if policy["name"] in named:
            raise SystemExit("Duplicate monitoring policy names; no changes made")
        named[policy["name"]] = policy


def ids(values):
    return {value["id"] if isinstance(value, dict) else value for value in values}


def validate(policy, protocol, ports, sources):
    rules = policy["rules"]
    if len(rules) != 1 or policy.get("source_posture_checks"):
        raise SystemExit("Customized monitoring policy; no changes made")
    rule = rules[0]
    if rule["protocol"] != protocol or set(rule.get("ports", [])) != ports or ids(rule["sources"]) != sources or ids(rule["destinations"]) != server_ids or rule["action"] != "accept" or rule.get("bidirectional") or rule.get("authorized_groups") or rule.get("destinationResource"):
        raise SystemExit("Customized monitoring grant; no changes made")


new = named.get("servers-to-servers-metrics")
old = named.get("gru-servers-to-servers-metrics")
gossip = named.get("servers-monitoring-gossip")
if new:
    validate(new, "tcp", {"9108", "9091", "9093", "9095"}, server_ids)
if old:
    validate(old, "tcp", {"9108", "9091"}, {groups["gru-servers"]})
if gossip:
    validate(gossip, "udp", {"9095"}, server_ids)
if not new and not old:
    raise SystemExit("No monitoring policy to restore; no changes made")
if new:
    if old:
        api("DELETE", "/policies/" + new["id"])
    else:
        payload = copy.deepcopy(new)
        payload.pop("id")
        payload["name"] = "gru-servers-to-servers-metrics"
        payload["description"] = "GRU servers (Prometheus runs on ts-gru-1) → regional servers in every region: host exporter 9108 and TerraBase metrics 9091"
        rule = payload["rules"][0]
        rule["name"], rule["description"] = payload["name"], payload["description"]
        rule["sources"], rule["destinations"] = [groups["gru-servers"]], sorted(server_ids)
        rule["ports"] = ["9108", "9091"]
        api("PUT", "/policies/" + new["id"], payload)
if gossip:
    api("DELETE", "/policies/" + gossip["id"])
print("monitoring rollback: restored GRU-only metrics policy; removed regional gossip and duplicate policy")
