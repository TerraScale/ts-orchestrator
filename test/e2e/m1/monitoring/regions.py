import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[4]
rendered, promtool, renderer = map(Path, sys.argv[1:])
hosts = (root / "deploy/observability/production/hosts.txt").read_text().splitlines()
regions = sorted({host.split("-")[1] for host in hosts})
monitors = [next(host for host in hosts if host.split("-")[1] == region) for region in regions]
if len(monitors) < 2:
    raise SystemExit("monitoring: no independent regions")
for monitor in monitors:
    config = json.loads((rendered / monitor / "prometheus.yml").read_text())
    jobs = {job["job_name"]: job for job in config["scrape_configs"]}
    discovery = {d["url"].split("://")[1].split(".")[0] for d in jobs["application-slo"]["http_sd_configs"]}
    if discovery != set(hosts):
        raise SystemExit("monitoring: application discovery misses a host")
    for name in ("host-storage", "terrabase-host-storage", "peer-topology"):
        if {t["labels"]["host"] for t in jobs[name]["static_configs"]} != set(hosts):
            raise SystemExit(f"monitoring: {name} misses a host")
    for name in ("monitoring-prometheus", "monitoring-alertmanager", "service-readiness"):
        if {t["labels"]["host"] for t in jobs[name]["static_configs"]} != set(monitors):
            raise SystemExit(f"monitoring: {name} misses a monitoring backend")
    generated = json.loads((rendered / monitor / "rules.yml").read_text())
    coverage = {}
    for group in generated["groups"]:
        for rule in group["rules"]:
            coverage.setdefault(rule.get("alert", rule.get("record")), set()).add(rule["labels"]["region"])
    if any(found != set(regions) for found in coverage.values()):
        raise SystemExit("monitoring: rule misses a region")
    canonical = json.loads((rendered / monitors[0] / "rules.yml").read_text())
    if generated != canonical:
        raise SystemExit("monitoring: backends evaluate different regional rules")
    if monitor != monitors[0]:
        continue
    cases = []
    for lost in regions:
        lost_monitor = next(host for host in monitors if host.split("-")[1] == lost)
        backend_alerts = []
        for name in ("monitoring-prometheus", "monitoring-alertmanager", "service-readiness"):
            backend_alerts.append({"exp_labels": {"severity": "critical", "region": lost, "job": name, "host": lost_monitor, "instance": lost_monitor}, "exp_annotations": {"summary": "A regional monitoring backend is unavailable"}})
        series = []
        for name in ("monitoring-prometheus", "monitoring-alertmanager", "service-readiness"):
            for target in monitors:
                region = target.split("-")[1]
                series.append({"series": f'up{{job="{name}",host="{target}",instance="{target}",region="{region}"}}', "values": ("0" if region == lost else "1") + "+0x16"})
        host_alerts = []
        for host in hosts:
            region = host.split("-")[1]
            series.append({"series": f'up{{job="host-storage",host="{host}",instance="{host}",region="{region}",service="host-storage"}}', "values": ("0" if region == lost else "1") + "+0x16"})
            for service in ("terrabase", "ts-auth", "ts-dashboard"):
                series.append({"series": f'ts_host_service_tasks_expected{{job="host-storage",host="{host}",region="{region}",service="{service}"}}', "values": "0+0x16"})
            if region == lost:
                host_alerts.append({"exp_labels": {"severity": "critical", "region": region, "job": "host-storage", "host": host, "instance": host, "service": "host-storage"}, "exp_annotations": {"summary": f"Expected node {host} has no host-storage heartbeat ({region})"}})
        cases.append({"interval": "1m", "input_series": series, "alert_rule_test": [
            {"eval_time": "1m", "alertname": "MonitoringBackendDown", "exp_alerts": []},
            {"eval_time": "2m", "alertname": "MonitoringBackendDown", "exp_alerts": backend_alerts},
            {"eval_time": "5m", "alertname": "ExpectedNodeAbsent", "exp_alerts": host_alerts},
            {"eval_time": "15m", "alertname": "HostServiceTaskInventoryMissing", "exp_alerts": []},
        ]})
    missing = []
    for host in hosts:
        missing.append({"exp_labels": {"severity": "critical", "region": host.split("-")[1], "job": "host-storage", "host": host}, "exp_annotations": {"summary": f"Service task inventory is absent on {host}"}})
    cases.append({"interval": "1m", "input_series": [], "alert_rule_test": [{"eval_time": "15m", "alertname": "HostServiceTaskInventoryMissing", "exp_alerts": missing}]})
    slo_series = []
    slo_alerts = []
    for region in regions:
        slo_series.append({"series": f'terrascale_slo_requests_total{{service="ts-dashboard",region="{region}",instance="{region}-task",outcome="bad"}}', "values": "0+20x65"})
        slo_alerts.append({"exp_labels": {"service": "ts-dashboard", "region": region, "slo": "availability", "severity": "critical", "long_window": "1h", "short_window": "5m"}, "exp_annotations": {"summary": "ts-dashboard availability error budget is burning", "description": "Burn exceeds 14.4x in both 1h and 5m with at least 695 eligible requests in 1h; inspect service failures before changing capacity or releases."}})
    cases.append({"interval": "1m", "input_series": slo_series, "alert_rule_test": [{"eval_time": "1h", "alertname": "ServiceSLOBurnFast", "exp_alerts": slo_alerts}]})
    telemetry_series = []
    telemetry_alerts = []
    for region in regions:
        for service in ("terrabase", "ts-auth", "ts-dashboard"):
            assigned = service != "ts-auth" or region == regions[0]
            telemetry_series.append({"series": f'ts_host_service_tasks_expected{{service="{service}",region="{region}"}}', "values": ("1" if assigned else "0") + "+0x16"})
            if assigned:
                telemetry_alerts.append({"exp_labels": {"service": service, "region": region, "slo": "availability", "severity": "warning"}, "exp_annotations": {"summary": f"{service} SLO telemetry is missing", "description": "No recent good or bad request counter; restore instrumentation or collection. Missing telemetry is not availability success."}})
    cases.append({"interval": "1m", "input_series": telemetry_series, "alert_rule_test": [{"eval_time": "15m", "alertname": "ServiceSLOTelemetryMissing", "exp_alerts": telemetry_alerts}]})
    fixture = rendered / monitor / "region-loss.yml"
    fixture.write_text(json.dumps({"rule_files": ["rules.yml"], "evaluation_interval": "15s", "tests": cases}))
    subprocess.run([str(promtool), "test", "rules", str(fixture)], check=True)
with tempfile.TemporaryDirectory() as directory:
    staged = Path(directory)
    shutil.copytree(root / "deploy/observability", staged / "deploy/observability")
    shutil.copytree(root / "internal", staged / "internal")
    rules = staged / "deploy/observability/production/operational-rules.yml"
    original = rules.read_text()
    for replacement, message in (("ts_nonexistent_monitoring_metric", "metric has no exporter"), ("terrabase_backup_abandoned_total", "metric has no exporter"), ("terrabase_backup_holes_total", "metric has no exporter"), ('ts_host_oom_kills_total{region="gru",', "must not pin a region")):
        source = "ts_host_oom_kills_total{" if "region=" in replacement else "ts_host_oom_kills_total"
        rules.write_text(original.replace(source, replacement))
        result = subprocess.run([str(renderer), str(staged / "output"), str(staged)], capture_output=True, text=True, check=False)
        if result.returncode == 0 or message not in result.stderr:
            raise SystemExit(f"monitoring: invalid rule was accepted: {replacement}: {result.stderr}")
    rules.write_text(original)
    inventory = staged / "deploy/observability/production/hosts.txt"
    inventory.write_text(inventory.read_text() + "ts-iad-1\n")
    subprocess.run([str(renderer), str(staged / "expanded"), str(staged)], check=True)
    expanded = json.loads((staged / "expanded/ts-iad-1/rules.yml").read_text())
    if not any(r["labels"]["region"] == "iad" for g in expanded["groups"] for r in g["rules"]):
        raise SystemExit("monitoring: new inventory region has no rules")
print("monitoring: every backend watches every region; region-loss evaluation, missing inventory and rule guardrails passed")
