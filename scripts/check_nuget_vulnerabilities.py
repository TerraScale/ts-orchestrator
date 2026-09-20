#!/usr/bin/env python3
"""Fail closed when restored NuGet packages have known vulnerabilities."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def validate_report(report: object, project: str) -> list[dict]:
    if not isinstance(report, dict) or type(report.get("version")) is not int or report["version"] != 1:
        raise ValueError("unsupported or missing report version")
    parameters = report.get("parameters")
    if not isinstance(parameters, str) or not {"--vulnerable", "--include-transitive"} <= set(parameters.split()):
        raise ValueError("report does not cover transitive vulnerability scanning")
    sources = report.get("sources")
    if not isinstance(sources, list) or not sources or any(not isinstance(s, str) or not s.strip() for s in sources):
        raise ValueError("missing advisory sources")
    if report.get("logs", []) != []:
        raise ValueError("scanner reported diagnostics")
    projects = report.get("projects")
    if not isinstance(projects, list) or len(projects) != 1:
        raise ValueError("expected exactly one audited project")
    entry = projects[0]
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or Path(entry["path"]).resolve() != Path(project).resolve():
        raise ValueError("audited project does not match requested project")
    frameworks = entry.get("frameworks", [])
    if not isinstance(frameworks, list):
        raise ValueError("invalid framework list")
    findings = []
    for framework in frameworks:
        if not isinstance(framework, dict) or not isinstance(framework.get("framework"), str) or not framework["framework"].strip():
            raise ValueError("invalid framework identity")
        if framework.get("logs", []) != []:
            raise ValueError("framework contains scanner diagnostics")
        for kind in ("topLevelPackages", "transitivePackages"):
            packages = framework.get(kind, [])
            if not isinstance(packages, list):
                raise ValueError("invalid package list")
            for package in packages:
                if not isinstance(package, dict) or any(not isinstance(package.get(k), str) or not package[k].strip() for k in ("id", "resolvedVersion")):
                    raise ValueError("invalid package identity")
                advisories = package.get("vulnerabilities")
                if not isinstance(advisories, list) or not advisories or any(not isinstance(a, dict) or a.get("severity") not in ("Low", "Moderate", "High", "Critical") or not isinstance(a.get("advisoryurl"), str) or not a["advisoryurl"].strip() for a in advisories):
                    raise ValueError("invalid vulnerability advisory")
                findings.append(package)
    return findings


def main() -> int:
    projects = sys.argv[1:]
    if not projects:
        print("usage: check_nuget_vulnerabilities.py <project> [... ]", file=sys.stderr)
        return 2
    vulnerable = 0
    for project in projects:
        result = subprocess.run(["dotnet", "list", project, "package", "--vulnerable", "--include-transitive", "--format", "json"], capture_output=True, text=True, check=False)
        if result.returncode:
            print(f"NuGet audit failed for {project}: {result.stderr.strip()}", file=sys.stderr)
            return 1
        try:
            findings = validate_report(json.loads(result.stdout), project)
        except (json.JSONDecodeError, ValueError) as exc:
            print(f"NuGet audit returned incomplete or malformed output for {project}: {exc}", file=sys.stderr)
            return 1
        for package in findings:
            vulnerable += 1
            print(f"vulnerable NuGet package in {project}: {package['id']} {package['resolvedVersion']}", file=sys.stderr)
    if vulnerable:
        print(f"{vulnerable} vulnerable NuGet package(s) require documented disposition.", file=sys.stderr)
        return 1
    print(f"NuGet vulnerability audit: {len(projects)} projects, 0 vulnerable packages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
