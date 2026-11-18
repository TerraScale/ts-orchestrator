import json
import os
import subprocess
from pathlib import Path

from qualified_release import REPOSITORY, api, require


def qualification():
    require(os.environ["GITHUB_EVENT_NAME"] == "push" and
            os.environ["GITHUB_REF"] == "refs/heads/main" and
            os.environ["GITHUB_REPOSITORY"] == REPOSITORY,
            "PR qualification only authorizes this repository's main pushes")
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(source == os.environ["GITHUB_SHA"], "source differs from main run")
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True).strip()
    pulls = api(f"commits/{source}/pulls")
    heads = {pull["head"]["sha"]: pull["number"] for pull in pulls
             if pull["merged_at"] is not None and pull["merge_commit_sha"] == source and
             pull["base"]["ref"] == "main" and
             pull["base"]["repo"]["full_name"] == REPOSITORY and
             (pull["head"].get("repo") or {}).get("full_name") == REPOSITORY}
    if not heads:
        return {"qualified": "false", "source": source, "tree": tree}
    runs = api("actions/workflows/ci.yml/runs?event=pull_request&status=success&per_page=100")
    for run in runs["workflow_runs"]:
        head = run.get("head_commit") or {}
        if not (run["event"] == "pull_request" and run["status"] == "completed" and
                run["conclusion"] == "success" and run["path"] == ".github/workflows/ci.yml" and
                run["repository"]["full_name"] == REPOSITORY and
                (run.get("head_repository") or {}).get("full_name") == REPOSITORY and
                run["head_sha"] in heads and head.get("id") == run["head_sha"] and
                head.get("tree_id") == tree):
            continue
        pages = json.loads(subprocess.check_output([
            "gh", "api", "--paginate", "--slurp",
            f"repos/{REPOSITORY}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100",
        ], text=True))
        gates = [job for page in pages for job in page["jobs"] if job["name"] == "all-green"]
        if (len(gates) == 1 and gates[0]["run_id"] == run["id"] and
                gates[0]["status"] == "completed" and gates[0]["conclusion"] == "success"):
            return {"qualified": "true", "source": source, "tree": tree,
                    "pr": heads[run["head_sha"]],
                    "pr_head": run["head_sha"], "pr_run": run["html_url"],
                    "pr_attempt": run["run_attempt"], "gate": gates[0]["html_url"]}
    return {"qualified": "false", "source": source, "tree": tree}


if __name__ == "__main__":
    os.environ["GH_HOST"] = "github.com"
    proof = qualification()
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"qualified={proof['qualified']}\n")
    evidence = json.dumps(proof, sort_keys=True)
    print(evidence)
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
        summary.write(f"PR tree qualification: `{evidence}`\n")
