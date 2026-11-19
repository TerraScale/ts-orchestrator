import json
import os
import subprocess
from pathlib import Path

from qualified_release import REPOSITORY, api, command, require


def job_passed(job, verified):
    if job["conclusion"] == "success":
        return True
    if job["name"] != "e2e-certificates" or job["conclusion"] != "skipped":
        return False
    reasons = [step for step in verified["certificate-paths"]["steps"]
               if step["name"] == "Prove certificate lane is inapplicable"]
    return (len(reasons) == 1 and reasons[0]["status"] == "completed" and
            reasons[0]["conclusion"] == "success")


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
        pages = json.loads(command(
            "gh", "api", "--paginate", "--slurp",
            f"repos/{REPOSITORY}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100",
            text=True))
        jobs = [job for page in pages for job in page["jobs"]]
        require(pages and all(page["total_count"] == len(jobs) for page in pages),
                "incomplete PR job evidence")
        required = ("all-green", "lint", "e2e-m1", "certificate-paths", "e2e-certificates",
                    "caller-key-changes", *(f"caller-key / {shard}" for shard in range(8)))
        verified = {}
        for name in required:
            matches = [job for job in jobs if job["name"] == name]
            if (len(matches) != 1 or matches[0]["run_id"] != run["id"] or
                    matches[0]["status"] != "completed" or not job_passed(matches[0], verified)):
                break
            verified[name] = matches[0]
        else:
            return {"qualified": "true", "source": source, "tree": tree,
                    "pr": heads[run["head_sha"]],
                    "pr_head": run["head_sha"], "pr_run": run["html_url"],
                    "pr_attempt": run["run_attempt"],
                    "gates": {name: job["html_url"] for name, job in verified.items()}}
    return {"qualified": "false", "source": source, "tree": tree}


if __name__ == "__main__":
    os.environ["GH_HOST"] = "github.com"
    try:
        proof = qualification()
    except (ValueError, KeyError, TypeError, AttributeError, IndexError,
            OSError, subprocess.SubprocessError) as error:
        proof = {"qualified": "false", "reason": f"{type(error).__name__}: {error}"}
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"qualified={proof['qualified']}\n")
    evidence = json.dumps(proof, sort_keys=True)
    print(evidence)
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as summary:
        summary.write(f"PR tree qualification: `{evidence}`\n")
