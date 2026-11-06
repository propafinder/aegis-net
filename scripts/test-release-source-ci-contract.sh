#!/usr/bin/env bash
# Offline GitHub API fixtures; never dispatch, publish, or access an account.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHONDONTWRITEBYTECODE=1 python3 - "${ROOT}" <<'PY'
import copy
import importlib.util
import io
import json
import re
import sys
import urllib.error
from pathlib import Path

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("release_source_ci", root / "scripts/check-release-source-ci.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
repository, sha = "fixture-owner/fixture-repo", "a" * 40
run = {
    "id": 42, "run_attempt": 1, "head_sha": sha, "event": "push", "head_branch": "main",
    "path": ".github/workflows/ci.yml", "status": "completed", "conclusion": "success",
    "repository": {"full_name": repository}, "head_repository": {"full_name": repository},
    "created_at": "2026-09-05T10:00:00Z",
}
jobs = [
    {"id": index, "name": name, "run_id": 42, "head_sha": sha, "status": "completed", "conclusion": "success"}
    for index, name in enumerate(gate.REQUIRED_JOBS, 1)
]
optional = {"id": 9, "name": "windows-wfp-proof-manual", "run_id": 42, "head_sha": sha,
            "status": "completed", "conclusion": "skipped"}


class FixtureApi:
    def __init__(self, runs=None, job_items=None, current=None):
        self.runs = copy.deepcopy([run] if runs is None else runs)
        self.jobs = copy.deepcopy(jobs if job_items is None else job_items)
        self.current = copy.deepcopy(run if current is None else current)
        self.calls = []

    def __call__(self, path, params=None):
        self.calls.append((path, params))
        prefix = f"/repos/{repository}/actions"
        if path == prefix + "/workflows/ci.yml/runs":
            assert params["head_sha"] == sha and params["event"] == "push" and params["branch"] == "main"
            # Do not filter to successful/completed runs and thereby hide a
            # newer failure or an in-progress rerun for this same source.
            assert "status" not in params
            items, key = self.runs, "workflow_runs"
        elif path == prefix + "/runs/42/attempts/1/jobs":
            items, key = self.jobs, "jobs"
        elif path == prefix + "/runs/42":
            return copy.deepcopy(self.current)
        else:
            raise AssertionError(("unexpected API operation", path, params))
        first = (params["page"] - 1) * params["per_page"]
        return {"total_count": len(items), key: copy.deepcopy(items[first:first + params["per_page"]])}


def accepted(api):
    receipt = gate.check_source_ci(api, repository, sha)
    assert receipt["source_ci_status"] == "PASS" and receipt["git_sha"] == sha
    assert receipt["required_jobs"] == list(gate.REQUIRED_JOBS)
    assert "not live canary" in receipt["boundary"]
    assert api.calls[-1][0].endswith("/runs/42"), "attempt snapshot must be re-read"


def blocked(api, reason):
    try:
        gate.check_source_ci(api, repository, sha)
    except gate.GateError as error:
        assert reason in str(error), (reason, str(error))
    else:
        raise AssertionError("source gate accepted a blocked fixture")


accepted(FixtureApi())
accepted(FixtureApi(job_items=jobs + [optional]))
blocked(FixtureApi(runs=[]), "exact_source_main_ci_missing")
for field, value in (("head_sha", "b" * 40), ("event", "pull_request"),
                     ("event", "workflow_dispatch"), ("head_branch", "feature"),
                     ("path", ".github/workflows/release.yml"),
                     ("head_repository", {"full_name": "another-owner/fork"})):
    blocked(FixtureApi(runs=[{**run, field: value}]), "exact_source_main_ci_missing")
for value in ("failure", "skipped", "cancelled", "timed_out", None):
    blocked(FixtureApi(runs=[{**run, "conclusion": value}]), "ci_run_not_successful")
blocked(FixtureApi(runs=[{**run, "status": "in_progress"}]), "ci_run_not_successful")
blocked(FixtureApi(runs=[run, {**run, "id": 43, "conclusion": "failure"}]), "ci_run_not_successful")
blocked(FixtureApi(runs=[run, {**run, "id": 41, "created_at": "2026-09-05T11:00:00Z", "conclusion": "failure"}]), "ci_run_not_successful")
blocked(FixtureApi(runs=[{**run, "created_at": None}]), "ci_run_created_at_missing_or_invalid")
blocked(FixtureApi(runs=[run, run]), "ci_run_listing_ambiguous")
for index, name in enumerate(gate.REQUIRED_JOBS):
    blocked(FixtureApi(job_items=[job for job in jobs if job["name"] != name]), "required_ci_job_missing")
    for field, value in (("conclusion", "skipped"), ("conclusion", "neutral"), ("conclusion", "failure"), ("status", "in_progress")):
        altered = copy.deepcopy(jobs)
        altered[index][field] = value
        blocked(FixtureApi(job_items=altered), "required_ci_job_not_successful")
    altered = copy.deepcopy(jobs)
    altered[index]["head_sha"] = "b" * 40
    blocked(FixtureApi(job_items=altered), "ci_job_source_mismatch")
blocked(FixtureApi(job_items=jobs + [jobs[0]]), "required_ci_job_missing_or_ambiguous")
blocked(FixtureApi(current={**run, "run_attempt": 2}), "ci_attempt_changed_during_check")
blocked(FixtureApi(current={**run, "status": "queued"}), "ci_run_not_successful")
extras = [{**optional, "id": 1000 + index, "name": f"optional-{index}"} for index in range(205)]
api = FixtureApi(job_items=extras + jobs)
accepted(api)
assert len([path for path, _ in api.calls if path.endswith("/jobs")]) == 3

for payload, reason in (
    ({"total_count": 1001, "workflow_runs": []}, "ci_pagination_unbounded_or_truncated"),
    ({"total_count": 2, "workflow_runs": []}, "ci_api_incomplete_listing"),
    ({"total_count": 0, "workflow_runs": [run]}, "ci_listing_changed_during_pagination"),
):
    blocked(lambda path, params=None: payload, reason)

# Exercise the production request adapter offline: GET only, fixed API origin,
# bounded socket timeout, no redirects, and sanitized failure classification.
class Opener:
    def open(self, request, timeout):
        assert request.get_method() == "GET" and request.full_url.startswith("https://api.github.com/repos/")
        assert timeout == 15 and request.headers["Authorization"] == "Bearer fixture-token"
        return io.BytesIO(json.dumps({"total_count": 0, "workflow_runs": []}).encode())


client = gate.GitHubApi("fixture-token")
client.opener = Opener()
assert client(f"/repos/{repository}/actions/workflows/ci.yml/runs", {"head_sha": sha})["total_count"] == 0
assert gate.NoRedirect().redirect_request(None, None, 302, "", {}, "https://elsewhere.invalid") is None


class FailedOpener:
    def open(self, *args, **kwargs):
        raise urllib.error.URLError("fixture-token must not appear in diagnostics")


client.opener = FailedOpener()
try:
    client(f"/repos/{repository}/actions/runs/42")
except gate.GateError as error:
    assert str(error) == "ci_api_unavailable_or_invalid"
else:
    raise AssertionError("API failure became approval")

workflow = (root / ".github/workflows/release.yml").read_text()
publish = workflow.split("\n  assemble-delivery:\n", 1)[1]
step = re.search(r'^      - name: Require exact-source main CI\n.*?(?=^      - name:)', publish, re.M | re.S)[0]
assert "        if:" not in step and "continue-on-error" not in step
assert "actions: read" in publish
assert 'GH_TOKEN: ${{ github.token }}' in step
assert '--repository "${GITHUB_REPOSITORY}" --sha "${GITHUB_SHA}"' in step
assert "timeout-minutes: 3" in step
assert publish.index("Require exact-source main CI") < publish.index("Sign release manifest") < publish.index("Publish GitHub release assets")
assert "${{" not in step.split("        run: |\n", 1)[1], "release checker arguments must use env"
print("PASS: exact-source main CI, all required jobs, optional skip, latest attempt, pagination, read-only API, pre-sign workflow wiring (offline fixtures only)")
PY
