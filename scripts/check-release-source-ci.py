#!/usr/bin/env python3
"""Fail-closed, read-only exact-source CI eligibility check; not live approval."""

import argparse
import datetime
import json
import os
import re
import signal
import sys
import urllib.error
import urllib.parse
import urllib.request

REQUIRED_JOBS = ("rust", "linux-arm64", "darwin-contract", "windows-rust", "dependency-security")
WORKFLOW_PATH = ".github/workflows/ci.yml"
MAX_ITEMS = 1000


class GateError(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise GateError(reason)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        # Do not forward the workflow token to a redirected or renamed target.
        return None


class GitHubApi:
    def __init__(self, token):
        require(bool(token), "missing_readonly_api_token")
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def __call__(self, path, params=None):
        require(path.startswith("/repos/"), "unexpected_api_path")
        url = "https://api.github.com" + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        request = urllib.request.Request(url, method="GET", headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self.token,
            "X-GitHub-Api-Version": "2026-03-10",
        })
        try:
            with self.opener.open(request, timeout=15) as response:
                data = response.read(8 * 1024 * 1024 + 1)
            require(len(data) <= 8 * 1024 * 1024, "ci_api_response_too_large")
            payload = json.loads(data)
            require(isinstance(payload, dict), "ci_api_malformed_response")
            return payload
        except (urllib.error.URLError, OSError, ValueError) as error:
            # API errors must not echo response bodies, tokens or raw headers.
            raise GateError("ci_api_unavailable_or_invalid") from error


def all_items(fetch, path, key, params=None):
    collected = []
    expected_total = None
    for page in range(1, MAX_ITEMS // 100 + 1):
        payload = fetch(path, {**(params or {}), "per_page": 100, "page": page})
        total = payload.get("total_count")
        items = payload.get(key)
        require(type(total) is int and 0 <= total <= MAX_ITEMS, "ci_pagination_unbounded_or_truncated")
        if expected_total is None:
            expected_total = total
        require(total == expected_total, "ci_listing_changed_during_pagination")
        require(isinstance(items, list) and len(items) <= 100, "ci_api_malformed_page")
        require(all(isinstance(item, dict) for item in items), "ci_api_malformed_item")
        collected.extend(items)
        if len(collected) >= total:
            require(len(collected) == total, "ci_listing_changed_during_pagination")
            return collected
        require(bool(items), "ci_api_incomplete_listing")
    raise GateError("ci_api_incomplete_listing")


def identity_matches(run, repository, sha):
    return (
        run.get("head_sha") == sha
        and run.get("event") == "push"
        and run.get("head_branch") == "main"
        and run.get("path", "").split("@", 1)[0] == WORKFLOW_PATH
        and run.get("repository", {}).get("full_name", "").lower() == repository.lower()
        and run.get("head_repository", {}).get("full_name", "").lower() == repository.lower()
    )


def validate_run(run, repository, sha):
    require(identity_matches(run, repository, sha), "ci_source_identity_mismatch")
    require(type(run.get("id")) is int and run["id"] > 0, "ci_run_id_missing")
    require(type(run.get("run_attempt")) is int and run["run_attempt"] > 0, "ci_attempt_missing")
    require(run.get("status") == "completed" and run.get("conclusion") == "success", "ci_run_not_successful")


def run_order(run):
    require(type(run.get("id")) is int and run["id"] > 0, "ci_run_id_missing")
    try:
        created = datetime.datetime.strptime(run.get("created_at", ""), "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError) as error:
        raise GateError("ci_run_created_at_missing_or_invalid") from error
    return created, run["id"]


def check_source_ci(fetch, repository, sha):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None, "invalid_repository")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "invalid_source_sha")
    base = f"/repos/{repository}/actions"
    runs = all_items(fetch, base + "/workflows/ci.yml/runs", "workflow_runs", {
        "head_sha": sha, "branch": "main", "event": "push",
    })
    candidates = [run for run in runs if identity_matches(run, repository, sha)]
    require(bool(candidates), "exact_source_main_ci_missing")
    ordered = [(run_order(run), run) for run in candidates]
    require(len({order[1] for order, _ in ordered}) == len(ordered), "ci_run_listing_ambiguous")
    # Never select an older green run while the latest same-source run is
    # failed, queued or still running. CI on PRs/manual dispatch can be shorter
    # than push/main and is deliberately not treated as equivalent evidence.
    selected = max(ordered, key=lambda item: item[0])[1]
    validate_run(selected, repository, sha)
    run_id, attempt = selected["id"], selected["run_attempt"]
    jobs = all_items(fetch, f"{base}/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
    for name in REQUIRED_JOBS:
        matching = [job for job in jobs if job.get("name") == name]
        require(len(matching) == 1, f"required_ci_job_missing_or_ambiguous:{name}")
        job = matching[0]
        require(job.get("run_id") == run_id and job.get("head_sha") == sha, f"ci_job_source_mismatch:{name}")
        require(job.get("status") == "completed" and job.get("conclusion") == "success", f"required_ci_job_not_successful:{name}")
    # Re-reading prevents a rerun from changing the selected attempt while its
    # jobs are being inspected. Optional/manual jobs are not promoted to gates.
    current = fetch(f"{base}/runs/{run_id}")
    validate_run(current, repository, sha)
    require((current["id"], current["run_attempt"]) == (run_id, attempt), "ci_attempt_changed_during_check")
    return {
        "source_ci_status": "PASS", "repository": repository, "git_sha": sha,
        "run_id": run_id, "run_attempt": attempt, "required_jobs": list(REQUIRED_JOBS),
        "boundary": "source CI only; not live canary, soak, artifact execution or stable approval",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()

    def expired(_signal, _frame):
        raise GateError("ci_api_total_budget_exhausted")

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(120)
    try:
        result = check_source_ci(GitHubApi(os.environ.get("GH_TOKEN", "")), args.repository, args.sha)
    except (GateError, KeyError, TypeError, AttributeError) as error:
        reason = str(error) if isinstance(error, GateError) else "ci_api_malformed_response"
        print(f"release-source-ci: BLOCKED reason={reason}", file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
