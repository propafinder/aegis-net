#!/usr/bin/env python3
"""Read-only, fail-closed release control-plane check (never reads secret values)."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import sys
import time

# Reuse the bounded GET-only transport, redacted errors and complete pagination.
_spec = importlib.util.spec_from_file_location(
    "source_ci", Path(__file__).with_name("check-release-source-ci.py"))
_ci = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ci)
GateError, require = _ci.GateError, _ci.require
SENSITIVE = {"AEGIS_MANIFEST_SIGNING_KEY", "AEGIS_RELEASE_REPO_TOKEN"}
ENVIRONMENTS = {"release": "AEGIS_MANIFEST_SIGNING_KEY", "publish": "AEGIS_RELEASE_REPO_TOKEN"}


def secret_names(fetch, path):
    items = _ci.all_items(fetch, path, "secrets")
    names = [item.get("name") for item in items]
    require(all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_]+", name) for name in names),
            "secret_metadata_malformed")
    require(len(set(names)) == len(names), "secret_metadata_ambiguous")
    return set(names)


def check_governance(fetch, repository, sha, event, ref):
    checked_at = int(time.time())
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None, "invalid_repository")
    require(re.fullmatch(r"[0-9a-f]{40}", sha) is not None, "invalid_source_sha")
    require(event == "workflow_dispatch" and ref == "refs/heads/main", "protected_main_dispatch_required")
    base = f"/repos/{repository}"
    repo = fetch(base)
    require(repo.get("full_name", "").lower() == repository.lower() and repo.get("private") is True,
            "private_source_repository_required")
    require(repo.get("default_branch") == "main" and repo.get("archived") is False and repo.get("disabled") is False,
            "repository_state_not_eligible")
    owner_type = repo.get("owner", {}).get("type")
    require(owner_type in {"User", "Organization"}, "repository_owner_type_unknown")
    comparison = fetch(f"{base}/compare/{sha}...main")
    require(comparison.get("status") in {"ahead", "identical"}
            and comparison.get("base_commit", {}).get("sha") == sha
            and comparison.get("merge_base_commit", {}).get("sha") == sha, "source_not_on_main")

    # This first version deliberately supports classic branch protection only.
    # A ruleset-only or unreadable configuration is unknown, never a PASS.
    protection = fetch(f"{base}/branches/main/protection")
    require(protection.get("enforce_admins", {}).get("enabled") is True, "main_admin_bypass_enabled")
    for field in ("allow_force_pushes", "allow_deletions"):
        require(protection.get(field, {}).get("enabled") is False, "main_destructive_changes_not_blocked")
    reviews = protection.get("required_pull_request_reviews") or {}
    require(type(reviews.get("required_approving_review_count")) is int
            and reviews["required_approving_review_count"] >= 1, "main_independent_review_missing")
    for field in ("dismiss_stale_reviews", "require_code_owner_reviews", "require_last_push_approval"):
        require(reviews.get(field) is True, "main_review_policy_incomplete")
    bypass = reviews.get("bypass_pull_request_allowances") or {}
    require(not any(bypass.get(kind) for kind in ("users", "teams", "apps")), "main_review_bypass_present")
    checks = protection.get("required_status_checks") or {}
    require(checks.get("strict") is True, "main_strict_checks_missing")
    contexts = set(checks.get("contexts") or [])
    contexts.update(item.get("context") for item in checks.get("checks", []) if isinstance(item, dict))
    require(set(_ci.REQUIRED_JOBS) <= contexts, "main_required_checks_missing")

    require(not (secret_names(fetch, f"{base}/actions/secrets") & SENSITIVE), "repository_secret_copy_present")
    if owner_type == "Organization":
        require(not (secret_names(fetch, f"{base}/actions/organization-secrets") & SENSITIVE),
                "accessible_organization_secret_copy_present")
    # A personal repository has no organization owner; a 404 is not used as proof.
    for name, expected_secret in ENVIRONMENTS.items():
        environment = fetch(f"{base}/environments/{name}")
        require(environment.get("name") == name and environment.get("can_admins_bypass") is False,
                "environment_identity_or_admin_policy_unverified")
        rules = environment.get("protection_rules")
        require(isinstance(rules, list), "environment_protection_rules_missing")
        required = [rule for rule in rules if isinstance(rule, dict) and rule.get("type") == "required_reviewers"]
        require(len(required) == 1 and required[0].get("prevent_self_review") is True,
                "environment_independent_review_missing")
        reviewers = required[0].get("reviewers")
        require(isinstance(reviewers, list) and bool(reviewers)
                and all(isinstance(item, dict) and item.get("type") in {"User", "Team"}
                        and type(item.get("reviewer", {}).get("id")) is int
                        and item["reviewer"]["id"] > 0 for item in reviewers), "environment_reviewers_invalid")
        policy = environment.get("deployment_branch_policy") or {}
        require(policy.get("protected_branches") is False and policy.get("custom_branch_policies") is True,
                "environment_exact_main_policy_missing")
        branches = _ci.all_items(fetch, f"{base}/environments/{name}/deployment-branch-policies", "branch_policies")
        require(len(branches) == 1 and branches[0].get("name") == "main" and branches[0].get("type") == "branch",
                "environment_allows_unreviewed_ref")
        names = secret_names(fetch, f"{base}/environments/{name}/secrets")
        require(names & SENSITIVE == {expected_secret}, "environment_secret_isolation_unverified")
    return {"event": "release_governance", "status": "PASS", "repository": repository,
            "source_sha": sha, "checked_at": checked_at, "owner_type": owner_type,
            "boundary": "metadata snapshot only; not immutable governance or release acceptance"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    def expired(_signal, _frame):
        raise GateError("governance_total_budget_exhausted")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(120)
    try:
        api = _ci.GitHubApi(os.environ.get("GH_TOKEN", ""))
        api.opener = _ci.urllib.request.build_opener(_ci.NoRedirect(), _ci.urllib.request.ProxyHandler({}))
        report = check_governance(api, args.repository, args.sha,
                                  os.environ.get("GITHUB_EVENT_NAME", ""), os.environ.get("GITHUB_REF", ""))
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write(f"checked_at={report['checked_at']}\nsource_sha={report['source_sha']}\n")
    except (GateError, KeyError, TypeError, AttributeError, ValueError, OSError) as error:
        reason = str(error) if isinstance(error, GateError) else "governance_metadata_invalid"
        print(f"release-governance: BLOCKED reason={reason}", file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
