#!/usr/bin/env python3
"""gates-doctor: read-only audit of a GitHub repository's quality and security gates.

Scores branch protection/rulesets, review rules, required checks, CODEOWNERS, Dependabot,
secret scanning, GITHUB_TOKEN defaults and workflow hygiene (SHA pinning, permissions,
pull_request_target, script injection), and prints the exact fix for every failed check.

Read-only: it only sends GET requests. Checks that need admin rights are reported as
UNKNOWN (with the permission needed) and do not lower the score.
Standard library only.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

__version__ = "1.0.0"
PASS, FAIL, WARN, UNKNOWN = "PASS", "FAIL", "WARN", "UNKNOWN"


@dataclass
class Result:
    id: str
    title: str
    status: str
    weight: int
    detail: str = ""
    fix: str = ""


@dataclass
class Workflow:
    path: str
    text: str


class Source:
    """Where repository facts come from (GitHub API or a local checkout)."""

    def get(self, path: str) -> tuple[int, object]:  # pragma: no cover - interface
        raise NotImplementedError

    def file(self, path: str) -> str | None:  # pragma: no cover - interface
        raise NotImplementedError

    def workflows(self) -> list[Workflow]:  # pragma: no cover - interface
        raise NotImplementedError


class GitHubSource(Source):
    def __init__(self, repo: str, token: str, api: str = "https://api.github.com"):
        self.repo, self.token, self.api = repo, token, api.rstrip("/")
        self._cache: dict[str, tuple[int, object]] = {}

    def get(self, path: str) -> tuple[int, object]:
        url = f"{self.api}/repos/{self.repo}{path}"
        if url in self._cache:
            return self._cache[url]
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": f"gates-doctor/{__version__}"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed GitHub API host
                body = resp.read()
                result = (resp.status, json.loads(body) if body else None)
        except urllib.error.HTTPError as exc:
            try:
                result = (exc.code, json.loads(exc.read() or b"null"))
            except ValueError:
                result = (exc.code, None)
        self._cache[url] = result
        return result

    def file(self, path: str) -> str | None:
        status, data = self.get(f"/contents/{urllib.parse.quote(path)}")
        if status == 200 and isinstance(data, dict) and data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", "replace")
        return None

    def workflows(self) -> list[Workflow]:
        status, data = self.get("/contents/.github/workflows")
        if status != 200 or not isinstance(data, list):
            return []
        out = []
        for item in data:
            if item.get("name", "").endswith((".yml", ".yaml")):
                text = self.file(item["path"])
                if text is not None:
                    out.append(Workflow(item["path"], text))
        return out


class LocalSource(Source):
    """Offline mode: only file-based checks; API-only checks become UNKNOWN."""

    def __init__(self, root: Path):
        self.root = root

    def get(self, path: str) -> tuple[int, object]:
        return 0, None

    def file(self, path: str) -> str | None:
        p = self.root / path
        return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None

    def workflows(self) -> list[Workflow]:
        d = self.root / ".github" / "workflows"
        return [Workflow(f".github/workflows/{p.name}", p.read_text(encoding="utf-8", errors="replace"))
                for p in sorted(d.glob("*.y*ml"))] if d.is_dir() else []


# ------------------------------------------------------------------ checks

USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)", re.M)
SHA = re.compile(r"@[0-9a-f]{40}$")
INJECTABLE = re.compile(r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)"
                        r"[^}]*\b(title|body|head_ref|label|name|message|email|ref)\b[^}]*|github\.head_ref)\s*\}\}")
RUN_BLOCK = re.compile(r"^(\s*)(-\s*)?run:\s*(\|[-+]?|>[-+]?)?(.*)$")


def _branch_rules(src: Source, branch: str) -> tuple[str, dict]:
    """Merge rulesets (readable with read access) and classic protection (admin) into one view."""
    view: dict = {"pr": False, "approvals": 0, "checks": [], "no_force": False, "no_delete": False,
                  "codeowners": False, "dismiss_stale": False, "enforce_admins": None}
    known = False
    status, rules = src.get(f"/rules/branches/{urllib.parse.quote(branch, safe='')}")
    if status == 200 and isinstance(rules, list):
        known = True
        for r in rules:
            t, p = r.get("type"), r.get("parameters") or {}
            if t == "pull_request":
                view["pr"] = True
                view["approvals"] = max(view["approvals"], int(p.get("required_approving_review_count", 0)))
                view["codeowners"] |= bool(p.get("require_code_owner_review"))
                view["dismiss_stale"] |= bool(p.get("dismiss_stale_reviews_on_push"))
            elif t == "required_status_checks":
                view["checks"] += [c.get("context") for c in p.get("required_status_checks", [])]
            elif t == "non_fast_forward":
                view["no_force"] = True
            elif t == "deletion":
                view["no_delete"] = True
    status, prot = src.get(f"/branches/{urllib.parse.quote(branch, safe='')}/protection")
    if status == 200 and isinstance(prot, dict):
        known = True
        rev = prot.get("required_pull_request_reviews")
        if rev:
            view["pr"] = True
            view["approvals"] = max(view["approvals"], int(rev.get("required_approving_review_count", 0)))
            view["codeowners"] |= bool(rev.get("require_code_owner_reviews"))
            view["dismiss_stale"] |= bool(rev.get("dismiss_stale_reviews"))
        rsc = prot.get("required_status_checks") or {}
        view["checks"] += list(rsc.get("contexts") or []) + [c.get("context") for c in rsc.get("checks") or []]
        if not (prot.get("allow_force_pushes") or {}).get("enabled", False):
            view["no_force"] = True
        if not (prot.get("allow_deletions") or {}).get("enabled", False):
            view["no_delete"] = True
        view["enforce_admins"] = (prot.get("enforce_admins") or {}).get("enabled")
    elif status == 404 and isinstance(prot, dict) and "not protected" in str(prot.get("message", "")).lower():
        known = True
    view["checks"] = sorted({c for c in view["checks"] if c})
    return ("known" if known else "unknown"), view


def run_checks(src: Source, offline: bool = False) -> tuple[list[Result], dict]:
    results: list[Result] = []
    meta: dict = {}
    status, repo = src.get("")
    branch = (repo or {}).get("default_branch", "main") if status == 200 else "main"
    meta["default_branch"] = branch
    settings_url = "Settings → Rules → Rulesets → New branch ruleset (target: default branch)"

    if offline:
        rules_state, view = "unknown", {}
    else:
        rules_state, view = _branch_rules(src, branch)

    def add(id_, title, ok, weight, detail="", fix="", warn=False):
        st = UNKNOWN if ok is None else (PASS if ok else (WARN if warn else FAIL))
        results.append(Result(id_, title, st, weight, detail, fix if st != PASS else ""))

    unknown_rules = rules_state == "unknown"
    add("branch-pr-required", f"Pull request required to merge into {branch}", None if unknown_rules else view["pr"], 15,
        "" if not unknown_rules else "needs read access to rulesets or admin for branch protection",
        f"{settings_url}: enable 'Require a pull request before merging'.")
    add("branch-approvals", "At least one approving review", None if unknown_rules else view["approvals"] >= 1, 10,
        "" if unknown_rules else f"required approvals: {view['approvals']}",
        "In the same rule set 'Required approvals' to 1 or more.")
    add("branch-required-checks", "Required status checks before merge", None if unknown_rules else bool(view["checks"]), 15,
        "" if unknown_rules else ("checks: " + ", ".join(view["checks"]) if view["checks"] else "no required checks"),
        "Enable 'Require status checks to pass' and add your CI job names (test, lint, build).")
    add("branch-no-force-push", "Force pushes and branch deletion blocked",
        None if unknown_rules else (view["no_force"] and view["no_delete"]), 10,
        "", "Enable 'Block force pushes' and 'Restrict deletions'.")
    add("branch-dismiss-stale", "New commits dismiss stale approvals", None if unknown_rules else view["dismiss_stale"], 3,
        "", "Enable 'Dismiss stale pull request approvals when new commits are pushed'.", warn=True)

    codeowners = next((p for p in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS") if src.file(p)), None)
    add("codeowners", "CODEOWNERS file", bool(codeowners), 5, codeowners or "",
        "Add .github/CODEOWNERS (e.g. '* @your-org/team' and owners for auth/, billing/, .github/).")
    if codeowners and not unknown_rules:
        add("codeowners-enforced", "Code owner review required", view["codeowners"], 3, "",
            "Enable 'Require review from Code Owners' in the ruleset.", warn=True)

    dep_cfg = next((p for p in (".github/dependabot.yml", ".github/dependabot.yaml", "renovate.json", ".github/renovate.json",
                                "renovate.json5") if src.file(p)), None)
    add("dependency-updates", "Automated dependency updates (Dependabot or Renovate)", bool(dep_cfg), 8, dep_cfg or "",
        "Add .github/dependabot.yml with your ecosystems (pip, npm, github-actions) on a weekly schedule.")

    if offline:
        add("vulnerability-alerts", "Dependabot security alerts", None, 6, "API only")
        add("secret-scanning", "Secret scanning + push protection", None, 8, "API only")
        add("token-read-only", "GITHUB_TOKEN default is read-only", None, 8, "API only")
    else:
        s, _ = src.get("/vulnerability-alerts")
        add("vulnerability-alerts", "Dependabot security alerts", True if s == 204 else (False if s == 404 else None), 6,
            "" if s in (204, 404) else "needs admin access",
            "Settings → Code security → enable Dependabot alerts.")
        sa = (repo or {}).get("security_and_analysis") if status == 200 else None
        if sa:
            ss = (sa.get("secret_scanning") or {}).get("status") == "enabled"
            pp = (sa.get("secret_scanning_push_protection") or {}).get("status") == "enabled"
            add("secret-scanning", "Secret scanning + push protection", ss and pp, 8,
                f"secret scanning: {'on' if ss else 'off'}, push protection: {'on' if pp else 'off'}",
                "Settings → Code security → enable Secret scanning and Push protection.")
        else:
            add("secret-scanning", "Secret scanning + push protection", None, 8, "needs admin access")
        s, perms = src.get("/actions/permissions/workflow")
        if s == 200 and isinstance(perms, dict):
            ro = perms.get("default_workflow_permissions") == "read"
            add("token-read-only", "GITHUB_TOKEN default is read-only", ro, 8,
                f"default: {perms.get('default_workflow_permissions')}, can approve PRs: {perms.get('can_approve_pull_request_reviews')}",
                "Settings → Actions → General → Workflow permissions → 'Read repository contents'.")
        else:
            add("token-read-only", "GITHUB_TOKEN default is read-only", None, 8, "needs admin access")

    wfs = src.workflows()
    meta["workflows"] = len(wfs)
    if wfs:
        unpinned, no_perms, prt, inject = [], [], [], []
        for wf in wfs:
            for ref in USES.findall(wf.text):
                if ref.startswith("./") or ref.startswith("docker://"):
                    continue
                if not SHA.search(ref):
                    unpinned.append(f"{wf.path}: {ref}")
            if not re.search(r"^permissions:", wf.text, re.M):
                no_perms.append(wf.path)
            if re.search(r"\bpull_request_target\b", wf.text) and re.search(r"github\.event\.pull_request\.head\.(sha|ref)", wf.text):
                prt.append(wf.path)
            inject += [f"{wf.path}:{n}" for n in _injections(wf.text)]
        third_party = [u for u in unpinned if not u.split(": ", 1)[1].startswith(("actions/", "github/"))]
        add("actions-pinned", "Third-party actions pinned to a commit SHA", not third_party, 6,
            f"{len(third_party)} unpinned: " + "; ".join(third_party[:5]) if third_party else f"{len(unpinned)} first-party tags (ok)",
            "Pin with the full SHA and keep the tag as a comment: uses: owner/action@<40-char-sha> # v4. Dependabot updates them.")
        add("workflow-permissions", "Every workflow declares top-level permissions", not no_perms, 6,
            ", ".join(no_perms), "Add 'permissions: { contents: read }' at the top of each workflow; widen per job only.")
        add("pull-request-target", "No pull_request_target that checks out PR code", not prt, 8, ", ".join(prt),
            "Never check out the PR head in pull_request_target. Use pull_request, or split into a privileged workflow_run.")
        add("script-injection", "No untrusted event data interpolated in run: steps", not inject, 8, ", ".join(inject[:6]),
            "Pass the value through env: (env: TITLE: ${{ github.event.pull_request.title }}) and use \"$TITLE\" in the script.")
    else:
        add("ci-present", "CI workflows present", False, 10, "no .github/workflows", "Add a workflow that runs tests on pull_request.")

    add("security-policy", "SECURITY.md (how to report vulnerabilities)",
        bool(src.file("SECURITY.md") or src.file(".github/SECURITY.md")), 2, "",
        "Add SECURITY.md with a private contact and expected response time.", warn=True)
    if status == 200 and isinstance(repo, dict):
        add("delete-branch-on-merge", "Head branches deleted after merge", bool(repo.get("delete_branch_on_merge")), 1, "",
            "Settings → General → 'Automatically delete head branches'.", warn=True)
    return results, meta


def _injections(text: str) -> list[int]:
    hits, in_run, run_indent = [], False, 0
    for n, line in enumerate(text.splitlines(), start=1):
        m = RUN_BLOCK.match(line)
        if m:
            in_run, run_indent = True, len(m.group(1))
            if m.group(4) and INJECTABLE.search(m.group(4)):
                hits.append(n)
            continue
        if in_run:
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())
            if stripped and indent <= run_indent:
                in_run = False
            elif INJECTABLE.search(line):
                hits.append(n)
    return hits


def score(results: list[Result]) -> int:
    evaluated = [r for r in results if r.status != UNKNOWN]
    total = sum(r.weight for r in evaluated)
    got = sum(r.weight for r in evaluated if r.status == PASS) + sum(r.weight // 2 for r in evaluated if r.status == WARN)
    return round(100 * got / total) if total else 0


def grade(s: int) -> str:
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


def render(results: list[Result], meta: dict, target: str, fmt: str) -> str:
    s = score(results)
    if fmt == "json":
        return json.dumps({"target": target, "score": s, "grade": grade(s), "meta": meta,
                           "results": [r.__dict__ for r in results]}, indent=2)
    icon = {PASS: "✅", FAIL: "❌", WARN: "⚠️", UNKNOWN: "❔"}
    if fmt == "markdown":
        out = [f"# gates-doctor: {target}", "", f"**Score {s}/100 · grade {grade(s)}**", "",
               "| | Check | Detail | Fix |", "|---|---|---|---|"]
        for r in results:
            out.append(f"| {icon[r.status]} | {r.title} | {r.detail} | {r.fix} |")
        return "\n".join(out)
    out = [f"gates-doctor {__version__} · {target} · default branch: {meta.get('default_branch')}",
           f"Score: {s}/100 (grade {grade(s)})", ""]
    for r in sorted(results, key=lambda r: [FAIL, WARN, UNKNOWN, PASS].index(r.status)):
        out.append(f"{r.status:7} {r.title}" + (f"  [{r.detail}]" if r.detail else ""))
        if r.fix and r.status in (FAIL, WARN):
            out.append(f"        fix: {r.fix}")
    unknown = [r for r in results if r.status == UNKNOWN]
    if unknown:
        out += ["", f"{len(unknown)} checks need more access and are not scored. Run with an admin token to include them."]
    return "\n".join(out)


def detect_token() -> str:
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if not tok:
        try:
            tok = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            tok = ""
    return tok


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="gates-doctor", description="Read-only audit of a GitHub repo's quality gates")
    ap.add_argument("repo", nargs="?", help="owner/name (omit with --local)")
    ap.add_argument("--local", type=Path, help="offline: audit files in a local checkout")
    ap.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    ap.add_argument("--min-score", type=int, default=0, help="exit 1 when the score is below this")
    ap.add_argument("--api", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    a = ap.parse_args(argv)
    if a.local:
        src: Source = LocalSource(a.local)
        target = str(a.local)
    elif a.repo and re.fullmatch(r"[\w.-]+/[\w.-]+", a.repo):
        src = GitHubSource(a.repo, detect_token(), a.api)
        status, data = src.get("")
        if status != 200:
            print(f"gates-doctor: cannot read {a.repo} (HTTP {status}: {(data or {}).get('message', '')}). "
                  "Set GITHUB_TOKEN or run 'gh auth login'.", file=sys.stderr)
            return 2
        target = a.repo
    else:
        ap.error("give owner/name or --local PATH")
        return 2
    results, meta = run_checks(src, offline=bool(a.local))
    print(render(results, meta, target, a.format))
    return 1 if score(results) < a.min_score else 0


if __name__ == "__main__":
    sys.exit(main())
