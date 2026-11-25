import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gates_doctor as gd  # noqa: E402

GOOD_WF = """name: ci
on: [pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@0123456789abcdef0123456789abcdef01234567 # v3
      - run: pytest
"""
BAD_WF = """name: greet
on: pull_request_target
jobs:
  hi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some/action@v1
      - run: |
          echo "Thanks for ${{ github.event.pull_request.title }}"
          echo ok
      - run: echo "${{ github.sha }}"
"""


class Fake(gd.Source):
    def __init__(self, api=None, files=None, wfs=None):
        self.api, self.files, self.wfs = api or {}, files or {}, wfs or []

    def get(self, path):
        return self.api.get(path, (404, {"message": "Not Found"}))

    def file(self, path):
        return self.files.get(path)

    def workflows(self):
        return [gd.Workflow(p, t) for p, t in self.wfs]


def by_id(results):
    return {r.id: r for r in results}


def strong_repo():
    return Fake(api={
        "": (200, {"default_branch": "main", "delete_branch_on_merge": True, "security_and_analysis": {
            "secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "enabled"}}}),
        "/rules/branches/main": (200, [
            {"type": "pull_request", "parameters": {"required_approving_review_count": 1, "require_code_owner_review": True,
                                                    "dismiss_stale_reviews_on_push": True}},
            {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "test"}]}},
            {"type": "non_fast_forward"}, {"type": "deletion"}]),
        "/vulnerability-alerts": (204, None),
        "/actions/permissions/workflow": (200, {"default_workflow_permissions": "read"}),
    }, files={".github/CODEOWNERS": "* @org/team", ".github/dependabot.yml": "version: 2", "SECURITY.md": "x"},
        wfs=[(".github/workflows/ci.yml", GOOD_WF)])


def test_strong_repo_scores_100():
    results, meta = gd.run_checks(strong_repo())
    assert all(r.status == gd.PASS for r in results), [r for r in results if r.status != gd.PASS]
    assert gd.score(results) == 100 and meta["default_branch"] == "main"


def test_unprotected_repo_fails_branch_checks():
    src = Fake(api={"": (200, {"default_branch": "main"}),
                    "/rules/branches/main": (200, []),
                    "/branches/main/protection": (404, {"message": "Branch not protected"})})
    r = by_id(gd.run_checks(src)[0])
    assert r["branch-pr-required"].status == gd.FAIL
    assert r["branch-required-checks"].status == gd.FAIL
    assert r["ci-present"].status == gd.FAIL
    assert gd.score(list(r.values())) < 40


def test_no_access_is_unknown_and_not_scored():
    src = Fake(api={"": (200, {"default_branch": "main"}), "/rules/branches/main": (403, {}),
                    "/branches/main/protection": (403, {})},
               files={".github/CODEOWNERS": "x", ".github/dependabot.yml": "x"},
               wfs=[(".github/workflows/ci.yml", GOOD_WF)])
    results, _ = gd.run_checks(src)
    r = by_id(results)
    assert r["branch-pr-required"].status == gd.UNKNOWN
    assert r["secret-scanning"].status == gd.UNKNOWN
    assert gd.score(results) > 80


def test_classic_protection_is_understood():
    src = Fake(api={"": (200, {"default_branch": "dev"}), "/rules/branches/dev": (200, []),
                    "/branches/dev/protection": (200, {
                        "required_pull_request_reviews": {"required_approving_review_count": 2},
                        "required_status_checks": {"contexts": ["ci"]},
                        "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": False}})})
    r = by_id(gd.run_checks(src)[0])
    assert r["branch-pr-required"].status == gd.PASS and r["branch-approvals"].status == gd.PASS
    assert "ci" in r["branch-required-checks"].detail


def test_bad_workflow_findings():
    src = Fake(api={"": (200, {"default_branch": "main"})}, wfs=[(".github/workflows/greet.yml", BAD_WF)])
    r = by_id(gd.run_checks(src)[0])
    assert r["actions-pinned"].status == gd.FAIL and "some/action@v1" in r["actions-pinned"].detail
    assert r["workflow-permissions"].status == gd.FAIL
    assert r["pull-request-target"].status == gd.FAIL
    assert r["script-injection"].status == gd.FAIL and ":12" in r["script-injection"].detail
    assert ":14" not in r["script-injection"].detail  # github.sha is safe


def test_injection_single_line_run():
    assert gd._injections("steps:\n  - run: echo ${{ github.head_ref }}\n") == [2]
    assert gd._injections("steps:\n  - run: echo ${{ github.sha }}\n") == []


def test_token_write_default_fails():
    src = strong_repo()
    src.api["/actions/permissions/workflow"] = (200, {"default_workflow_permissions": "write"})
    assert by_id(gd.run_checks(src)[0])["token-read-only"].status == gd.FAIL


def test_local_mode(tmp_path):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(GOOD_WF)
    (tmp_path / ".github" / "dependabot.yml").write_text("version: 2")
    results, _ = gd.run_checks(gd.LocalSource(tmp_path), offline=True)
    r = by_id(results)
    assert r["branch-pr-required"].status == gd.UNKNOWN
    assert r["dependency-updates"].status == gd.PASS and r["codeowners"].status == gd.FAIL


def test_cli_local_json_and_min_score(tmp_path, capsys):
    assert gd.main(["--local", str(tmp_path), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["grade"] in "ABCDF" and data["results"]
    assert gd.main(["--local", str(tmp_path), "--min-score", "101"]) == 1


def test_render_formats():
    results, meta = gd.run_checks(strong_repo())
    assert "Score: 100/100" in gd.render(results, meta, "o/r", "text")
    assert gd.render(results, meta, "o/r", "markdown").startswith("# gates-doctor: o/r")
