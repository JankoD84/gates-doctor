# gates-doctor

**Read-only audit of a GitHub repository's quality and security gates.** One command, a score out of 100, and the exact fix for every gap.

```bash
GITHUB_TOKEN=$(gh auth token) python3 gates_doctor.py your-org/your-repo
python3 gates_doctor.py --local .            # offline: files and workflows only
python3 gates_doctor.py org/repo --format markdown > gates-report.md
python3 gates_doctor.py org/repo --min-score 75   # fail CI below 75
```

```
Score: 41/100 (grade D)
FAIL    Every workflow declares top-level permissions  [ci.yml, deploy.yml]
        fix: Add 'permissions: { contents: read }' at the top of each workflow; widen per job only.
FAIL    Third-party actions pinned to a commit SHA  [docker/build-push-action@v6 …]
UNKNOWN Secret scanning + push protection  [needs admin access]
```

## What it checks

| Area | Checks |
|---|---|
| Branch rules (rulesets + classic protection) | PR required, ≥1 approval, required status checks, force push and deletion blocked, stale approvals dismissed |
| Ownership | CODEOWNERS present and enforced |
| Supply chain | Dependabot or Renovate configured, Dependabot alerts on, third-party actions pinned to SHA |
| Secrets | secret scanning and push protection |
| Actions | `GITHUB_TOKEN` read-only by default, top-level `permissions:` in every workflow, no `pull_request_target` that checks out PR code, no untrusted `${{ github.event.* }}` inside `run:` |
| Hygiene | SECURITY.md, delete head branches after merge |

## Safe by design

* Sends only `GET` requests. It cannot change your repository.
* Checks your token cannot see are **UNKNOWN** and excluded from the score, so a read-only token never produces a false fail.
* Standard library only. Python 3.10+. Token from `GITHUB_TOKEN`, `GH_TOKEN` or `gh auth token`.

Fixing the gaps is usually an afternoon of rulesets, CODEOWNERS and workflow hardening. If you'd rather have it done for you, see the About section below.

MIT License.

## About

Built by **Ján Ďuriš**, QA Automation Engineer (Playwright, Python, CI/CD). Part of a small set of open tools for release quality: [release-ready](https://github.com/JankoD84/release-ready) · [gates-doctor](https://github.com/JankoD84/gates-doctor) · [flaky-playwright-lab](https://github.com/JankoD84/flaky-playwright-lab) · [oncall-rota](https://github.com/JankoD84/oncall-rota) · [expiry-radar](https://github.com/JankoD84/expiry-radar) · [dependabot-tamer](https://github.com/JankoD84/dependabot-tamer)

Flaky tests, slow CI or releases nobody trusts? Find me on [Upwork](https://www.upwork.com/freelancers/~0198692795e824559b) or [LinkedIn](https://www.linkedin.com/in/jduris).
