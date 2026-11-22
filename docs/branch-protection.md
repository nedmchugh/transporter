# Branch protection

The implementer cannot change repository settings. The maintainer should
apply the settings below to `main` (CI-8; maintainer open item 3).

## Required status checks

These are the exact check names produced by the workflows. Keep this list
in sync with job names in `.github/workflows/`.

| Workflow | Check name |
| --- | --- |
| ci | `lint` |
| ci | `test (ubuntu-latest, go 1.26.x)` |
| ci | `test (ubuntu-latest, go 1.27.x)` |
| ci | `test (macos-latest, go 1.26.x)` |
| ci | `test (macos-latest, go 1.27.x)` |
| ci | `test (windows-latest, go 1.26.x)` |
| ci | `test (windows-latest, go 1.27.x)` |
| ci | `e2e (ubuntu-latest)` |
| ci | `e2e (macos-latest)` |
| ci | `e2e (windows-latest)` |
| ci | `fuzz-smoke` |
| ci | `vuln` |
| ci | `license` |
| ci | `build` |
| ci | `docker-build` |
| ci | `install (ubuntu-latest, docker)` |
| ci | `install (ubuntu-latest, local)` |
| ci | `install (macos-latest, local)` |
| ci | `mod-tidy` |
| ci | `docs` |
| codeql | `codeql` |
| dependency-review | `dependency-review` |

While the repository is private, the `codeql` and `dependency-review`
jobs are skipped unless the repository variable `ENABLE_CODE_SCANNING` is
`true` (they need GitHub Advanced Security there; DECISIONS.md D-9.5). A
skipped job still satisfies a required check, so they can stay in the list.

When the minimum or latest Go version changes, the `test` check names
change too; update the protection rule at the same time.

## Recommended settings for `main`

- Require a pull request before merging, with no required approvals:
  the project has a single maintainer, and GitHub does not let an author
  approve their own pull request. Dismiss stale approvals. When there are
  other regular contributors, require one approving review and review from
  code owners (`.github/CODEOWNERS`).
- Require the status checks above to pass, and require branches to be up to
  date before merging.
- Require conversation resolution before merging.
- Require linear history.
- Do not allow force pushes or deletions.
- Apply the rules to administrators too.
- In repository settings, enable private vulnerability reporting (used by
  `SECURITY.md`), Dependabot alerts and security updates, and secret
  scanning.

## Applying with `gh`

Run:

```sh
gh api -X PUT repos/nedmchugh/transporter/branches/main/protection \
  -H "Accept: application/vnd.github+json" --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      {"context": "lint"},
      {"context": "test (ubuntu-latest, go 1.26.x)"},
      {"context": "test (ubuntu-latest, go 1.27.x)"},
      {"context": "test (macos-latest, go 1.26.x)"},
      {"context": "test (macos-latest, go 1.27.x)"},
      {"context": "test (windows-latest, go 1.26.x)"},
      {"context": "test (windows-latest, go 1.27.x)"},
      {"context": "e2e (ubuntu-latest)"},
      {"context": "e2e (macos-latest)"},
      {"context": "e2e (windows-latest)"},
      {"context": "fuzz-smoke"},
      {"context": "vuln"},
      {"context": "license"},
      {"context": "build"},
      {"context": "docker-build"},
      {"context": "install (ubuntu-latest, docker)"},
      {"context": "install (ubuntu-latest, local)"},
      {"context": "install (macos-latest, local)"},
      {"context": "mod-tidy"},
      {"context": "docs"},
      {"context": "codeql"},
      {"context": "dependency-review"}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 0,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": false
  },
  "restrictions": null,
  "required_linear_history": true,
  "required_conversation_resolution": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

Private vulnerability reporting can be enabled with:

```sh
gh api -X PUT repos/nedmchugh/transporter/private-vulnerability-reporting
```
