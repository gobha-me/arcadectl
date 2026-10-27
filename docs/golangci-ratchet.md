# Golangci-lint baseline and ratchet

[Issue #96](https://github.com/gobha-me/arcadectl/issues/96) establishes a
configuration-only baseline. `.golangci.yml` enables exactly `errcheck`, `govet`,
`ineffassign`, `staticcheck`, and `unused`, with a 15-minute timeout and concurrency
of two. Use golangci-lint v2.15.0 (built with Go 1.27.0). The original intake
command was:

```sh
golangci-lint run ./... --no-config --timeout=15m --concurrency=2 \
  --enable-only=errcheck,govet,ineffassign,staticcheck,unused
```

The original intake printed 121 findings, but its default reporting limits
capped each linter at 50 findings and each identical message at three. An
uncapped scan of the same tree, with same-line deduplication disabled, found
**532 existing findings**, including all 121 intake locations. The committed
baseline covers the full inventory so a configured run can pass without fixing
production code:

| Linter | Original capped intake | Remaining baseline |
| --- | ---: | ---: |
| errcheck | 50 | 300 |
| govet | 3 | 3 |
| ineffassign | 9 | 9 |
| staticcheck | 50 | 211 |
| unused | 9 | 9 |
| Total | 121 | 532 |

The committed baseline lives directly in `.golangci.yml`: 322 exclusions match
the exact file path, linter, and complete diagnostic text. Each rule records the
original line:column locations; identical messages in the same file share a rule.
Those locations are cleanup hints and do not constrain matching. Golangci-lint
v2 uses [`linters.exclusions.rules`](https://golangci-lint.run/docs/configuration/file/#linters-configuration)
for these exclusions. Tests remain included, and no linter is disabled by path.

Run from the repository root with golangci-lint v2.15.0:

```sh
golangci-lint config verify
golangci-lint run ./...
```

On a shared worker, check `pgrep -af stryker` first and defer while Stryker is
running. Hold `/config/projects/logs/heavy.lock` around each invocation, for
example `flock -n /config/projects/logs/heavy.lock golangci-lint run ./...`.
If the lock is busy, defer the run. Keep core dumps enabled and directed to
`/config/coredumps`; investigate any dump before deleting it.

Wave 0 validation on 2026-10-27 passed config verification and a full configured
scan with **0 issues**, under that lock. The worker used an absolute repository
package pattern and a temporary Go workspace from `/config/coredumps` so any
core dump would land there. No unused-exclusion warnings were emitted.

The ratchet targets zero exclusions:

1. Fix findings in small follow-up changes, with relevant behavioral tests.
2. Remove the matching rule and its location comment in the same change. If a
   rule covers several locations, remove fixed locations from the comment and
   keep the rule until every matching finding in that file is fixed.
3. Run config validation and the full lint command. Address unused-exclusion
   warnings by removing stale rules. Update the remaining baseline counts and
   rule count above and in the config comment whenever the baseline shrinks.
4. Fix new findings instead of adding or broadening exclusions. Keep issue output
   limits disabled so new diagnostics cannot be hidden by reporting caps.

Exact text rules still suppress a new occurrence of the same diagnostic in the
same file. Review changes to baselined files for this case. To audit all remaining
debt, bypass the baseline and reporting limits under the same shared-worker lock:

```sh
golangci-lint run ./... --no-config --timeout=15m --concurrency=2 \
  --enable-only=errcheck,govet,ineffassign,staticcheck,unused \
  --max-issues-per-linter=0 --max-same-issues=0 --uniq-by-line=false
```

Reconcile the inventory during tool upgrades rather than silently regenerating
exclusions. Remove the exclusions block when the baseline reaches zero.

CI wiring for [issue #106](https://github.com/gobha-me/arcadectl/issues/106) uses
the SHA-pinned official golangci-lint action with v2.15.0 on PRs and main pushes.
The job verifies this config and scans all packages with an explicit failure
exit code for unsuppressed findings. The exclusions are the ratchet: baseline
findings pass, and findings outside those rules fail, including outside changed
lines. The required Go and policy gate also requires this job to succeed.
GOMAXPROCS=2 and GOMEMLIMIT=1GiB match the other policy workers; the config's
15-minute lint timeout and concurrency of two remain in force. Atlas permits
this additive CI job under #106; it depends on the baseline from #98. Independent
verification confirmed `actionlint`, `golangci-lint config verify`, a 0-issue
full-tree scan with `--issues-exit-code=1`, fail-closed detection of an
unsuppressed probe finding, and `TestInstallerAdmissionCIProfilesAndFailClosedRequiredGate`.
