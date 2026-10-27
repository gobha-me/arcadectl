# Contributing

Arcadectl is building a small, evidence-backed core before expanding its game
catalog or user interface.

Contributions should:

- preserve the game-neutral platform boundary;
- put game-specific behavior behind a game adapter;
- add or extend conformance tests for contract changes;
- preserve world data unless an operation is explicitly destructive;
- validate before mutation and fail closed on ambiguous input;
- avoid credentials and private infrastructure details in code, fixtures,
  logs, issues, and pull requests; and
- include tests that demonstrate the claimed behavior.

Run the commands in the README before opening a pull request. Substantive work
is merged through a pull request after required checks pass. When API types
change, run `make generate` and commit the resulting DeepCopy and CRD artifacts.

See [CI operation and budgets](docs/ci-efficiency.md) for required-check behavior,
nightly runs, timeout measurements and cache ownership. Retry failed or flaky
runs with `gh run rerun <run-id> --failed` (UI: **Re-run failed jobs**), never
**Re-run all jobs**: October's full reruns consumed 5,017 minutes.
