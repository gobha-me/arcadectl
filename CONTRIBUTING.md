# Contributing

Arcadectl is building a small, evidence-backed core before expanding its game
catalog or user interface.

## Documentation checks

`make verify-generated` also checks repository-local Markdown destinations and
heading anchors. Run `make verify-doc-links` for a quick documentation check.
Inline links, reference definitions, local images and HTML links are checked;
fenced/indented examples and inline code are ignored. External URLs are not
fetched. Use paths relative to the source document, and preserve the exact
heading anchor when linking within Markdown. This check does not establish
that operator commands were exercised against a release candidate; that remains
part of the exact-candidate documentation acceptance in issue #40.

Documentation-only pull requests must also run `make verify-doc-links`. CI scope
selection must keep this lightweight check mandatory even when Go, image, or
Kind jobs are skipped. A passing code-scope gate does not replace this check.

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
