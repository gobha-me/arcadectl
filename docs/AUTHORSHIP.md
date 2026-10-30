# Agent authorship and historical correction

This record addresses [issue #115](https://github.com/gobha-me/arcadectl/issues/115).
It records provenance without changing published commit history.

Commit `0a1c84edd3` on the former `wave0/kind137-phase-attribution` branch
([PR #104](https://github.com/gobha-me/arcadectl/pull/104)) was written by
Codex (gpt-6.1-sol). It includes both production and test changes and lacks
agent trailers. A planned second test author did not produce those tests;
they must not be attributed to that author or described as independent.

The subsequent production correction, `282e15cb5f`, was written by Codex.
The subsequent tests, `9cfa238532`, were written by Antigravity. Those tests
failed against `0a1c84edd3` and passed against `282e15cb5f`, as recorded in
issue #115. This is historical evidence from that issue, not a new execution
of those old trees.

The work was recreated under the agent commit identity in
[PR #128](https://github.com/gobha-me/arcadectl/pull/128). The initial mapping is:

| Historical commit | Agent-identity replacement | Authoring agent / role |
| --- | --- | --- |
| `0a1c84edd3` | `7f8f310f38` | Codex / change, including original test hunks |
| `282e15cb5f` | `0118ff3327` | Codex / change |
| `9cfa238532` | `82ecf9f96b` | Antigravity / tests |

Later commits in #128 removed the original code-author tests and introduced
independently written tests. Review the final PR tree and its exact CI head;
the mapping above does not certify either current correctness or CI success.

For new agent contributions, keep author and committer identity separate from
the repository owner's identity. This maintenance run uses
`Projects Lead (agent) <agents@noreply.invalid>`, with an agent attribution and
an explicit role on each commit:

```text
Agent: Codex (via Projects Lead)
Agent-Role: change
```

Tests written by the same agent belong in separate commits and disclose the
remaining independent-author requirement:

```text
Agent: Codex (via Projects Lead)
Agent-Role: tests (Codex, needs non-author re-make)
```

The agent/role lines disclose who performed the work without claiming joint
authorship. A reviewer, test executor, or planned second author must not receive
a co-author trailer for work they did not write. New remediation commits in this
maintenance pass carry no co-author trailers. Preserve already published
history; a false historical trailer requires an explicit correction during the
eventual owner-controlled squash, not a force push.

Executing another author's tests does not make the executor their author.
Executing one's own tests does not establish independent verification. Preserve
these distinctions in PR descriptions, reports, and future corrections.
