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

For new agent contributions, use the author and committer identity
`Projects Lead (agent) <agents@noreply.invalid>`, separate from the repository
owner's identity. The subject must summarize the change; never use an `Agent:`
line as the subject. Explain the work in the body, then end with these trailers
in this order:

```text
Agent-Role: change
Agent: Codex (gpt-6.1-sol)
Co-authored-by: Codex (gpt-6.1-sol) <agents@noreply.invalid>
```

Use the role that describes the work, such as `change` or
`tests (non-author test lane)`. Include the authoring agent and its exact model
in the `Agent:` trailer, exactly once, followed by its `Co-authored-by:` trailer.
The block above shows the required convention for Codex (gpt-6.1-sol).
A reviewer, test executor, or planned second author must not receive a co-author
trailer for work they did not write.

Older commits predate this convention and can lack an `Agent:` trailer. In this
PR's original range, `0225dc4..d46c6a7`, `5dbed74` has co-author and role trailers
but no `Agent:` trailer, and `d46c6a7` has no trailers. Preserve published history;
apply the required trailer block in the eventual owner-controlled squash message
rather than rewriting those commits. Correct any false historical attribution
explicitly in that squash message.

Executing another author's tests does not make the executor their author.
Executing one's own tests does not establish independent verification. Preserve
these distinctions in PR descriptions, reports, and future corrections.
