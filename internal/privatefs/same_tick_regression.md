# Same-tick protection regression fixture

`TestRestoredProtectionWithinSameCTimeTickInvalidatesIdentity` records issue
[#174](https://github.com/gobha-me/arcadectl/issues/174). Its explicit bug skip
keeps the known production gap visible without claiming that every filesystem
can reproduce it.

Run the unskipped test only in a privatefs-approved temporary directory whose
ancestors pass the normal trust checks, on a real filesystem where creation and
both `chmod` operations can share one ctime value. The fixture requires an actual
`0600 → 0644 → 0600` protection change, identical before/exposed/restored ctime,
and unchanged file identity and contents. It then requires `ErrChanged` from
each public confirmation API.

For a diagnostic run, remove only the named bug skip in a disposable test copy,
run the focused test once, and restore the skip. A failure at the final
`ErrChanged` assertion with every fixture precondition satisfied reproduces the
bug. A rejected temporary directory or a changed ctime establishes only that the
fixture is unsuitable; neither is bug reproduction. Preserve the failure output
and identify which assertion failed.

Do not add waits or retry until ctime changes: the regression concerns a change
that ctime cannot distinguish. Release the skip after the issue's behavior or
accepted-limitation decision is reviewed and its required evidence is available.
