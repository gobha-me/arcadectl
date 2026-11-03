# Private storage identity and protection history

Review record for #174, based on main
`0225dc4a1da171b3aa07028ab8e94e7e77ea8cf5`. This documents the accepted-limitation
option offered by that issue. It requires security-owner review before merge;
it does not claim that same-tick protection changes are detected.

## What confirmation establishes

[`privatefs`](../internal/privatefs/privatefs.go) opens a descriptor-anchored,
effective-user-owned `0700` directory without following symlinks. Each private
file observation checks the current owner, regular-file type, `0600` mode and
single link. `FileIdentity` compares device, inode, SHA-256 content digest and
ctime. `ConfirmDurable` and
[`ConfirmDurableComparing`](../internal/privatefs/confirm_comparing.go) perform
fresh reads and metadata checks around file/directory synchronization. An unsafe
mode observed during any of those checks is refused. Changed bytes cannot be
accepted merely because their ctime happens to match.

These checks observe file state. They are not an audit log of every intermediate
permission transition. The [Linux stat manual](https://man7.org/linux/man-pages/man2/stat.2.html)
(accessed 2026-11-03) describes metadata observations, including the possibility
that fields come from different moments during a concurrent change. The
[statx field list](https://man7.org/linux/man-pages/man2/statx.2.html)
(accessed 2026-11-03) likewise describes timestamps and current attributes; a
higher-resolution timestamp representation is not a unique change sequence.

## Explicit limitation and threat-model reason

A file can change `0600 -> 0644 -> 0600` and retain the same observed ctime tick.
If device, inode and bytes also remain the same, `FileIdentity` has no signal
that distinguishes that history from an unchanged file. That file can confirm
successfully. This is the limitation accepted within the following proposed
trust boundary, not a newly implemented detection mechanism.

The file owner and privileged local principals are trusted to maintain private
storage. [chmod(2)](https://man7.org/linux/man-pages/man2/chmod.2.html) (accessed
2026-11-03) requires the owning effective UID or privilege to change these mode
bits. An unrelated unprivileged UID cannot induce this transition by chmod on
our owned file. A hostile process with the same UID, a compromised owner, root
or filesystem control is outside this boundary: such a principal can read, or grant themselves access to, the protected bytes
and can interfere with private storage. The
`0700` directory is a separate access boundary; an intermediate file-mode change
alone does not grant another UID traversal through it.

This is **not** proof that a secret was never exposed. Trusted-owner mistakes,
existing file descriptors, alternate access paths or other trusted-principal
actions can disclose bytes; later confirmation cannot undo disclosure. If an
operator suspects exposure, stop use of that credential and rotate it under the
existing credential procedure. Do not treat restoring mode or a successful
confirmation as evidence that rotation is unnecessary.

The security-owner decision is whether this local-owner trust boundary is
acceptable for #174. A threat model that includes hostile same-UID writers or
requires historical protection auditing needs a separate stronger contract;
this document does not grant that guarantee. Keeping an original descriptor
witness protects against inode replacement, but does not by itself record chmod
history on the same inode. Adding mtime, file size or current mode cannot recover
an intermediate mode that has already been restored with identical metadata.
The [ext4 inode layout](https://docs.kernel.org/filesystems/ext4/inodes.html)
(accessed 2026-11-03) distinguishes timestamps and generation/version fields;
that is not a portable promise that the current `fstat` identity exposes an
unforgeable permission-change counter. No privileged filesystem configuration,
arbitrary delay or unreviewed event-watcher lifetime is introduced here.

## Tests and the stronger-contract counterexample

`TestSameTickProtectionRestorationBoundary` uses real chmod/read/confirmation
calls. It searches a bounded number of immediate transitions with unchanged
device, inode, digest and ctime, with no sleep and no requirement that a
timestamp advance. A future additional identity signal does not disable the
stronger-contract probe by changing its fixture precondition. On a host
where no same-tick pair is observed it skips with an explicit reason. On a host
where a pair exists, it asserts the documented confirmation result for both
confirmation implementations. Separate tests still require refusal while the
file is actually `0644` and after its bytes change.

The optional `privatefs_history_probe` build tag enables
`TestSameTickProtectionHistoryStrongerContractProbe`. It uses that same real
counterexample and requires historical-mode-change detection. It is expected to
**fail on current production behavior** when the host reproduces the same-tick
pair. It preserves #174's stronger regression demand as a runnable proof, not a
claim that documenting the limitation makes that demand green:

```sh
go test -p 2 -count=1 -tags=privatefs_history_probe ./internal/privatefs -run '^TestSameTickProtectionHistoryStrongerContractProbe$'
```

Run tests through the required heavy-run wrapper. The ordinary suite certifies
the documented state-observation boundary; it does not certify the stronger
probe. Accepting the limitation or requiring a future detector is an explicit
review decision. Existing assertions have not been weakened to hide this gap;
the inaccurate comment about guaranteed ctime advancement is corrected, while
its existing refusal assertion is preserved. The distinct #161 fixture repair
and #160 review remain separate work.
