# Independent baseline fixture review

Review date: 2026-11-09. Test session: `arcadectl-light-d1-20261109T2309Z`.
Scope: [issue #161](https://github.com/gobha-me/arcadectl/issues/161) and
[PR #162](https://github.com/gobha-me/arcadectl/pull/162), code head
`5532a0471f09983cf15e15f08b55e4ad9aa42140`, compared with main
`effbb5d4546b3788c25e53e6e5be014766cb27ef`.

This independent session reviewed the checked-out PR code, linked issue and
`tests-needed` hand-off. Compilation, runtime tests and mutation controls were
not run. The observations below are source review and text comparison, not a
runtime PASS or merge approval.

## Existing assertions

The original main assertion conditions and failure messages remain verbatim:
nine blocks in `TestConfirmComparingOperandBoundsAndFirstReadPrecedence` and
eight blocks in `testDirectReadPoolGetNotFoundAtFixture`. A text comparison
checked their presence and occurrence counts in the candidate; no original
block was missing or changed.

Privatefs retains the nil-store refusal, first path/protection error precedence
for bad operands, unsafe path/limit refusal and exact stale-identity
`ErrChanged` assertion. HTTP retains frozen identity, method, route and HTTP/1
checks; the exact sanitized response shape and absence classification; fixture
capture classification; surrounding successful reads; request, reuse, handshake
and sanitizer counts; and canonical parent provenance. Both ordinary reads and
derived private fixture reads exercise the real TLS transport.

## Independently remade ctime witness

The setup keeps the existing one-second witness deadline and one-millisecond
poll interval. Each attempt toggles mode to `0644` and restores `0600`, then
observes ctime through the anchored directory descriptor. This also covers a
filesystem that elides a chmod repeating the current mode. Failure to establish
a changed timestamp fails the test.

New assertions compare the before/after stat with only ctime and atime
normalized, require private ownership/mode/link protection, and independently
read back the original bytes. Device, inode and content digest must match the
opening identity; the fresh identity must have the observed changed ctime.
The original stale-identity refusal is followed by a fresh-identity success
control, for both ordinary and evidence confirmation methods. No bytes or
identity are replaced to manufacture the stale refusal.

## Incomplete HTTP responses

Known oversize, chunked oversize, gzip and gzip/chunked responses keep native
EOF unavailable. The known oversized response advertises 65536 bytes but sends
8193; the chunked response sends the same prefix without a terminating chunk.
The known gzip response omits its final advertised byte; gzip/chunked withholds
its chunk terminator. The existing truncated response still ends naturally
with a content-length mismatch. Successful reuse controls remain complete.

New handler channels establish entry into the EOF hold and join its completion
before cleanup releases it. At that point, the hold can finish only when the
native request context is cancelled. New five-second guards fail on missing
entry or completion; no existing timeout is increased. The original connection
counts remain exact. No round-tripper, read pool or confirmation method is
mocked.

Cleanup still registers server close before the release-channel close, so LIFO
cleanup releases a blocked handler before joining server shutdown. These
callbacks are registered before access construction and remain available when
an assertion fails. Native request cancellation also releases the hold.

## Expected regression evidence

On pre-fix main, the original ctime assertion can fail when rapid mode changes
share one timestamp, and the original non-reuse assertion can fail when a
transport drains a complete small response. At the candidate, changed ctime
and incomplete native responses are explicit prerequisites, with all original
refusals and counts retained. The stacked base already includes the first
fixture repair; a new runtime red against that base is not claimed.

The added metadata/content checks fail if witness setup changes the file or
fails to change its generation. Fresh-identity confirmation fails if the test
merely obtains a blanket refusal. The new HTTP guards fail if the EOF hold is
not entered or its handler survives native connection discard. These are
expected outcomes from source inspection; CI must supply compiled execution
at the final candidate SHA. Any mutation proof remains outside this light lane.

Both existing test functions were edited. This requires `[needs review]` and
Argus review even though their original safety assertions remain unchanged.
