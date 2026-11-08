# Bounded settings property fuzzing

`internal/games/settings_fuzz_test.go` contains native Go fuzz targets
`FuzzFactorioSettingsProperties` and `FuzzSyntheticSettingsProperties`.
Committed corpora below `internal/games/testdata/fuzz/` cover key ordering,
whitespace, Unicode/escaping, optional omissions, malformed/trailing JSON,
unknown fields, schema string/numeric boundaries, and exact 64 KiB and
one-byte-over input limits. Seeds run during ordinary `go test`.

Seven Days to Die's corpus row is **pending #164 / PR #179**, which is unmerged
at implementation time. No hidden skip, runtime proof, or 7DTD success is
reported. This does not change the #170 shared conformance kit or #165's
planner resource proof.

Inputs are capped at 64 KiB plus one byte. Larger generated fuzz inputs return
without work; the extra byte exercises the planner's settings limit. Output
must remain within `game.MaxRenderedSettingsBytes`. Schema-valid settings
already bound the actual adapters' rendered output well below that ceiling.

The real `kube.Build` performs schema and renderer admission. Settings refusals
remain refusals, with their category checked. Schema limits are not incorrectly
asserted at the renderer-only boundary. Separate admission controls include
values the renderer alone would accept (such as zero player capacity). The
renderer must reject malformed/trailing JSON and an independently injected
unknown field. A renderer-only acceptance never counts as API admission.

For admitted settings, an independent JSON decoder and re-encoder construct a
semantic equivalent without invoking the renderer or digest as an oracle. The
real `RenderSettingsFiles` and `SettingsDigest` must produce identical ordered
targets, paths, bytes and digests for both representations. A valid change to
actual rendered meaning must change the digest. Target names/paths, UTF-8,
nonempty text, NUL exclusion and the total byte limit are checked.

Output is independently parsed: Factorio's JSON must match the supported input
meaning and its documented omission values, including omitted player capacity
rendering zero. Synthetic's single-line text artifacts must match its own seed
and greeting defaults, rather than imposing Factorio defaults on it. The tests
do not claim settings rendering executes a workload.

`TestFuzzSettingsNegativeControls` collects real production observations, then
corrupts a digest or both output files at the explicitly named observation
boundary. The same verifier used by fuzzing must reject those observations.
Deleting its digest comparison or output-meaning check makes this committed
negative control fail. No production renderer or digest is mocked.

Run seeds/race checks and finite campaigns through the required heavy wrapper:

```sh
HEAVY_WAIT=1800 CMAKE_BUILD_PARALLEL_LEVEL=2 MAKEFLAGS=-j2 GOFLAGS=-p=2 \
  GOMAXPROCS=2 GOMEMLIMIT=1GiB /config/.local/bin/heavy-run \
  go test -race -p 2 -timeout=5m ./internal/games ./internal/games/factorio ./internal/games/synthetic ./internal/platform/game ./internal/platform/kube

HEAVY_WAIT=1800 CMAKE_BUILD_PARALLEL_LEVEL=2 MAKEFLAGS=-j2 GOFLAGS=-p=2 \
  GOMAXPROCS=2 GOMEMLIMIT=1GiB /config/.local/bin/heavy-run \
  go test -p 2 ./internal/games -run='^$' -fuzz='^FuzzFactorioSettingsProperties$' -fuzztime=60s -parallel=2 -timeout=3m

HEAVY_WAIT=1800 CMAKE_BUILD_PARALLEL_LEVEL=2 MAKEFLAGS=-j2 GOFLAGS=-p=2 \
  GOMAXPROCS=2 GOMEMLIMIT=1GiB /config/.local/bin/heavy-run \
  go test -p 2 ./internal/games -run='^$' -fuzz='^FuzzSyntheticSettingsProperties$' -fuzztime=60s -parallel=2 -timeout=3m
```

Persist any minimized failure in the corresponding corpus and report the exact
candidate SHA, command and exit code. Production mutation evidence concerns
the real renderer/settings packages; mutating a copied renderer or these test
oracles is not production mutation evidence. On desktop-1, mutation is deferred
to desktop-2 under the session rules. Unit/seed/fuzz success does not certify
native lifecycle, recovery, or a release.
