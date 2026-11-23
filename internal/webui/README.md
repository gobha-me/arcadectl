# Read-only API views

`RenderServerList` and `RenderOperationList` accept administrator API DTOs and
write passive HTML using `html/template`. They open no connections and perform
no actions. Both pages use the same semantic structure: English document,
descriptive title, skip link, main landmark, one heading, captioned table and
column headers. No scripts, framework, external assets or color-only status
indicators are needed.

The operations view shows operation ID, action, phase, timestamps and the
failure code, retryability and suggested action. It never supplies the full
receipt to its template: UID, child identity, generation, polling URL, raw
failure message and destroy preview/challenge are excluded. Receipt status is
an observation; rendering it does not claim that a workload completed.

Rows are ordered by the instant in `StartedAt`, newest first, then operation
ID ascending. RFC 3339 timestamps with fractional seconds or timezone offsets
are compared chronologically. Missing or malformed timestamps sort after
dated operations, ordered by ID; the displayed API text remains escaped.
Missing timestamps say "Not recorded", and an absent failure says "None".
Neither rendering nor sorting changes the caller's list.

The DOM tests use the existing `golang.org/x/net/html` dependency to check the
landmarks, columns, ordering, private-field omissions and contextual escaping.
This is structural accessibility coverage; it is not a browser/screen-reader
audit. Serving, navigation, receipt details and controls are separate slices.
