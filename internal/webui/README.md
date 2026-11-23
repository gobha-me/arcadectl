# Read-only API views

`RenderServerList`, `RenderOperationList` and `RenderOperationDetail` accept
administrator API DTOs and write passive HTML using `html/template`. They open
no connections and perform no actions. All pages use an English document,
descriptive title, skip link, main landmark and one heading. List pages have
captioned tables and column headers; receipt detail uses labelled terms and
descriptions. No scripts, framework, external assets or color-only status
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
audit.

All pages include labelled local navigation and a keyboard-reachable manual
refresh link. Operation-list IDs link to `/operations/{id}` only when they
match the exact API receipt-ID syntax; malformed IDs remain escaped text.
`PollURL` never chooses a destination. There are no scripts or background
requests.

The detail view projects only ID, action, reported phase, timestamp text,
derived currentness/status, failure code, retryability and suggested action.
It requires a positive generation equal to the observed generation and a valid
recorded completion timestamp before calling Succeeded/Failed/Cancelled
current completed work. Stale, missing and malformed evidence says completion
is unconfirmed. A succeeded receipt does not establish present server readiness;
server status remains a separate observation. Destroy confirmation and all
mutation controls remain unavailable. Invalid detail IDs fail with a fixed
error before writing any HTML.
