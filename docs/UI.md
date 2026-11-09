# UI action contract

The future UI is a client of the authenticated [admin API](ADMIN_API.md). Its
mutating controls may call only the routes in the ordered
[`uicontract.Actions()` table](../internal/uicontract/actions.go). The contract
tests compare each method, path and authenticated action with
[`adminv1.Routes()`](../api/admin/v1/routes.go) and require an explicit disposition
for every non-GET route. New GET routes are allowed without adding a control here.
The table is design data; it does not enable any controls or grant authority.

<!-- action-map:start -->
| ID | Label | Method | Path | API action | Confirmation | Second step only |
| --- | --- | --- | --- | --- | --- | --- |
| create-server | Create server | POST | /v1/servers | server.create | none | false |
| configure-server | Configure server | PATCH | /v1/servers/{name} | server.configure | none | false |
| start-server | Start server | POST | /v1/servers/{name}/start | server.start | none | false |
| stop-server | Stop server | POST | /v1/servers/{name}/stop | server.stop | none | false |
| restart-server | Restart server | POST | /v1/servers/{name}/restart | server.restart | none | false |
| update-server | Update server | POST | /v1/servers/{name}/update | server.update | none | false |
| backup-world | Back up world | POST | /v1/servers/{name}/backup | world.backup | none | false |
| decommission-server | Decommission server | POST | /v1/servers/{name}/decommission | server.decommission | typed-name | false |
| preview-server-destroy | Preview server world destruction | POST | /v1/servers/{name}/destroy | world.destroy.preview | preview-then-confirm | false |
| preview-retained-destroy | Preview retained world destruction | POST | /v1/retained-worlds/{operationID}/destroy | world.destroy.preview | preview-then-confirm | false |
| confirm-world-destroy | Confirm previewed world destruction | POST | /v1/destroy-operations/{operationID}/confirm | world.destroy.confirm | preview-then-confirm | true |
| cancel-world-destroy | Cancel previewed world destruction | POST | /v1/destroy-operations/{operationID}/cancel | world.destroy.cancel | none | true |
<!-- action-map:end -->

<!-- unmapped:start -->
| API action | Reason |
| --- | --- |
| world.restore | Needs exact backup selection and candidate recovery UX |
<!-- unmapped:end -->

`none` means no additional UI confirmation; it never bypasses API validation or
authorization. `typed-name` asks the operator to type the exact server name before
submission. `preview-then-confirm` requires a fresh destroy preview and its exact
challenge. Both destroy entry points begin with preview; confirmation and
cancellation are second-step-only actions on that preview's operation ID. A UI
must never show the confirm route as a standalone action or synthesize, reuse or
skip the challenge. Follow [DESTROY.md](DESTROY.md) for expiry, identity and backup
gates. No control offers the no-backup override.

Not decided here: auth/session model, forms (blocked on #30), CSRF design or
game-option discovery. Read-only rendering (#166) and serving (#167) do not depend
on this table. Future forms must preserve the existing server-side authorization
and two-step destruction contract rather than add a second backend or direct
Kubernetes access.
