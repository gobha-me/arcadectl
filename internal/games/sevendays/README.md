# Experimental Seven Days to Die planner fixture

This adapter is unregistered and its image repository is a placeholder. It is
not installed by the production catalog. The tests in
[`sevendays_plan_test.go`](../../platform/kube/sevendays_plan_test.go) exercise
the real adapter and resource planner without downloading or running a game
server. They establish a resource mapping, not runtime certification (#33).

## Lifecycle mapping

The running plan publishes the adapter's five player endpoints: TCP and UDP
26900, and UDP 26901–26903. Its readiness probe connects to the named
`game-tcp` port. A listening TCP socket does not establish that a world is loaded
or a player can join. Telnet and the web dashboard remain disabled in rendered
configuration; neither is declared or published as a player endpoint.

The `serverconfig` ConfigMap key contains the rendered XML. The platform's
fixed init container reads that source and atomically materializes it at
`/sdtd/config/serverconfig.xml` on the independently retained `world` claim,
mounted at `/sdtd`. Both containers inherit the adapter's non-root UID, GID and
filesystem group. Equivalent JSON produces the same configuration hash;
changing a rendered description changes the hash and requests workload
replacement through the existing recreate strategy.

Stopped intent produces the same retained claim and data identity, with no
Deployment, Service or configuration ConfigMap. This is the planner's desired
resource set; it does not prove that a running game has completed a clean save.
`Capabilities.GracefulShutdown` currently supplies no stop hook or termination
grace budget. Whether the eventual certified image saves safely on SIGTERM,
needs a private shutdown protocol, and finishes within a measured bound remain
[#32](https://github.com/gobha-me/arcadectl/issues/32) follow-ups.

Cold backup and restore use the existing generic path contract: every declared
persistent root must be included, currently the complete `/sdtd` tree. The
renderer sets `UserDataFolder` to the persistent root `/sdtd` and fixes
`GameWorld` and `GameName`, so settings cannot select a different world. Image
certification must still establish that generated worlds, saves, player data
and administration state stay under that root and survive a complete cold
restore.
Create-only world identity and any future game-secret references require
separate #32 contract decisions before additional settings become editable.

No production planner, controller, API or catalog changes are needed for these
resource assertions. Actual shutdown, world preservation, joinability, image
provenance and restore evidence are still required by
[#33](https://github.com/gobha-me/arcadectl/issues/33) and
[#34](https://github.com/gobha-me/arcadectl/issues/34).
