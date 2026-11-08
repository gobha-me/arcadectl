# Adapter option metadata v1

`game.Definition.Options` describes the small settings subset an adapter already
accepts. `Definition.Validate` checks it before catalog admission or planning.
The contract is game-neutral and contains no commands, credential values,
secret references, arbitrary schema expressions, or workload overrides.

The initial inventory is Factorio's `name`, `description`, `maxPlayers`, and
`visibility`, and the synthetic fixture's `seed` and `motd`. Their definitions
remain the sources of truth. No game settings or rendering behavior are added.
Seven Days to Die is not registered or certified by this change. Its requirements
inventory remains in [PR #175](https://github.com/gobha-me/arcadectl/pull/175).

## Representation and compatibility

- `OptionMetadata.Version` must be `v1`. A nil `Options` value preserves legacy
  definition compatibility and means discovery is unavailable. A consumer must
  not interpret nil as permission to accept arbitrary settings.
- `Supported` has exactly one entry for every top-level `SettingsSchema`
  property. Each entry has a stable lowercase DNS-label `ID`, the exact
  `Property` key, label, help, grouping, lifecycle, availability, omission
  semantics, and an exact scalar `Schema` fragment. IDs are adapter-local and
  must not be reassigned to a different setting.
- `Unsupported` lists known unavailable capabilities with stable IDs and plain
  reasons. It is not an exhaustive catalog of upstream game options. Anything
  absent from the supported inventory remains unsupported. Existing renderer
  and schema errors remain authoritative.
- An inventory has at most 64 entries and encodes to at most 64 KiB. Labels are
  at most 256 bytes; help and reasons at most 1024. Text is nonempty UTF-8 with
  no control characters. Groups use lowercase DNS labels.
- The discoverable schema subset is a closed object (`additionalProperties:
  false`) with scalar `string`, `boolean`, `integer`, or `number` properties.
  Strings have a bounded `maxLength` or a finite enum; numbers have minimum
  and maximum bounds. Strings may declare `minLength` and a bounded regular
  expression. Enums have at most 32 schema-valid values. Nested objects, arrays,
  references, dependency expressions, unknown keywords and executable extensions
  are refused. This restriction applies when metadata is present; it does not
  broaden the platform's existing schema contract.
- Presentation text may change additively. Removing or reassigning an ID,
  narrowing accepted values, changing omission semantics or changing lifecycle
  meaning needs explicit compatibility review. An incompatible representation
  needs a new metadata version; unknown versions fail closed. This is a small
  metadata version, not completion of the whole adapter contract in #30.

## Omission and explicit defaults

`Omission: required` matches a schema-required field and has no `OmittedValue`.
An optional field uses `renderer-value` and records the scalar value the real
renderer produces when input is absent. `Default`, when supplied, is a separately
validated explicit input. Neither field changes settings, rewrites requests or
claims an upstream game default.

For example, Factorio renders an absent `maxPlayers` as `max_players: 0`, but
its input schema accepts only explicit integers 1 through 65535. Its metadata
therefore has `OmittedValue: 0` and no explicit `Default`. Description omission
renders an empty string, which is also a valid explicit default. Synthetic
omission uses its existing `default-seed` and `Arcadectl conformance server`
values. Tests compare these claims with the actual renderers and retain exact
Factorio minimal/full output bytes.

Metadata describes schema bounds, not every renderer restriction. Synthetic's
MOTD renderer additionally rejects CR/LF; its help says so. Validation and the
renderer continue to decide whether a submitted value is accepted.

## Lifecycle and version availability

The only lifecycle tags are `restart-required` and `create-only`. They classify
effects; they neither authorize changes nor implement create-only enforcement.
Current adapter settings are `restart-required`. A separate synthetic scalar
schema fixture exercises booleans, enums, bounded numbers and `create-only`
metadata validation without introducing new production settings. Any actual
world-identity/create-only enforcement remains a reviewed #32 capability.

`Availability.Since` is inclusive and `Before` exclusive. Bounds use canonical
numeric `major.minor.patch` game versions with at most six digits per component,
no leading zeros, and must satisfy the adapter's curated version policy.
Reversed or empty intervals fail validation. Empty bounds add no restriction
to that policy and do not certify an image or a runtime version. Current
Factorio/synthetic entries add no version restriction; no upstream release
availability has been guessed. A future discovery operation must bind and check
the requested game/image identity before returning usable options (#188).

## Ownership and boundaries

`Clone`, catalog construction, `Get`, and `List` copy the metadata pointer,
supported/unsupported slices, and every JSON buffer. Callers cannot change the
registered definition by modifying returned metadata. Stable refusal categories
are exposed through `OptionMetadataError` without echoing metadata contents.

The metadata is curated adapter data, not an untrusted plugin interface. Human
review must keep credential values out of it. Future API/browser consumers must
escape presentation strings and must never turn descriptions into commands or
credential inputs. Authenticated discovery (#188), browser forms (#192), secret
references, and create-only admission are separate work.
