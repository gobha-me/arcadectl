# Authentic installation predecessor

These 31 YAML/template files are byte-exact Git blobs from
`7dcbad6497782c198c7b142a6a8b902dead4b79e`, at their original `config/` paths.
They are compatibility evidence, not current installation inputs. Do not
regenerate, normalize, or update them when changing current manifests.

`config.LegacyInstallation` embeds only the original asset patterns, separately
from `config.Installation`. Rendering and the frozen whole-tree hash use a
filesystem view with the original `api/`, `install/`, and `rbac/` relative paths.
The unchanged checksum is
`092b6c22e136be7fde6029e45498145246962a8c555bb85bf512b04e273dbe3b`:
sort paths; SHA-256 each original file; hash the concatenated lines formatted
as `<file-sha256>  config/<relative-path>\n`.

This README is outside both asset embed patterns and is not part of the hash.
Legacy packages still require the exact original source, default namespace,
reviewed profile, original resource counts, and images built from that source.
