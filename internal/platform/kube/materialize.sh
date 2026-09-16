#!/bin/sh
# Copyright 2026 gobha-me
# SPDX-License-Identifier: Apache-2.0

set -eu
umask 022
temporary_path=
cleanup_temporary_file() {
  if [ -n "$temporary_path" ]; then
    rm -f -- "$temporary_path"
  fi
}
trap cleanup_temporary_file 0 1 2 15
while [ "$#" -gt 0 ]; do
  if [ "$#" -lt 3 ]; then
    echo "configuration materializer received an incomplete path tuple" >&2
    exit 1
  fi
  persistent_root=$1
  source_path=$2
  target_path=$3
  shift 3
  case "$target_path" in
    "$persistent_root"/*) ;;
    *) echo "configuration target is outside its persistent root" >&2; exit 1 ;;
  esac
  if [ ! -f "$source_path" ]; then
    echo "configuration source is not a regular file" >&2
    exit 1
  fi
  target_relative=${target_path#"$persistent_root"/}
  case "$target_relative" in
    */*) parent_relative=${target_relative%/*} ;;
    *) parent_relative= ;;
  esac
  current_path=$persistent_root
  remaining=$parent_relative
  while [ -n "$remaining" ]; do
    component=${remaining%%/*}
    if [ "$remaining" = "$component" ]; then
      remaining=
    else
      remaining=${remaining#*/}
    fi
    current_path=$current_path/$component
    if [ -L "$current_path" ]; then
      echo "configuration target parent must not be a symbolic link" >&2
      exit 1
    fi
    if [ -e "$current_path" ]; then
      if [ ! -d "$current_path" ]; then
        echo "configuration target parent is not a directory" >&2
        exit 1
      fi
    else
      mkdir "$current_path"
    fi
  done
  if [ -L "$target_path" ]; then
    echo "configuration target must not be a symbolic link" >&2
    exit 1
  fi
  if [ -e "$target_path" ] && [ ! -f "$target_path" ]; then
    echo "configuration target is not a regular file" >&2
    exit 1
  fi
  temporary_path=$(mktemp "$current_path/.arcadectl-configuration.XXXXXX")
  cp "$source_path" "$temporary_path"
  chmod 0444 "$temporary_path"
  mv -f "$temporary_path" "$target_path"
  temporary_path=
done
trap - 0 1 2 15
