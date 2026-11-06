#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo 'usage: build-observe-helper.sh ABSOLUTE_FRESH_OUTPUT' >&2
    exit 2
fi
case "$1" in
    /*) ;;
    *) echo 'absolute output required' >&2; exit 2 ;;
esac
if [ -e "$1" ] || [ -L "$1" ]; then
    echo 'fresh output required' >&2
    exit 2
fi
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
umask 077
clang -std=c11 -Wall -Wextra -Werror -mmacosx-version-min=14.4 \
    "$source_dir/src/bin/observe_helper.c" -o "$1"
