#!/bin/sh

PREFIX=$1

if ! [ -d "$PREFIX" ] ; then
    echo "You don't have a volume 'Marionette Cache' attached - can't continue. See the README." >&2
    exit 1
fi

BASE="$(cd "$(dirname "$0")" ; pwd)"
cd "$BASE"

mkdir -p "$PREFIX"

for repo in $(cat ./repos); do
    if ! [ -d "$PREFIX/$repo" ] ; then
        git clone --mirror git@git.corp.stripe.com:/stripe-internal/$repo "$PREFIX/$repo"
    fi
done
cp scripts/* "$PREFIX"
