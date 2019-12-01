#!/bin/sh -e

# List each of the clone URLs of a given user's public, non-fork repositories.
# Example usage:
#   $ sh list-github.sh skeeto | xargs -n1 git clone

if [ -z "$1" ]; then
    echo 'usage: list-github.sh <user>'
    exit 1
fi

pagenum=1
while true; do
    repos="$(curl -s "https://api.github.com/users/$1/repos?page=$pagenum&per_page=100" |
                 jq -r '.[] | select(.fork | not) | .clone_url')"
    if [ -z "$repos" ]; then
        break
    fi
    printf '%s\n' "$repos"
    pagenum=$((pagenum+1))
done
