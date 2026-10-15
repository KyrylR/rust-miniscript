#!/bin/sh
# Create a local upstream review branch without changing the checkout.
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <upstream-ref> <new-local-branch>" >&2
    exit 2
fi

upstream=$(git rev-parse --verify --end-of-options "$1^{commit}")
current=$(git rev-parse --verify HEAD)
if git merge-base --is-ancestor "$upstream" "$current"; then
    echo "The current branch already contains $upstream."
    exit 0
fi
if ! git merge-base "$current" "$upstream" >/dev/null; then
    echo "The upstream revision has no shared history with this branch." >&2
    exit 1
fi

git branch -- "$2" "$upstream"
git --no-pager log --reverse --oneline "$current..$upstream"
echo "Created $2 at $upstream. Checkout is unchanged."
echo "Merge the Elements branch into it, resolve conflicts, and run the tests before integration."
