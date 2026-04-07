#!/bin/sh
set -ex

# reset previously applied patches
git reset --hard origin/main
git clean -fdx -e patches/
git checkout c94f944bef49e9bf5fbc316389754349444a784a

# apply patches
variant=""
for dir in "$@"; do
  if [ "$variant" = "" ]; then
    variant="$dir"
  else
    variant="$variant-$dir"
  fi

  #git am patches/"$dir"/*.patch
  git apply patches/"$dir"/*.patch
done

# build hoedur variant
mkdir -p /tmp/bin
cargo install --path "$HOEDUR/hoedur" \
  --bin hoedur-arm \
  --root /tmp \
  --no-track
mv /tmp/bin/hoedur-arm "/home/user/.cargo/bin/hoedur-$variant-arm"
