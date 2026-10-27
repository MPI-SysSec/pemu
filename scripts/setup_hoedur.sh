#!/bin/bash
set -x
DIR="$(dirname "$(readlink -f "$0")")"

HOEDUR_BASE_COMMIT=c94f944bef49e9bf5fbc316389754349444a784a
hoedur_base="${DIR}/../rehosting_platforms/hoedur/hoedur_in_docker/"
fuzzware_hoedur_base="${DIR}/../rehosting_platforms/hoedur/fuzzware/"
hoedur_src="${DIR}/../rehosting_platforms/hoedur/src/hoedur"
pemu_hoedur_base="${hoedur_base}/patches/pemu/pemu.patch"
pemu_src="${DIR}/../src/"

# Build fuzzware docker
cd $fuzzware_hoedur_base
./update.sh
./build_docker.sh fuzzware-hoedur-eval

# Build hoedur in docker
cd $hoedur_base
# First move pemu srces to hoedur
mkdir -p ./pemu
rm -rf pemu/*
cp -r $pemu_src/* ./pemu
cd pemu
mv analysis/* .
rm -r analysis/
sed -i "s/from \./from /g" ./*
# Hoedur provides plugin_api as a builtin Rust (pyo3) module instead of the python APIGadget
sed -i "s/^from plugin_api import APIGadget$/import plugin_api/" ./artificial_network_interface.py
cd $hoedur_base

./build_docker.sh

# setup hoedur sources
cd $hoedur_src
git checkout $HOEDUR_BASE_COMMIT
git apply $pemu_hoedur_base
cd $DIR
