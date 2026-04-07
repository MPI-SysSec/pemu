#!/bin/bash

set -x
DIR="$(dirname "$(readlink -f "$0")")"
fuzzware_base=${DIR}/../rehosting_platforms/fuzzware/fuzzware
fuzzware_patch_base=${DIR}/../rehosting_platforms/fuzzware/patches/
BASE_COMMIT=f5979d009f18ce0069c7e57c9f557766b5f977c8
pemu_src=${DIR}/../src/

echo "Setting up fuzzware for the use with PEMU"
# Initialize Fuzzware DMA
cd $fuzzware_base
git checkout $BASE_COMMIT
./update.sh

# patch emulator
cd ./emulator
git apply $fuzzware_patch_base/fuzzware-emulator.patch
cp -r $pemu_src ./harness/fuzzware_harness/network/
cd -

# patch pipeline
cd ./pipeline
git apply $fuzzware_patch_base/fuzzware-pipeline.patch
cd -

# patch modeling
cd ./modeling
git apply $fuzzware_patch_base/fuzzware-modeling.patch
cd -

cp $fuzzware_patch_base/run_docker_for_experiments.sh .

# build the ddocker
./build_docker.sh
