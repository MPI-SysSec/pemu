#!/bin/bash

set -x
DIR="$(dirname "$(readlink -f "$0")")"
semu_fuzz=${DIR}/../../rehosting_platforms/semu/SEmu-Fuzz/
semu_fuzz_vanilla=${DIR}/../../rehosting_platforms/semu/SEmu-Fuzz_vanilla/

# run experiments contents should be
bash $semu_fuzz/run_docker.sh
bash $semu_fuzz_vanilla/run_docker.sh
