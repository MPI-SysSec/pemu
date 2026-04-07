#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Usage run_experiments.sh <number of available cores>"
  exit
fi

set -x
cores=$1
DIR="$(dirname "$(readlink -f "$0")")"
run_script_dir=${DIR}/run_scripts/

# Run semu experiments
bash $run_script_dir/run_semu.sh

# Run fuzzware experiments
bash $run_script_dir/run_fuzzware.sh $cores
bash $run_script_dir/run_modbus.sh $cores

# Run Hoedur experiments
bash $run_script_dir/run_hoedur.sh $cores
