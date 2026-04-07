#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Usage: run_modbus.sh <num_of_available_cores>"
  exit 1
fi

set -x
DIR="$(dirname "$(readlink -f "$0")")"
fuzzware_dir=${DIR}/../../rehosting_platforms/fuzzware/fuzzware/
fuzzware_docker=$fuzzware_dir/run_docker_for_experiments.sh
fuzzware_targets=${DIR}/../../eval/03-non-network-protocols/
targets=("heat_press/")

default_cfg=config.yml
pemu_cfg=config_np.yml
cfgs=($default_cfg $rand_cfg $pemu_cfg)

runs=5
num_cores=$1
num_parallel_procs=$(($num_cores / 4))
fuzzing_runtime="00:24:00:00"

project_base_name="fuzzware-project"
statistics_names="coverage"
extra_emu_args="--run-for $fuzzing_runtime"

cur_core=0

(for run_no in $(seq 1 $runs); do
  for target in ${targets[@]}; do
    project_name=$(printf ${project_base_name}_default-run-%02d $run_no)
    counter=0
    for config in ${cfgs[@]}; do
      if [[ $counter -eq 0 ]]; then
        project_name=$(printf ${project_base_name}_default-run-%02d $run_no)
      elif [[ $counter -eq 1 ]]; then
        project_name=$(printf ${project_base_name}_random-run-%02d $run_no)
      elif [[ $counter -eq 2 ]]; then
        project_name=$(printf ${project_base_name}_pemu-run-%02d $run_no)
      fi

      counter=$(($counter + 1))
      echo "${fuzzware_docker} ${fuzzware_targets} ${cur_core}-$((cur_core + 3)) fuzzware pipeline -p ${project_name} -n 4 -c ${target}/${config} ${extra_emu_args} ${target} && ${fuzzware_docker} ${fuzzware_targets} ${cur_core}-$((cur_core + 3)) fuzzware genstats -p ${target}/${project_name} ${statistics_names}"
      cur_core=$(($cur_core + 4))
    done

    if [[ $cur_core -gt $(($num_parallel_procs * 4 - 12)) ]]; then
      cur_core=0
    fi
  done
done) | xargs -I{} --max-procs $num_parallel_procs -- bash -c "{}"
