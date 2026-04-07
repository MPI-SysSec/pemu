#!/bin/bash
set -x
DIR="$(dirname "$(readlink -f "$0")")"
semu=${DIR}/../rehosting_platforms/semu/SEmu
semu_fuzz=${DIR}/../rehosting_platforms/semu/SEmu-Fuzz
semu_fuzz_vanilla=${DIR}/../rehosting_platforms/semu/SEmu-Fuzz_vanilla
pemu_src=${DIR}/../src/

build_script=./build_docker.sh
patch1=../patches/semu-repair-setup.patch
patch2=../patches/semu-patches.patch
pemu_cfg=../patches/pemu_fuzz.yml
client_cfg=../patches/semu_config_tcp_client.yml
server_cfg=../patches/semu_config_tcp_server.yml
run_experiment=../patches/run_experiment.sh

echo "This script sets up the SEmu rehosting platforms in two versions: One that supports PEMU and one that is vanilla"
# 1) create a vanilla SEmu version
cp -r $semu_fuzz $semu_fuzz_vanilla

# 2) copy the semu sample dir to the Semu-Fuzz setups
# But first add the pemu experiment config - we don't need to fuzz all eval targets
cd $semu
cp $pemu_cfg DataSet/fuzz_tests/
cp $client_cfg DataSet/fuzz_tests/f429/LwIP_TCP_Echo_Client/semu_config.yml
cp $server_cfg DataSet/fuzz_tests/f429/LwIP_TCP_Echo_Server/semu_config.yml

cd $DIR

cp -r $semu $semu_fuzz
cp -r $semu $semu_fuzz_vanilla

# 3) Prepare the PEMU capable version of SEmu
cd $semu_fuzz
git checkout 8eb4ee0

# 3a) apply patches to make semu runnable and to allow for the use of Pemu
git apply $patch1
git apply $patch2

# 3b) copy experiment script
cp $run_experiment .

# 3c) copy Pemu source
cp -r $pemu_src $semu_fuzz/semu_fuzz/emulate/network

# 3d) update run_docker script
mkdir -p results/
sed -i "s%semu_fuzz /bin/bash%-v ./results:/opt/results semu_fuzz /bin/bash /SEmu-Fuzz/run_experiment.sh%g" ./run_docker.sh

# 3d) build docker
bash $build_script

# 4) Prepare a  working version of the vanilla SEmu
cd $DIR && cd $semu_fuzz_vanilla
mkdir -p results
git apply $patch1
cp $run_experiment .
sed -i "s/semu_fuzz/semu_fuzz_vanilla/g" ./build_docker.sh
sed -i "s%semu_fuzz /bin/bash%-v ./results:/opt/results semu_fuzz_vanilla /bin/bash /SEmu-Fuzz/run_experiment.sh%g" ./run_docker.sh
bash $build_script

cd $DIR
