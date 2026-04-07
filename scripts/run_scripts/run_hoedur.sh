#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Usage: run_hoedur.sh <num_of_available_cores>"
  exit 1
fi

set -x
DIR="$(dirname "$(readlink -f "$0")")"
hoedur_dir=${DIR}/../../rehosting_platforms/hoedur/hoedur_in_docker/
hoedur_docker=$hoedur_dir/run_in_docker.sh
cores=$1
duration=24h

# If corpus already exists in hoedur-experiments -> move it to corpus_old, remove any corpus_old that was there before
if [[ -d $DIR/../../rehosting_platforms/hoedur/corpus ]]; then
  echo "[!] Corpus dir already exists, moving to corpus-old and REMOVING all older versions"
  if [[ -d $DIR/../../rehosting_platforms/hoedur/corpus-old ]]; then
    rm -r $DIR/../../rehosting_platforms/hoedur/corpus-old 
  fi
  mv $DIR/../../rehosting_platforms/hoedur/corpus $DIR/../../rehosting_platforms/hoedur/corpus-old 
fi

if [[ -d $DIR/../../rehosting_platforms/hoedur/corpus-bugs ]]; then
  echo "[!] Corpus dir already exists, moving to corpus-bugs-old and REMOVING all older versions"
  if [[ -d $DIR/../../rehosting_platforms/hoedur/corpus-bugs-old ]]; then
    rm -r $DIR/../../rehosting_platforms/hoedur/corpus-bugs-old 
  fi
  mv $DIR/../../rehosting_platforms/hoedur/corpus $DIR/../../rehosting_platforms/hoedur/corpus-bugs-old 
fi
# coverage experiments
bash $hoedur_docker /bin/bash -c "cp -r ~/hoedur-experiments/hoedur_in_docker/pemu/probe_based_detection.py ~/hoedur/pemu/ && cd ~/hoedur && CONFIG_FILE=hoedur_config.yml python3 scripts/fuzz-local.py --runs 5 --cores ${cores} --duration ${duration} --fuzzers hoedur hoedur-dma hoedur-pemu --targets 01-coverage-experiments/nrf52840/nuttx_nimble 01-coverage-experiments/nrf52840/coap_client 01-coverage-experiments/nrf52840/ble_central_hr 01-coverage-experiments/nrf52840/radio_ping 01-coverage-experiments/ti_cc2538/snmp_server_cve_2020_12141 01-coverage-experiments/stm32_f7xx/udp_echo_server 01-coverage-experiments/stm32_f7xx/http_static 01-coverage-experiments/stm32_f429/LwIP_TCP_Echo_Client 01-coverage-experiments/stm32_f429/LwIP_TCP_Echo_Server"&& mv ~/hoedur/corpus ~/hoedur-experiments/ && mv ~/hoedur/corpus ~/hoedur-experiments/ && mv ~/hoedur/corpus ~/hoedur-experiments/"
# bug rediscovery
bash $hoedur_docker /bin/bash -c "cp -r ~/hoedur-experiments/hoedur_in_docker/pemu/probe_based_detection.py ~/hoedur/pemu/ && cd ~/hoedur && CONFIG_FILE=hoedur_config.yml python3 scripts/fuzz-local.py --runs 5 --cores ${cores} --duration ${duration} --fuzzers hoedur hoedur-dma hoedur-pemu --targets 02-bug-rediscovery/contiki-ng/rpl-udp 02-bug-rediscovery/freertos/cve-2018-16523 02-bug-rediscovery/freertos/cve-2018-16524 02-bug-rediscovery/freertos/cve-2018-16526 02-bug-rediscovery/freertos/cve-2018-16601 02-bug-rediscovery/freertos/cve-2018-16603 02-bug-rediscovery/picoTCP/four_ping 02-bug-rediscovery/picoTCP/six_ping 02-bug-rediscovery/picoTCP/four_tcp 02-bug-rediscovery/picoTCP/six_tcp && mv ~/hoedur/corpus ~/hoedur-experiments/corpus-bugs"
