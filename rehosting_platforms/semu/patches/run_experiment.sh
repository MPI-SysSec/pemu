#!/bin/bash

cd /SEmu-Fuzz/SEmu/DataSet/fuzz_tests
semu-fuzz-helper run pemu_fuzz.yml
sleep 24h
cp -r /SEmu-Fuzz/SEmu/DataSet/fuzz_tests/f429/LwIP_TCP_Echo_Client/ /opt/results/
cp -r /SEmu-Fuzz/SEmu/DataSet/fuzz_tests/f429/LwIP_TCP_Echo_Server/ /opt/results/
