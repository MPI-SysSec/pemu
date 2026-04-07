# Bug rediscovery
TODO emnettest

## FreeRTOS
For FreeRTOS we took the same version used by EmNetTest and made different versions, each containing one CVE.

## PicoTCP
For PicoTCP we clone the repsitory, which has not been updated in years and built 4 samples, which contain all the different CVEs: Ping application for IPv4 and IPv6, and TCP Server for IPv4 and IPv6

## contiki-ng
For the contiki-ng RTOS we checked out the repository at the same commit as EmNetTest and built the same sample as EmNetTest (`rpl-udp`)
