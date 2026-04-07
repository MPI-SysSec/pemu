#!/bin/sh

DIR="$(dirname "$(readlink -f "$0")")"

docker build --no-cache -t fuzzware:hoedur-eval $DIR -f $DIR/hoedur-fuzzware.dockerfile
