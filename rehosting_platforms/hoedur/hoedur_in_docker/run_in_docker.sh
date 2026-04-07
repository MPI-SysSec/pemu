#!/bin/bash

cd "$(dirname "$0")" || exit 1

docker run --rm --user "$(id -u):$(id -g)" --env "HOME=/home/user" --mount src="$PWD/..",target=/home/user/hoedur-experiments,type=bind --mount src="$PWD/../../../eval/",target=/home/user/hoedur-targets/arm/,type=bind -it fuzzware:hoedur-eval "$@"
