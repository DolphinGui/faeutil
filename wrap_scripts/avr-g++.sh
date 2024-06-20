#!/usr/bin/bash

set -e

args=( "$@" )
BIN=`dirname "$0"`

for i in $(seq 0 ${#args[@]});
do
    if [[ "${args[$i]}" = "-o" ]]; then
      if ! [[ "${args[($i+1)]}" =~ .+\.o ]]; then
        linking="yes"
        output="${args[($i+1)]}"
      fi
    fi
done

if [[ "$linking" = "yes" ]]; then
  $BIN/avr-g++ $@
  $BIN/faegen $output
  $BIN/avr-g++ $@ __fae_data.o
  rm __fae_data.o
else
  $BIN/avr-g++ $@
fi
