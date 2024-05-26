#!/usr/bin/bash

set -e

args=( "$@" )

for i in $(seq 0 ${#args[@]}); 
do
    if [[ "${args[$i]}" = "-o" ]]; then
      if [[ "${args[($i+1)]}" =~ ^.+[^o]$ ]]; then
        linking="yes"
        output="${args[($i+1)]}"
      fi
    fi
done

if [[ "$linking" = "yes" ]]; then
  avr-g++ $@
  faegen $output
  avr-g++ $@ __fae_data.o
else

  avr-g++ $@

fi