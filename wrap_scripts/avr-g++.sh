#!/usr/bin/bash

objects=()
sources=()
for arg in "$@"
do
    if [[ "$arg" =~ ^.+\.o$ ]]; then
      objects+=($arg)
    elif [[ "$arg" =~ ^.+\.c.{1,2}$ ]]; then
      sources+=($arg)
    fi
done
obj_count="${#objects[@]}"
src_count="${#sources[@]}"

avr-g++ $@

if (( obj_count > 1 )); then

  echo "link mode"
  else

  if (( obj_count == 0)); then
    for src in "${sources[@]}"; do
      objects+=(${src%.*}.o)
    done
  fi


  for obj in "${objects[@]}"; do
    faegen $obj
  done
  

fi