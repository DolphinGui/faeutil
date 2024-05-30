project(
  'faeutil',
  ['cpp', 'c'],
  version: '1.0',
  default_options: ['warning_level=3', 'cpp_std=c++20'],
)

dwarf = dependency('libdw')
elf = dependency('libelf')
fmt = dependency('fmt')
ranges = dependency('range-v3')

obj_util = static_library(
  'obj_util',
  'src/parse_obj.cpp',
  'src/parse_cfi.cpp',
  include_directories: include_directories('include'),
  dependencies: [dwarf, elf, fmt, ranges],
)


elf_parse = static_library(
  'elf_parse',
  'src/parse_elf.cpp',
  include_directories: include_directories('include'),
  dependencies: [fmt, ranges],
)

executable(
  'faegen',
  'src/main/gen.cpp',
  dependencies: [elf, fmt, ranges],
  link_with: [obj_util],
  include_directories: include_directories('include'),
  install: true,
)

executable(
  'readfae',
  'src/main/read.cpp',
  dependencies: [elf, fmt, ranges],
  link_with: [obj_util],
  include_directories: include_directories('include'),
  install: true,
)

executable(
  'elftest',
  'src/main/elftest.cpp',
  dependencies: [fmt, ranges],
  link_with: [elf_parse],
  include_directories: include_directories('include'),
)

install_data(
  ['wrap_scripts/avr-g++.sh'],
  preserve_path: false,
  install_dir: 'bin',
)