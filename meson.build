project(
  'aetgen',
  ['cpp', 'c'],
  version: '0.1',
  default_options: ['warning_level=3', 'cpp_std=c++20'],
)

dwarf = dependency('libdw')
elf = dependency('libelf')
fmt = dependency('fmt')
ranges = dependency('range-v3')

executable(
  'aefgen',
  'aefgen.cpp',
  'parse_obj.cpp',
  'parse_cfi.cpp',
  'write_fae.cpp',
  dependencies: [dwarf, elf, fmt, ranges],
  include_directories: include_directories('include'),
  install: true,
)

executable(
  'mapper',
  'mapper.cpp',
  dependencies: [dwarf, elf, fmt, ranges],
  include_directories: include_directories('include'),
  install: true,
)
