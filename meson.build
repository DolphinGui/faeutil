project(
  'faeutil',
  ['cpp', 'c'],
  version: '0.1',
  default_options: ['warning_level=3', 'cpp_std=c++20'],
)

dwarf = dependency('libdw')
elf = dependency('libelf')
fmt = dependency('fmt')
ranges = dependency('range-v3')

fae_reader = static_library('fae_reader', 'read_fae.cpp', 
  dependencies: [elf, fmt, ranges])

executable(
  'faegen',
  'faegen.cpp',
  'parse_obj.cpp',
  'parse_cfi.cpp',
  'write_fae.cpp',
  dependencies: [dwarf, elf, fmt, ranges],
  include_directories: include_directories('include'),
  install: true,
)

executable(
  'readfae',
  'readfae.cpp',
  dependencies: [dwarf, elf, fmt, ranges, fae_reader],
  include_directories: include_directories('include'),
  install: true,
)
