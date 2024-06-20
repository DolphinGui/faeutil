project(
  'faeutil',
  ['cpp', 'c'],
  version: '1.4.2',
  default_options: ['warning_level=3', 'cpp_std=c++20'],
)

fmt = dependency('fmt')

obj_util = static_library(
  'obj_util',
  'src/parse_obj.cpp',
  'src/parse_cfi.cpp',
  include_directories: include_directories('include'),
  dependencies: [fmt],
)


elf_parse = static_library(
  'elf_parse',
  'src/parse_elf.cpp',
  include_directories: include_directories('include'),
  dependencies: [fmt],
)

executable(
  'faegen',
  'src/main/gen.cpp',
  dependencies: [fmt],
  link_with: [obj_util, elf_parse],
  include_directories: include_directories('include'),
  install: true,
)

executable(
  'readfae',
  'src/main/read.cpp',
  dependencies: [fmt],
  link_with: [obj_util, elf_parse],
  include_directories: include_directories('include'),
  install: true,
)

executable(
  'elftest',
  'src/main/elftest.cpp',
  dependencies: [fmt],
  link_with: [elf_parse],
  include_directories: include_directories('include'),
)

install_data(
  ['wrap_scripts/avr-g++.sh', 'wrap_scripts/avr-g++.ps1'],
  preserve_path: false,
  install_dir: 'bin',
)
