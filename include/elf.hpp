#pragma once

#include "elf_types.hpp"
#include <cstdint>
#include <span>
#include <vector>

namespace elf {
struct section;
struct file {
  elf_class format;
  endianess endian;
  u8 ei_version = 1;
  os_abi abi;
  u8 abi_version;
  file_type type;
  machine_type machine;
  u32 e_version = 1;
  u64 entry_point;
  u32 flags;
  u16 section_str_index;
  std::vector<section> sections;
  std::vector<program_header> program_headers;
};

struct section {
  std::string name;
  sh::type type;
  sh::flags flags;
  u32 address;
  std::vector<uint8_t> data;
  u32 link;
  u32 info;
  u32 alignment;
  u32 entry_size;
};

file parse_buffer(std::span<uint8_t>);
std::vector<uint8_t> serialize(file);

} // namespace elf