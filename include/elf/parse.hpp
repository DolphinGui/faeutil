#pragma once

#include "elf/types.hpp"
#include <array>
#include <concepts>
#include <string>
#include <type_traits>

#define def_enum()

namespace elf {
namespace parse {

struct header {
  u8 header[4] = {0x7f, 'E', 'L', 'F'};
  elf_class format;
  endianess endian;
  u8 ei_version = 1;
  os_abi abi;
  u8 abi_version;
  u8 padding[7];
  file_type type;
  machine_type machine;
  u32 e_version = 1;
};
// either uint32_t or uint64_t
template <std::integral Int> struct header_body {
  Int entry_point;
  Int program_offset;
  Int section_offset;
  template <std::integral Other>
  header_body &operator=(header_body<Other> other)
    requires(sizeof(Other) <= sizeof(Int))
  {
    entry_point = other.entry_point;
    program_offset = other.program_offset;
    section_offset = other.section_offset;
    return *this;
  }
};
using body32 = header_body<u32>;
using body64 = header_body<u64>;
struct header_tail {
  u32 flags;
  u16 header_size;
  u16 ph_size;
  u16 ph_num;
  u16 sh_size;
  u16 sh_num;
  u16 section_str_index;
};

struct section_header {
  u32 name_offset;
  sh::type type;
  sh::flags flags;
  u32 address;
  u32 offset;
  u32 size;
  u32 link;
  u32 info;
  u32 alignment;
  u32 entry_size;
};

} // namespace parse
} // namespace elf