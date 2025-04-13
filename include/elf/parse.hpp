#pragma once

#include "elf/types.hpp"
#include <concepts>

#define def_enum()

namespace elf {
namespace parse {

struct header {
  constexpr static std::array<u8, 4> default_magic = {0x7f, 'E', 'L', 'F'};
  std::array<u8, 4> magic = default_magic;
  elf_class format;
  endianess endian;
  u8 ei_version = 1;
  os_abi abi;
  u8 abi_version;
  u8 padding[7]{};
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

template<std::integral Int>
struct section_header {
  u32 name_offset;
  sh::type type;
  sh::flags<Int> flags;
  Int address;
  Int offset;
  Int size;
  u32 link;
  u32 info;
  Int alignment;
  Int entry_size;
};
using section_header64 = section_header<uint64_t>;
using section_header32 = section_header<uint32_t>;
} // namespace parse
} // namespace elf