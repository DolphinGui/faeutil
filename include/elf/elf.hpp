#pragma once

#include "elf/types.hpp"
#include <cstdint>
#include <fmt/core.h>
#include <span>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace elf {
struct section {
  std::string name;
  sh::type type;
  sh::flags flags = {};
  u32 address = 0;
  u32 file_offset;
  std::vector<uint8_t> data;
  u32 link = 0;
  u32 info = 0;
  u32 alignment = 1;
  u32 entry_size = 0;
  bool operator==(section const &o) const noexcept = default;
};
const section null_section = {.name = "",
                              .type = {},
                              .file_offset = 0,
                              .data = {},
                              .alignment = 0};

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
  u16 sh_str_index;
  u32 header_size() const {
    switch (format) {
    case e32:
      return 52;
    case e64:
      return 64;
    }
    throw std::logic_error("Unknown elf_class enumeration");
  }
  std::vector<section> sections = {null_section};
  std::vector<program_header> program_headers;
  std::unordered_map<std::string_view, uint32_t> name_map = {{"", 0}};

  inline section &get_section(u32 index) { return sections.at(index); }
  inline section &get_section(std::string_view name) {
    for (auto &sh : sections) {
      if (sh.name == name) {
        return sh;
      }
    }
    throw std::out_of_range(fmt::format("Section {} not found", name));
  }
  bool operator==(file const &o) const noexcept = default;
};

file parse_buffer(std::span<uint8_t>);
std::vector<uint8_t> serialize(file);

} // namespace elf