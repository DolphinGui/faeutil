#include "binary_parsing.hpp"
#include "elf.hpp"
#include "elf_parse.hpp"
#include "elf_types.hpp"

#include <range/v3/range/conversion.hpp>
#include <ranges>

namespace elfp = elf::parse;

elf::file elf::parse_buffer(std::span<uint8_t> buffer) {

  auto data = Reader(buffer);
  auto head = data.consume<elfp::header>();
  elfp::body64 body;
  if (head.format == elf::e32) {
    body = data.consume<elfp::body32>();
  } else {
    body = data.consume<elfp::body64>();
  }
  auto tail = data.consume<elfp::header_tail>();
  auto headers = std::span(reinterpret_cast<elfp::section_header *>(
                               buffer.data() + body.section_offset),
                           tail.sh_num);
  auto &sh_str_tab = headers[tail.section_str_index];

  auto read_header = std::views::transform([&](elfp::section_header sh) {
    auto data_start = buffer.data() + sh.offset;
    return elf::section{
        .name = reinterpret_cast<const char *>(sh_str_tab.offset +
                                               sh.name_offset + buffer.data()),
        .type = sh.type,
        .flags = sh.flags,
        .address = sh.address,
        .data = std::vector<uint8_t>(data_start, data_start + sh.size),
        .link = sh.link,
        .info = sh.info,
        .alignment = sh.alignment,
        .entry_size = sh.entry_size};
  });

  auto program_start =
      reinterpret_cast<program_header *>(buffer.data() + body.program_offset);

  return {.format = head.format,
          .endian = head.endian,
          .ei_version = head.ei_version,
          .abi = head.abi,
          .abi_version = head.abi_version,
          .type = head.type,
          .machine = head.machine,
          .e_version = head.e_version,
          .entry_point = body.entry_point,
          .flags = tail.flags,
          .section_str_index = tail.section_str_index,
          .sections = headers | read_header | ranges::to<std::vector>,
          .program_headers =
              std::vector(program_start, program_start + tail.sh_num)};
}