#include "binary_parsing.hpp"
#include "elf/elf.hpp"
#include "elf/parse.hpp"
#include "elf/types.hpp"

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
        .file_offset = sh.offset,
        .data = std::vector<uint8_t>(data_start, data_start + sh.size),
        .link = sh.link,
        .info = sh.info,
        .alignment = sh.alignment,
        .entry_size = sh.entry_size};
  });

  std::unordered_map<std::string_view, uint32_t> name_map;
  auto *str_tab = reinterpret_cast<const char *>(
      headers[tail.section_str_index].offset + buffer.data());
  name_map.reserve(headers.size());
  for (auto &section : headers) {
    name_map.insert({str_tab + section.name_offset, section.name_offset});
  }

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
          .sh_str_index = tail.section_str_index,
          .sections = headers | read_header | ranges::to<std::vector>,
          .program_headers =
              std::vector(program_start, program_start + tail.sh_num),
          .name_map = std::move(name_map)};
}

std::vector<uint8_t> elf::serialize(file f) {
  std::vector<uint8_t> result;
  namespace elfp = elf::parse;
  size_t size = 0;
  for (auto sh : f.sections) {
    auto new_size = sh.file_offset + sh.data.size();
    if (new_size > size) {
      size = new_size;
    }
  }
  auto ph_size = f.program_headers.size() * sizeof(elf::program_header);
  auto sh_size = f.sections.size() * sizeof(elfp::section_header);
  size += f.header_size() + sh_size + ph_size;
  result.reserve(size);
  auto writer = write_vector(result);
  writer.write(elfp::header{.magic = parse::header::default_magic,
                            .format = f.format,
                            .endian = f.endian,
                            .ei_version = f.ei_version,
                            .abi = f.abi,
                            .abi_version = f.abi_version,
                            .type = f.type,
                            .machine = f.machine,
                            .e_version = f.e_version});
  if (f.format == elf::e32) {
    writer.write(elfp::body32{
        .entry_point = static_cast<unsigned int>(f.entry_point),
        .program_offset = f.header_size(),
        .section_offset = static_cast<unsigned int>(
            size - f.sections.size() * sizeof(elfp::section_header))});
  } else {
    writer.write(elfp::body64{.entry_point = f.entry_point,
                              .program_offset = f.header_size(),
                              .section_offset = size - sh_size});
  }
  writer.write(elfp::header_tail{
      .flags = f.flags,
      .header_size = static_cast<u16>(f.header_size()),
      .ph_size = static_cast<u16>(sizeof(elf::program_header)),
      .ph_num = static_cast<u16>(f.program_headers.size()),
      .sh_size = static_cast<u16>(sizeof(elfp::section_header)),
      .sh_num = static_cast<u16>(f.sections.size()),
      .section_str_index = f.sh_str_index});
  writer.write(std::span(f.program_headers));
  result.resize(size, 0);

  auto *headers =
      reinterpret_cast<elfp::section_header *>((result.end() - sh_size).base());

  for (auto &sh : f.sections) {
    if (!sh.data.empty())
      std::memcpy(result.data() + sh.file_offset, sh.data.data(),
                  sh.data.size());
    auto h = elfp::section_header{.name_offset = f.name_map.at(sh.name),
                                  .type = sh.type,
                                  .flags = sh.flags,
                                  .address = sh.address,
                                  .offset = sh.file_offset,
                                  .size = static_cast<u32>(sh.data.size()),
                                  .link = sh.link,
                                  .info = sh.info,
                                  .alignment = sh.alignment,
                                  .entry_size = sh.entry_size};
    std::memcpy(headers++, &h, sizeof(elfp::section_header));
  }

  return result;
}