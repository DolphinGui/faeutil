#include "binary_parsing.hpp"
#include "elf/elf.hpp"
#include "elf/parse.hpp"
#include "elf/types.hpp"
#include <cast.hpp>

#include <cstddef>
#include <fmt/format.h>
#include <iterator>
#include <ranges>
#include <span>

namespace elfp = elf::parse;

namespace {


template <std::integral Int>
elf::file read_sections(std::span<uint8_t> buffer, elfp::header head,
                        elfp::header_body<Int> &body, elfp::header_tail &tail,
                        std::span<elfp::section_header<Int>> headers) {
  std::unordered_map<std::string_view, uint32_t> name_map;
  auto &sh_str_tab = headers[tail.section_str_index];
  auto read_header = std::views::transform([&](elfp::section_header<Int> sh) {
    auto data_start = buffer.data() + sh.offset;
    return elf::section{
        .name = reinterpret_cast<const char *>(sh_str_tab.offset +
                                               sh.name_offset + buffer.data()),
        .type = sh.type,
        .flags = static_cast<elf::sh::flags64>(static_cast<elf::u64>(sh.flags)),
        .address = sh.address,
        .file_offset = sh.offset,
        .data = std::vector<uint8_t>(data_start, data_start + sh.size),
        .link = sh.link,
        .info = sh.info,
        .alignment = sh.alignment,
        .entry_size = sh.entry_size};
  });

  std::vector<elf::section> sections;
  sections.reserve(headers.size());
  std::ranges::copy(headers | read_header, std::back_inserter(sections));

  auto *str_tab = reinterpret_cast<const char *>(
      headers[tail.section_str_index].offset + buffer.data());
  name_map.reserve(headers.size());
  for (auto &section : headers) {
    name_map.insert({str_tab + section.name_offset, section.name_offset});
  }

  auto program_start = reinterpret_cast<elf::program_header *>(
      buffer.data() + body.program_offset);

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
          .sections = std::move(sections),
          .program_headers =
              std::vector(program_start, program_start + tail.ph_num),
          .name_map = std::move(name_map)};
}

} // namespace

elf::file elf::parse_buffer(std::span<uint8_t> buffer) {

  auto data = Reader(buffer);
  auto head = data.consume<elfp::header>();
  elfp::header_tail tail;

  if (head.format == elf::e32) {
    elfp::body32 body = data.consume<elfp::body32>();
    tail = data.consume<elfp::header_tail>();
    auto headers = std::span(reinterpret_cast<elfp::section_header32 *>(
                                 buffer.data() + body.section_offset),
                             tail.sh_num);
    return read_sections<u32>(buffer, head, body, tail, headers);
  } else {
    elfp::body64 body = data.consume<elfp::body64>();
    tail = data.consume<elfp::header_tail>();
    auto headers = std::span(reinterpret_cast<elfp::section_header64 *>(
                                 buffer.data() + body.section_offset),
                             tail.sh_num);
    return read_sections<u64>(buffer, head, body, tail, headers);
  }
}

namespace {

template <template <typename> typename T> size_t sizeof_elf(bool is_64) {
  if (is_64) {
    return sizeof(T<elf::u64>);
  } else {
    return sizeof(T<elf::u32>);
  }
}

template <std::integral Int>
void write_sections(std::span<uint8_t> result, elf::file f,
                    size_t sh_begin_offset) {

  auto *headers = reinterpret_cast<elfp::section_header<Int> *>(
      result.data() + sh_begin_offset);

  for (auto &sh : f.sections) {
    if (!sh.data.empty())
      std::memcpy(result.data() + sh.file_offset, sh.data.data(),
                  sh.data.size());
    auto h = elfp::section_header<Int>{.name_offset = f.name_map.at(sh.name),
                                       .type = sh.type,
                                       .flags = elf::sh::convert<Int, elf::u64>(sh.flags),
                                       .address = cast<Int>(sh.address),
                                       .offset = cast<Int>(sh.file_offset),
                                       .size = cast<Int>(sh.data.size()),
                                       .link = sh.link,
                                       .info = sh.info,
                                       .alignment = cast<Int>(sh.alignment),
                                       .entry_size = cast<Int>(sh.entry_size)};
    std::memcpy(headers++, &h, sizeof(elfp::section_header<Int>));
  }
}
} // namespace

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
  size_t sh_begin_offset = size;
  auto alignment = f.format == elf_class::e32 ? alignof(u32) : alignof(u64);
  size += alignment - (size % alignment);
  bool is_64 = f.format == elf_class::e64;
  auto ph_size = f.program_headers.size() * sizeof(elf::program_header);
  auto sh_size = f.sections.size() * sizeof_elf<elfp::section_header>(is_64);
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
        .entry_point = cast<u32>(f.entry_point),
        .program_offset = f.program_headers.empty() ? 0 : f.header_size(),
        .section_offset = cast<u32>(sh_begin_offset)});
  } else {
    writer.write(elfp::body64{.entry_point = f.entry_point,
                              .program_offset = f.header_size(),
                              .section_offset = sh_begin_offset});
  }
  writer.write(elfp::header_tail{
      .flags = f.flags,
      .header_size = cast<u16>(f.header_size()),
      .ph_size = cast<u16>(
          f.program_headers.empty() ? 0 : sizeof(elf::program_header)),
      .ph_num = cast<u16>(f.program_headers.size()),
      .sh_size = cast<u16>(sizeof_elf<elfp::section_header>(is_64)),
      .sh_num = cast<u16>(f.sections.size()),
      .section_str_index = f.sh_str_index});
  writer.write(f.program_headers);
  result.resize(size, 0);

  if (is_64) {
    write_sections<u64>(result, f, sh_begin_offset);
  } else {
    write_sections<u32>(result, f, sh_begin_offset);
  }

  return result;
}