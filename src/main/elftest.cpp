#include "elf/elf.hpp"
#include "external/ctre/ctre.hpp"
#include <cassert>
#include <cstdio>
#include <fmt/core.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <io.hpp>

int main(int argc, char **argv) {
  assert(argc == 2);
  assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[1]));
  auto file = read_file(argv[1]);
  auto elf = elf::parse_buffer(file);

  auto result = elf::serialize(elf);
  write_file(result);

  fmt::println("bit parity: {}", result == file);
  // fmt::println("parse parity: {}", elf == elf::parse_buffer(r));
  fmt::println("total size: {}", file.size());
  fmt::println("file first few bytes: {}", std::span(file).subspan(0, 8));
  fmt::println("format: {}, endian: {}, abi: {}, type: {}, machine: {}",
               elf.format, elf.endian, elf.abi, elf.type, elf.machine);
  fmt::println("name offsets: {}", elf.name_map);
  fmt::println("program headers: {}", elf.program_headers.size());
  fmt::println("There are {} section headers:\n", elf.sections.size());
  fmt::println(
      "Section Headers:\n"
      "  [Nr] Name              Type            Addr     Off    Size   "
      "ES Flg Lk Inf Al");
  int i = 0;
  for (auto &sh : elf.sections) {
    fmt::println(
        "  [{:2}] {:17} {:15} {:08x} {:06x} {:06x} {:02x} {:3>} {:2} {:3} {:2}",
        i++, sh.name, sh.type, sh.address, sh.file_offset, sh.data.size(),
        sh.entry_size, sh.flags, sh.link, sh.info, sh.alignment);
  }
}