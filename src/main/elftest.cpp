#include "elf/elf.hpp"
#include "elf/types.hpp"
#include "external/ctre/ctre.hpp"
#include "external/scope_guard.hpp"
#include <cassert>
#include <cstdio>
#include <fmt/core.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {
auto read_file(std::string_view path) {
  auto f = fopen(path.data(), "rb+");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });

  if (int err = fseek(f, 0, SEEK_END)) {
    throw std::runtime_error(fmt::format("failed to fseek: {}", err));
  }

  std::vector<uint8_t> result;
  result.resize(ftell(f));
  fseek(f, 0, SEEK_SET);
  fread(result.data(), 1, result.size(), f);
  return result;
}

void write_file(std::span<uint8_t> buffer) {
  auto f = fopen("a.out", "wb");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });
  fwrite(buffer.data(), 1, buffer.size_bytes(), f);
}
template <typename T> std::span<uint8_t> to_binspan(std::span<T> span) {
  return std::span<uint8_t>(reinterpret_cast<uint8_t *>(span.data()),
                            span.size() * sizeof(T));
}

} // namespace

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