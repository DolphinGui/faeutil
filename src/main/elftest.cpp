#include "elf/elf.hpp"
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
} // namespace

int main(int argc, char **argv) {
  assert(argc == 2);
  assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[1]));
  auto file = read_file(argv[1]);
  auto elf = elf::parse_buffer(file);
  fmt::println("total size: {}", file.size());
  fmt::println("file first few bytes: {}", std::span(file).subspan(0, 8));
  fmt::println("format: {}, endian: {}, abi: {}, type: {}, machine: {}",
               elf.format, elf.endian, elf.abi, elf.type, elf.machine);
  for (auto &sh : elf.sections) {
    fmt::println("section {}: size: {}", sh.name, sh.data.size());
  }
}