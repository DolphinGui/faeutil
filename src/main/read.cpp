#include "external/ctre/ctre.hpp"
#include "external/scope_guard.hpp"
#include "fae.hpp"
#include "parse.hpp"
#include "read_fae.hpp"
#include <cassert>
#include <elf.h>
#include <fmt/ranges.h>
#include <libelf.h>
#include <range/v3/range/conversion.hpp>

int main(int argc, char **argv) {
  assert(argc == 2);
  assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[1]));

  auto f = fopen(argv[1], "r+");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });
  auto o = ObjectFile(fileno_unlocked(f));
  auto info = fae::read_info(o);
  if (info.size() == 0) {
    fmt::println("No entries");
    return 0;
  }

  uint32_t i = 0;
  for (auto &entry : info) {
    fmt::println("Entry {}: {} bytes at {:#0x}, pc: [{:#0x}, {:#0x}], lsda: {:#0x}",
                 i++, entry.length, entry.offset, entry.begin,
                 entry.range + entry.begin, entry.lsda_offset);
  }

  fmt::println("frame instructions:");
  auto instructions = fae::get_inst(o);
  for (auto instruction : instructions) {
    if (instruction.is_pop()) {
      fmt::println("{:#0x}: pop r{}", instruction.byte,
                   fae::denumerate(instruction.p.get_reg()));
    } else {
      fmt::println("{:#0x}: skip {} bytes", instruction.byte,
                   (instruction.s.bytes));
    }
  }
}