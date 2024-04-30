#include "external/ctre/ctre.hpp"
#include "external/scope_guard.hpp"
#include "fae.hpp"
#include "parse.hpp"
#include "read_fae.hpp"
#include <cassert>
#include <cstring>
#include <elf.h>
#include <fmt/ranges.h>
#include <libelf.h>

namespace {
std::string_view get_symbol_name(ObjectFile &o, uint32_t index) {
  return elf_strptr(o.elf, o.strtab_index, o.get_sym(index).st_name);
}

} // namespace

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

  // auto inst = fae::get_inst(o);
  uint32_t i = 0;
  for (auto &entry : info) {
    fmt::println("Entry {}: {} bytes at {:#0x}, pc: [{:#0x}, {:#0x}]", i++, entry.length,
                 entry.offset, entry.begin, entry.range + entry.begin);
    // for (auto i = inst + entry.offset; i != inst + entry.length +
    // entry.offset;
    //      i++) {
    //   if (i->is_pop()) {
    //     fmt::println("  pop r{}", fae::denumerate(i->p.get_reg()));
    //   } else {
    //     fmt::println("  skip {} bytes", (i->s.bytes));
    //   }
    // }
  }
}