
#include "avr_reloc.hpp"
#include "external/ctre/ctre.hpp"
#include "external/generator.hpp"
#include "external/scope_guard.hpp"
#include "fae.hpp"
#include "range/v3/view/concat.hpp"
#include "read_fae.hpp"
#include <algorithm>
#include <cassert>
#include <concat_str.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <elf.h>
#include <fmt/ranges.h>
#include <iterator>
#include <libelf.h>
#include <map>
#include <range/v3/range/conversion.hpp>
#include <ranges>
#include <span>
#include <stdexcept>
#include <vector>

#include "macros.hpp"
#include "parse.hpp"

namespace {
struct Range {
  size_t begin{}, end{};
  uint32_t begin_sym{}, end_sym{};
  uint32_t lsda_sym{};
  uint32_t offset{};
  uint32_t length{};
  std::string symbol_name;
};

using addr_space = std::map<std::string_view, std::vector<Range>>;

// void write_table(ObjectFile &output, std::vector<fae::info_entry> info) {}

} // namespace

int main(int argc, char **argv) {
  assert(argc == 1);
  addr_space text_sections;
  std::vector<std::string> symbol_names;
  assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[1]));
  auto f = fopen(argv[1], "r+");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });
  auto o = ObjectFile(fileno_unlocked(f));

  // write_table(o, fae::read_info(o));

  elf_update(o.elf, Elf_Cmd::ELF_C_WRITE);
}