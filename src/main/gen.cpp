#include "external/ctre/ctre.hpp"
#include "external/scope_guard.hpp"
#include <cassert>
#include <cstdio>
#include <fmt/ranges.h>

#include "parse.hpp"

namespace {
using namespace std::string_view_literals;
constexpr auto section_names = ".fae_data\0"sv;
// std::map< create_fae_data(){}
// void create_fae_table(){}
// void create_rela(){}
} // namespace

int main(int argc, char **argv) {
  assert(argc == 2);
  assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[1]));

  auto f = fopen(argv[1], "r+");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });
  auto o = ObjectFile(fileno_unlocked(f));

  // auto out_file = fopen("__fae_data.o", "w");
  // auto g2 = sg::make_scope_guard([&]() { fclose(out_file); });
  // auto data_obj = ObjectFile(fileno_unlocked(out_file), section_names);

  auto frames = parse_object(o);
  for (auto &f : frames) {
    fmt::println("{:#0x}, {:#0x}, offsets: {}", f.begin.val, f.range.val,
                 f.frame.register_offsets);
  }
}