#include "external/ctre/ctre.hpp"
#include "external/scope_guard.hpp"
#include <cassert>
#include <cstdio>

#include "parse.hpp"

int main(int argc, char **argv) {
  assert(argc == 2);
  assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[1]));

  auto f = fopen(argv[1], "r+");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });
  auto o = ObjectFile(fileno_unlocked(f));

  auto frames = parse_object(o);
  write_fae(o, frames, argv[1]);
}