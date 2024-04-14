#include "external/ctre/ctre.hpp"
#include "external/scope_guard.hpp"
#include <cassert>
#include <cstdio>
#include <vector>

#include "parse.hpp"

namespace {
  void read_file(std::string_view path, std::vector<frame>& out ){
  auto f = fopen(path.data(), "r+");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });
  auto o = ObjectFile(fileno_unlocked(f), std::string(path));
  
  }
}

int main(int argc, char **argv) {
  assert(argc > 1);
  for (int i = 1; i != argc; ++i) {
    assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[i]));
  }


}