#pragma once

#include <fmt/core.h>
#include <libelf.h>
#include <stdexcept>

namespace {
inline const char *m(const char *c) {
  if (!c)
    return "";
  return c;
}
inline void update(Elf *e) {
  elf_update(e, ELF_C_NULL);
  auto err = elf_errno();
  // this is unstable and probably depends on implementation
  // I hate this
  if (err != 42 && err != 0)
    throw std::runtime_error(
        fmt::format("Error at {}: {}", __LINE__, m(elf_errmsg(err))));
}
} // namespace

#define CHECK(a)                                                               \
  do {                                                                         \
    auto elferrnonumber = elf_errno();                                         \
    if (a)                                                                     \
      throw std::runtime_error(fmt::format("Error at {}:{}: {}", __LINE__,     \
                                           __FILE__,                           \
                                           m(elf_errmsg(elferrnonumber))));    \
  } while (0)

#define CHECK_DECL(a, cond)                                                    \
  a;                                                                           \
  do {                                                                         \
    auto elferrnonumber = elf_errno();                                         \
    if (cond)                                                                  \
      throw std::runtime_error(fmt::format("CHECK_DECL failed at {}:{}: {}",   \
                                           __LINE__, __FILE__,                 \
                                           m(elf_errmsg(elferrnonumber))));    \
  } while (0)

#define THROW_IF(cond)                                                         \
  do {                                                                         \
    auto elferrnonumber = elf_errno();                                         \
    if (cond)                                                                  \
      throw std::runtime_error(                                                \
          fmt::format("Assertion \"{}\" failed at {}:{}, {}", #cond, __LINE__, \
                      __FILE__, m(elf_errmsg(elferrnonumber))));               \
  } while (0)
