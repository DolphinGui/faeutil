#pragma once

#include <fmt/core.h>
#include <libelf.h>
#include <stdexcept>

inline const char *m(const char *c) {
  if (!c)
    return "";
  return c;
}

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
