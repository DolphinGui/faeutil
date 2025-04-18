#pragma once

#include "cast.hpp"
#include <array>
#include <cstdint>
#include <string>
#include <type_traits>

namespace elf {

template <typename True, typename False, bool> struct phi;

template <typename True, typename False>
struct phi<True, False, true> : std::type_identity<True> {};
template <typename True, typename False>
struct phi<True, False, false> : std::type_identity<False> {};

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

enum elf_class : u8 { e32 = 1, e64 = 2 };
inline auto format_as(elf_class e) noexcept {
  switch (e) {
  case e32:
    return "e32";
  case e64:
    return "e64";
  default:
    return "???";
  }
}

enum endianess : u8 { little = 1, big = 2 };
inline auto format_as(endianess e) noexcept {
  switch (e) {
  case little:
    return "little";
  case big:
    return "big";
  default:
    return "???";
  }
}
// many more os_abi I am not going to implement
enum os_abi : u8 { sys_v };

inline auto format_as(os_abi e) noexcept {
  switch (e) {
  case sys_v:
    return "SYSTEM-V";
  default:
    return "???";
  }
}

enum file_type : u16 { none_f, rel, exec, dyn, core };
inline auto format_as(file_type e) noexcept {
  switch (e) {
  case none_f:
    return "none_f";
  case rel:
    return "relocatable";
  case exec:
    return "executable";
  case dyn:
    return "dynamic library";
  case core:
    return "core";
  default:
    return "???";
  }
}

enum machine_type : u16 { none_m, att, sparc, x86, avr = 0x53 };

inline auto format_as(machine_type e) noexcept {
  switch (e) {
  case none_m:
    return "none_m";
  case att:
    return "AT&T WE 32100";
  case sparc:
    return "SPARC";
  case x86:
    return "x86";
  case avr:
    return "AVR";
  default:
    return "???";
  }
}

namespace sh {

enum type : u32 {
  null,
  prog_bit,
  sym_tab,
  str_tab,
  rela,
  hash,
  dynamic,
  note,
  nobit,
  rel,
  shlib,
  dynsym,
  init_arr,
  fini_arr,
  preinit_arr,
  t_group,
  symtab_shndx
};

inline auto format_as(type e) noexcept {
  switch (e) {
  case null:
    return "null";
  case prog_bit:
    return "prog_bit";
  case sym_tab:
    return "sym_tab";
  case str_tab:
    return "str_tab";
  case rela:
    return "rela";
  case hash:
    return "hash";
  case dynamic:
    return "dynamic";
  case note:
    return "note";
  case nobit:
    return "nobit";
  case rel:
    return "rel";
  case shlib:
    return "shlib";
  case dynsym:
    return "dynsym";
  case init_arr:
    return "init_arr";
  case fini_arr:
    return "fini_arr";
  case preinit_arr:
    return "preinit_arr";
  case t_group:
    return "group";
  case symtab_shndx:
    return "symtab_shndx";
  default:
    return "reserved";
  }
}

enum flags32 : u32 {};

enum flags64 : u64 {
  write = 0x1,
  alloc = 0x2,
  execinstr = 0x4,
  merge = 0x10,
  strings = 0x20,
  info_link = 0x40,
  link_order = 0x80,
  os_nonconforming = 0x100,
  f_group = 0x200,
  tls = 0x400,
  maskos = 0x0ff00000,
  maskproc = 0xf0000000,
  ordered = 0x4000000,
  exclude = 0x8000000,
};
template <std::integral Int>
using flags = phi<flags32, flags64, std::is_same_v<u32, Int>>::type;

template<std::integral To, std::integral From>
inline constexpr flags<To> convert(flags<From> f){
  if constexpr(std::is_same_v<To, From>){
    return f;
  }
  return flags<To>(cast<To>(cast<From>(f)));
}


inline std::string format_as(flags64 e) noexcept {
  std::string result;
  constexpr auto all_flags =
      std::to_array<std::pair<flags64, const char *>>({{write, "W"},
                                                       {alloc, "A"},
                                                       {execinstr, "X"},
                                                       {merge, "M"},
                                                       {strings, "S"},
                                                       {info_link, "I"},
                                                       {link_order, "L"},
                                                       {os_nonconforming, "O"},
                                                       {f_group, "G"},
                                                       {tls, "T"},
                                                       {exclude, "X"}});
  for (auto &&[val, name] : all_flags) {
    if (bool(e & val)) {
      result += name;
    }
  }
  return result;
}
} // namespace sh

namespace ph {

enum type : u32 { null, load, dynamic, interp, note, shlib, phdr };

constexpr auto format_as(type e) {
  switch (e) {
  case null:
    return "null";
  case load:
    return "load";
  case dynamic:
    return "dynamic";
  case interp:
    return "interp";
  case note:
    return "note";
  case shlib:
    return "shlib";
  case phdr:
    return "phdr";
  default:
    return "???";
  }
}
enum flags { executable = (1 << 0), write = (1 << 1), read = (1 << 2) };
inline std::string format_as(flags f) {
  std::string result;
  constexpr auto all_flags = std::to_array<std::pair<flags, const char *>>(
      {{executable, "X"}, {write, "W"}, {read, "R"}});
  for (auto &&[val, name] : all_flags) {
    if (bool(f & val)) {
      result += name;
    }
  }
  return result;
}
} // namespace ph

struct program_header {
  ph::type type;
  u32 offset;
  u32 virtual_addr;
  u32 physical_addr;
  u32 file_size;
  u32 mem_size;
  ph::flags flags;
  u32 alignment;
  bool operator==(program_header const &) const = default;
};
} // namespace elf
