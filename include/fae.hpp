#pragma once

#include <cstdint>
#include <fmt/core.h>
#include <stdexcept>

namespace fae {

struct info_entry {
  uint32_t offset;
  uint32_t length;
  uint32_t begin;
  uint32_t range;
  uint32_t lsda_offset;
  uint32_t cfa_reg;
};

struct header {
  char header[8] = "avrc++0";
  uint16_t length;
};
struct table_entry {
  uint16_t pc_begin;
  uint16_t pc_end;
  uint16_t data;
  uint8_t frame_reg;
  uint8_t length;
  uint16_t lsda;
};
/* Entries are aligned by 2 so that personality_ptr
   can be read by a single movw instruction. Pad
    using 0x00. Entries may be null terminated to
    simplify debugging */

// 0x00 is padding byte, should only occur at the end of the entry.
// high bit is 0
struct skip {
  uint8_t bytes;
  constexpr static uint32_t max_skip_bytes = uint8_t(~0b10000000);
  constexpr skip(uint8_t b) : bytes(b & ~0b10000000) {
    if (b > max_skip_bytes)
      throw std::runtime_error(fmt::format("{} skip is too large!", b));
  }
};

enum struct reg : uint8_t {
  r2,
  r3,
  r4,
  r5,
  r6,
  r7,
  r8,
  r9,
  r10,
  r11,
  r12,
  r13,
  r14,
  r15,
  r16,
  r17,
  r28,
  r29,
  SPL,
  SPH
};

constexpr inline bool is_valid_reg(uint8_t r) {
  return !(r < 2 || (r > 17 && r < 28) || r > 29);
}

constexpr inline reg enumerate(uint8_t r) {
  if (!is_valid_reg(r))
    throw std::out_of_range(fmt::format("register r{} not in range", r));
  if (r < 18) {
    return reg(r - 2);
  } else {
    return reg(r - 12);
  }
}

constexpr inline uint8_t denumerate(reg r) {
  switch (r) {
  case reg::r2:
    return 2;
  case reg::r3:
    return 3;
  case reg::r4:
    return 4;
  case reg::r5:
    return 5;
  case reg::r6:
    return 6;
  case reg::r7:
    return 7;
  case reg::r8:
    return 8;
  case reg::r9:
    return 9;
  case reg::r10:
    return 10;
  case reg::r11:
    return 11;
  case reg::r12:
    return 12;
  case reg::r13:
    return 13;
  case reg::r14:
    return 14;
  case reg::r15:
    return 15;
  case reg::r16:
    return 16;
  case reg::r17:
    return 17;
  case reg::r28:
    return 28;
  case reg::r29:
    return 29;
  default:
    throw std::runtime_error("invalid register!");
  }
};

// high bit is 1
struct pop {
  constexpr reg get_reg() const noexcept { return reg(_reg & ~0b10000000); }
  constexpr pop(reg b) noexcept : _reg(uint8_t(b) | 0b10000000) {}
  uint8_t _reg;
};

union frame_inst {
  pop p;
  skip s;
  uint8_t byte;
  constexpr frame_inst(skip s) : s(s) {}
  constexpr frame_inst(pop p) : p(p) {}
  constexpr bool is_pop() const noexcept { return byte & 0b1000'0000; }
  constexpr bool is_skip() const noexcept { return !is_pop(); }
};

inline auto format_as(frame_inst f) {
  if (f.is_pop())
    return fmt::format("pop r{}", fae::denumerate(f.p.get_reg()));
  return fmt::format("skip {} bytes", (f.s.bytes));
}

} // namespace fae

/* When unwinding, first see if cfa_reg is nonzero. If so, use out to
   load cfa_reg to SP. Then, do pop and skip to restore register state.
   Finally, pop the return address and use that to look up the next unwind.*/