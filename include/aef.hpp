#pragma once

#include "parse.hpp"
#include <cstdint>

namespace fae {

struct aef_header {
  char header[8] = "avrc++0";
  uint16_t length;
};
/*
.fae_entries contains unwinding entries
.fae_info contains information on unwinding entries

uint32_t version (0)
uint32_t length (in bytes, not including this)
struct []{
uint32_t entry_offset
uint32_t entry_length (includes entry_header)
uint32_t begin_pc_symbol (index into symtab)
uint32_t range_pc_symbol
}

*/
/* Entries are aligned by 2 so that personality_ptr
   can be read by a single movw instruction. Pad
    using 0x00. Entries are also null terminated to
    simplify debugging */
struct entry_header {
  // canonical frame address is always frame register - 2.
  // -2 accounts for the return addresss
  uint8_t length;
  uint8_t cfa_reg;
  uint16_t lsda_ptr;
};

// 0x00 is padding byte, should only occur at the end of the entry.
// high bit is 0
struct skip {
  uint8_t bytes;
  constexpr skip(uint8_t b) noexcept : bytes(b & ~0b10000000) {}
};

// high bit is 1
struct pop {
  constexpr uint8_t get_reg() const noexcept { return _reg & ~0b10000000; }
  constexpr pop(uint8_t b) noexcept : _reg(b | 0b10000000) {}
  uint8_t _reg;
};

union frame_inst {
  pop p;
  skip s;
  uint8_t byte;
  constexpr frame_inst(skip s) : s(s) {}
  constexpr frame_inst(pop p) : p(p) {}
  constexpr bool is_pop() noexcept { return byte & 0b10000000; }
  constexpr bool is_skip() noexcept { return !is_pop(); }
};
// only call-saved registers are indexed
/*
0 -> 2
1 -> 3
2 -> 4
...
15 -> 17
16 -> 28
17 -> 29
*/

struct frame_info {
  unwind_info unwind;
};

struct info_entry {
  uint32_t entry_offset;
  uint32_t entry_length;
  uint32_t begin_pc_symbol;
  uint32_t range_pc_symbol;
};

} // namespace fae

/* When unwinding, first see if cfa_reg is nonzero. If so, use out to
   load cfa_reg to SP. Then, do pop and skip to restore register state.
   Finally, pop the return address and use that to look up the next unwind.*/