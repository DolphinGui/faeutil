#pragma once

#include <cstdint>

namespace aef {

struct aef_header {
  char header[8] = "avrc++0";
  uint16_t length;
};

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
struct skip {
  uint8_t is_reg : 1 = false;
  uint8_t bytes : 7;
};

struct pop {
  uint8_t is_reg : 1 = true;
  uint8_t reg : 7;
};
} // namespace aef

/* When unwinding, first see if cfa_reg is nonzero. If so, use out to
   load cfa_reg to SP. Then, do pop and skip to restore register state.
   Finally, pop the return address and use that to look up the next unwind.*/