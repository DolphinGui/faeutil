#pragma once

#include "binary_parsing.hpp"
#include <cstdint>
#include <cstring>
#include <fmt/core.h>
#include <optional>
struct base_addr {
  std::optional<uint64_t> pc{}, text{}, data{}, func{};
};

enum {
  DW_EH_PE_absptr = 0x00,
  DW_EH_PE_omit = 0xff,

  /* FDE data encoding.  */
  DW_EH_PE_uleb128 = 0x01,
  DW_EH_PE_udata2 = 0x02,
  DW_EH_PE_udata4 = 0x03,
  DW_EH_PE_udata8 = 0x04,
  DW_EH_PE_sleb128 = 0x09,
  DW_EH_PE_sdata2 = 0x0a,
  DW_EH_PE_sdata4 = 0x0b,
  DW_EH_PE_sdata8 = 0x0c,
  DW_EH_PE_signed = 0x08,

  /* FDE flags.  */
  DW_EH_PE_pcrel = 0x10,
  DW_EH_PE_textrel = 0x20,
  DW_EH_PE_datarel = 0x30,
  DW_EH_PE_funcrel = 0x40,
  DW_EH_PE_aligned = 0x50,

  DW_EH_PE_indirect = 0x80
};

inline int64_t consume_ptr(Reader &r, uint8_t encoding, base_addr base = {}) {
  int64_t result = 0;
  if (encoding & DW_EH_PE_pcrel) {
    result = base.pc.value();
  } else if (encoding & DW_EH_PE_textrel)
    result = base.text.value();
  else if (encoding & DW_EH_PE_datarel)
    result = base.data.value();
  else if (encoding & DW_EH_PE_funcrel)
    result = base.func.value();

  switch (encoding & 0x0f) {
  case DW_EH_PE_absptr:
    result += r.consume<uint32_t>();
    return result;
  case DW_EH_PE_udata2:
    result += r.consume<uint16_t>();
    return result;
  case DW_EH_PE_udata4:
    result += r.consume<uint32_t>();
    return result;
  case DW_EH_PE_udata8:
    result += r.consume<uint64_t>();
    return result;
  case DW_EH_PE_uleb128:
    result += r.consume_uleb();
    return result;
  case DW_EH_PE_sdata2:
    result += r.consume<int16_t>();
    return result;
  case DW_EH_PE_sdata4:
    result += r.consume<int32_t>();
    return result;
  case DW_EH_PE_sdata8:
    result += r.consume<int64_t>();
    return result;
  case DW_EH_PE_sleb128: {
    result += r.consume_sleb();
    return result;
  }
  default:
    throw std::runtime_error(
        fmt::format("Unknown DWARF encoding: {:#0x}", encoding));
  }
}
