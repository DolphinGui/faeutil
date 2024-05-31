#pragma once

#include "binary_parsing.hpp"
#include "external/leb128.hpp"
#include <cstdint>
#include <cstring>
#include <dwarf.h>
#include <fmt/core.h>
#include <optional>
struct base_addr {
  std::optional<uint64_t> pc{}, text{}, data{}, func{};
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
