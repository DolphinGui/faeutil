#pragma once

#include "external/leb128.hpp"
#include <cstdint>
#include <cstring>
#include <dwarf.h>
#include <fmt/core.h>
#include <optional>
#include <string>

template <typename T> T consume(const uint8_t **ptr) noexcept {
  T result;
  std::memcpy(&result, *ptr, sizeof(T));
  *ptr += sizeof(T);
  return result;
}

inline std::string consume_cstr(const uint8_t **ptr) {
  auto result = std::string(reinterpret_cast<const char *>(*ptr));
  *ptr += result.length() + 1;
  return result;
}

struct base_addr {
  std::optional<uint64_t> pc{}, text{}, data{}, func{};
};

inline int64_t consume_ptr(const uint8_t **ptr, uint8_t encoding,
                           base_addr base = {}) {
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
    result += consume<uint32_t>(ptr);
    return result;
  case DW_EH_PE_udata2:
    result += consume<uint16_t>(ptr);
    return result;
  case DW_EH_PE_udata4:
    result += consume<uint32_t>(ptr);
    return result;
  case DW_EH_PE_udata8:
    result += consume<uint64_t>(ptr);
    return result;
  case DW_EH_PE_uleb128:
    uint64_t r;
    ptr += bfs::DecodeLeb128<uint64_t>(*ptr, 12, &r);
    result += r;
    return result;
  case DW_EH_PE_sdata2:
    result += consume<int16_t>(ptr);
    return result;
  case DW_EH_PE_sdata4:
    result += consume<int32_t>(ptr);
    return result;
  case DW_EH_PE_sdata8:
    result += consume<int64_t>(ptr);
    return result;
  case DW_EH_PE_sleb128: {
    int64_t r{};
    ptr += bfs::DecodeLeb128(*ptr, 12, &r);
    result += r;
    return result;
  }
  default:
    throw std::runtime_error(
        fmt::format("Unknown DWARF encoding: {:#0x}", encoding));
  }
}
