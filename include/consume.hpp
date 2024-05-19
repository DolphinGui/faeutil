#pragma once

#include "external/leb128.hpp"
#include <cstdint>
#include <cstring>
#include <dwarf.h>
#include <fmt/core.h>
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

struct dwarf_ptr {
  int64_t val{};
  bool pc_rel{}, text_rel{}, data_rel{}, func_rel{}, aligned{};
};

inline dwarf_ptr consume_ptr(const uint8_t **ptr, uint8_t encoding) {
  dwarf_ptr result;
  if (encoding & DW_EH_PE_pcrel)
    result.pc_rel = true;
  if (encoding & DW_EH_PE_textrel)
    result.text_rel = true;
  if (encoding & DW_EH_PE_datarel)
    result.data_rel = true;
  if (encoding & DW_EH_PE_funcrel)
    result.func_rel = true;
  if (encoding & DW_EH_PE_aligned)
    result.aligned = true;

  switch (encoding & 0x0f) {
  case DW_EH_PE_absptr:
    result.val = consume<uint32_t>(ptr);
    return result;
  case DW_EH_PE_udata2:
    result.val = consume<uint16_t>(ptr);
    return result;
  case DW_EH_PE_udata4:
    result.val = consume<uint32_t>(ptr);
    return result;
  case DW_EH_PE_udata8:
    result.val = consume<uint64_t>(ptr);
    return result;
  case DW_EH_PE_uleb128:
    uint64_t r;
    ptr += bfs::DecodeLeb128<uint64_t>(*ptr, 12, &r);
    result.val = r;
    return result;
  case DW_EH_PE_sdata2:
    result.val = consume<int16_t>(ptr);
    return result;
  case DW_EH_PE_sdata4:
    result.val = consume<int32_t>(ptr);
    return result;
  case DW_EH_PE_sdata8:
    result.val = consume<int64_t>(ptr);
    return result;
  case DW_EH_PE_sleb128:
    ptr += bfs::DecodeLeb128(*ptr, 12, &result.val);
    return result;
  default:
    throw std::runtime_error(
        fmt::format("Unknown DWARF encoding: {:#0x}", encoding));
  }
}
