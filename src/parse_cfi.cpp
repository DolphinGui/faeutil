#include "binary_parsing.hpp"
#include "parse.hpp"
#include <cstdint>
#include <dwarf.h>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <stdexcept>
#include <type_traits>

namespace {
constexpr auto data_alignment = -1;

void parse(callstack *out, Reader& r) {
  uint8_t inst = r.consume<uint8_t>();
  auto operand = [&](auto fake_arg) {
    decltype(fake_arg) offset{};
    if constexpr (std::is_signed_v<decltype(fake_arg)>) {
      offset = r.consume_sleb();
    } else {
      offset = r.consume_uleb();
    }
    return offset;
  };
  switch (inst & 0b11000000) {
  case DW_CFA_advance_loc:
    return;
  case DW_CFA_offset: {
    uint8_t reg = inst & 0b00111111;
    auto offset = operand(uint64_t{});
    out->register_offsets[reg] = offset * data_alignment;
    return;
  }
  case DW_CFA_restore:
    throw std::runtime_error("I am not implementing restore.");
  case 0:
    break;
  }
  switch (inst) {
  case DW_CFA_def_cfa_register: {
    out->cfa_register = operand(uint64_t{});
    return;
  }

  case DW_CFA_def_cfa_offset: {
    out->cfa_offset = operand(uint64_t{}) * data_alignment;
    return;
  }

  case DW_CFA_def_cfa: {
    auto reg = operand(uint64_t{});
    out->cfa_offset = operand(uint64_t{}) * data_alignment;
    out->cfa_register = reg;
  }
  case DW_CFA_nop:
    return;
  default:
    throw std::runtime_error(fmt::format("unexpected DW_CFA value: {:#04x}", inst));
  }
}
} // namespace

callstack parse_cfi(std::span<const uint8_t> cfi_initial,
                      std::span<const uint8_t> fde_cfi) {
  callstack result;
  auto data = Reader(cfi_initial);
  while (!data.empty()) {
    parse(&result, data);
  }
  auto ptr = Reader(fde_cfi);
  while (!ptr.empty()) {
    parse(&result, ptr);
  }
  return result;
}