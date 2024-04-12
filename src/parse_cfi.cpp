#include "consume.hpp"
#include "external/leb128.hpp"
#include "parse.hpp"
#include <cstdint>
#include <dwarf.h>
#include <fmt/ranges.h>
#include <stdexcept>

namespace {
constexpr auto data_alignment = -1;

void parse(unwind_info *out, const uint8_t **ptr) {
  uint8_t inst = consume<uint8_t>(ptr);
  auto operand = [&](auto fake_arg) {
    decltype(fake_arg) offset{};
    *ptr += bfs::DecodeLeb128<decltype(fake_arg)>(*ptr, 4, &offset);
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
    auto offset = operand(uint64_t{});
    out->register_offsets[reg] = offset;
  }
  case DW_CFA_nop:
    return;
  default:
    throw std::runtime_error(fmt::format("unexpected DW_CFA value: {}", inst));
  }
}
} // namespace

unwind_info parse_cfi(std::span<const uint8_t> cfi_initial,
                      std::span<const uint8_t> fde_cfi) {
  unwind_info result;
  const uint8_t *ptr = cfi_initial.data();
  while (ptr < cfi_initial.end().base()) {
    parse(&result, &ptr);
  }
  ptr = fde_cfi.data();
  while (ptr < fde_cfi.end().base()) {
    parse(&result, &ptr);
  }
  return result;
}