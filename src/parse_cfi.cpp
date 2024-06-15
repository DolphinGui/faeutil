#include "binary_parsing.hpp"
#include "fae.hpp"
#include "parse.hpp"
#include <cstdint>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <stdexcept>
#include <type_traits>

namespace {
constexpr auto data_alignment = -1;
enum {
  DW_CFA_advance_loc = 0x40,
  DW_CFA_offset = 0x80,
  DW_CFA_restore = 0xc0,
  DW_CFA_extended = 0,

  DW_CFA_nop = 0x00,
  DW_CFA_set_loc = 0x01,
  DW_CFA_advance_loc1 = 0x02,
  DW_CFA_advance_loc2 = 0x03,
  DW_CFA_advance_loc4 = 0x04,
  DW_CFA_offset_extended = 0x05,
  DW_CFA_restore_extended = 0x06,
  DW_CFA_undefined = 0x07,
  DW_CFA_same_value = 0x08,
  DW_CFA_register = 0x09,
  DW_CFA_remember_state = 0x0a,
  DW_CFA_restore_state = 0x0b,
  DW_CFA_def_cfa = 0x0c,
  DW_CFA_def_cfa_register = 0x0d,
  DW_CFA_def_cfa_offset = 0x0e,
  DW_CFA_def_cfa_expression = 0x0f,
  DW_CFA_expression = 0x10,
  DW_CFA_offset_extended_sf = 0x11,
  DW_CFA_def_cfa_sf = 0x12,
  DW_CFA_def_cfa_offset_sf = 0x13,
  DW_CFA_val_offset = 0x14,
  DW_CFA_val_offset_sf = 0x15,
  DW_CFA_val_expression = 0x16,

  DW_CFA_low_user = 0x1c,
  DW_CFA_MIPS_advance_loc8 = 0x1d,
  DW_CFA_GNU_window_save = 0x2d,
  DW_CFA_AARCH64_negate_ra_state = 0x2d,
  DW_CFA_GNU_args_size = 0x2e,
  DW_CFA_GNU_negative_offset_extended = 0x2f,
  DW_CFA_high_user = 0x3f
};

void parse(callstack *out, Reader &r) {
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

    // this is jank, but reg 36 is presumably either SP or a fictional return
    // reg for some reason
    // AVR only
    if (!fae::is_valid_reg(reg) && reg != 36) {
      throw std::out_of_range(
          fmt::format("r{} is a call-clobbered register", reg));
    }
    out->register_offsets[reg] = offset * data_alignment;
    return;
  }
  case DW_CFA_restore:
    throw std::runtime_error("I am not implementing restore.");
  case 0:
    break;
  }

  switch (inst) {
  case DW_CFA_advance_loc1:
  case DW_CFA_advance_loc2:
  case DW_CFA_advance_loc4:
  case DW_CFA_set_loc:
    return;

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
    throw std::runtime_error(
        fmt::format("unexpected DW_CFA value: {:#04x}", inst));
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
