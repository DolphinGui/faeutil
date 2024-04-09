#pragma once
#include <cstdint>
#include <string_view>
namespace avr {
/* Processor specific flags for the ELF header e_flags field.  */
constexpr auto EF_AVR_MACH = 0x7F;

/* If bit #7 is set, it is assumed that the elf file uses local symbols
   as reference for the relocations so that linker relaxation is possible.  */
constexpr auto EF_AVR_LINKRELAX_PREPARED = 0x80;

constexpr auto E_AVR_MACH_AVR1 = 1;
constexpr auto E_AVR_MACH_AVR2 = 2;
constexpr auto E_AVR_MACH_AVR25 = 25;
constexpr auto E_AVR_MACH_AVR3 = 3;
constexpr auto E_AVR_MACH_AVR31 = 31;
constexpr auto E_AVR_MACH_AVR35 = 35;
constexpr auto E_AVR_MACH_AVR4 = 4;
constexpr auto E_AVR_MACH_AVR5 = 5;
constexpr auto E_AVR_MACH_AVR51 = 51;
constexpr auto E_AVR_MACH_AVR6 = 6;
constexpr auto E_AVR_MACH_AVRTINY = 100;
constexpr auto E_AVR_MACH_XMEGA1 = 101;
constexpr auto E_AVR_MACH_XMEGA2 = 102;
constexpr auto E_AVR_MACH_XMEGA3 = 103;
constexpr auto E_AVR_MACH_XMEGA4 = 104;
constexpr auto E_AVR_MACH_XMEGA5 = 105;
constexpr auto E_AVR_MACH_XMEGA6 = 106;
constexpr auto E_AVR_MACH_XMEGA7 = 107;

enum reloc_type : uint32_t {
  R_AVR_NONE = 0,
  R_AVR_32 = 1,
  R_AVR_7_PCREL = 2,
  R_AVR_13_PCREL = 3,
  R_AVR_16 = 4,
  R_AVR_16_PM = 5,
  R_AVR_LO8_LDI = 6,
  R_AVR_HI8_LDI = 7,
  R_AVR_HH8_LDI = 8,
  R_AVR_LO8_LDI_NEG = 9,
  R_AVR_HI8_LDI_NEG = 10,
  R_AVR_HH8_LDI_NEG = 11,
  R_AVR_LO8_LDI_PM = 12,
  R_AVR_HI8_LDI_PM = 13,
  R_AVR_HH8_LDI_PM = 14,
  R_AVR_LO8_LDI_PM_NEG = 15,
  R_AVR_HI8_LDI_PM_NEG = 16,
  R_AVR_HH8_LDI_PM_NEG = 17,
  R_AVR_CALL = 18,
  R_AVR_LDI = 19,
  R_AVR_6 = 20,
  R_AVR_6_ADIW = 21,
  R_AVR_MS8_LDI = 22,
  R_AVR_MS8_LDI_NEG = 23,
  R_AVR_LO8_LDI_GS = 24,
  R_AVR_HI8_LDI_GS = 25,
  R_AVR_8 = 26,
  R_AVR_8_LO8 = 27,
  R_AVR_8_HI8 = 28,
  R_AVR_8_HLO8 = 29,
  R_AVR_DIFF8 = 30,
  R_AVR_DIFF16 = 31,
  R_AVR_DIFF32 = 32,
  R_AVR_LDS_STS_16 = 33,
  R_AVR_PORT6 = 34,
  R_AVR_PORT5 = 35,
  R_AVR_32_PCREL = 36,
  R_AVR_max
};

constexpr uint32_t r_sym(uint32_t i) noexcept { return i >> 8; }
constexpr reloc_type r_type(uint32_t i) noexcept {
  return static_cast<reloc_type>(i & 0xff);
}
constexpr uint32_t r_info(uint32_t sym, reloc_type type) noexcept {
  return ((unsigned)(sym) << 8) + ((type) & 0xff);
}

#define STRINGTIZE(TOK) #TOK
constexpr std::string_view to_string(reloc_type t) noexcept {
  switch (t) {
  case R_AVR_NONE:
    return STRINGTIZE(R_AVR_NONE);
  case R_AVR_32:
    return STRINGTIZE(R_AVR_32);
  case R_AVR_7_PCREL:
    return STRINGTIZE(R_AVR_7_PCREL);
  case R_AVR_13_PCREL:
    return STRINGTIZE(R_AVR_13_PCREL);
  case R_AVR_16:
    return STRINGTIZE(R_AVR_16);
  case R_AVR_16_PM:
    return STRINGTIZE(R_AVR_16_PM);
  case R_AVR_LO8_LDI:
    return STRINGTIZE(R_AVR_LO8_LDI);
  case R_AVR_HI8_LDI:
    return STRINGTIZE(R_AVR_HI8_LDI);
  case R_AVR_HH8_LDI:
    return STRINGTIZE(R_AVR_HH8_LDI);
  case R_AVR_LO8_LDI_NEG:
    return STRINGTIZE(R_AVR_LO8_LDI_NEG);
  case R_AVR_HI8_LDI_NEG:
    return STRINGTIZE(R_AVR_HI8_LDI_NEG);
  case R_AVR_HH8_LDI_NEG:
    return STRINGTIZE(R_AVR_HH8_LDI_NEG);
  case R_AVR_LO8_LDI_PM:
    return STRINGTIZE(R_AVR_LO8_LDI_PM);
  case R_AVR_HI8_LDI_PM:
    return STRINGTIZE(R_AVR_HI8_LDI_PM);
  case R_AVR_HH8_LDI_PM:
    return STRINGTIZE(R_AVR_HH8_LDI_PM);
  case R_AVR_LO8_LDI_PM_NEG:
    return STRINGTIZE(R_AVR_LO8_LDI_PM_NEG);
  case R_AVR_HI8_LDI_PM_NEG:
    return STRINGTIZE(R_AVR_HI8_LDI_PM_NEG);
  case R_AVR_HH8_LDI_PM_NEG:
    return STRINGTIZE(R_AVR_HH8_LDI_PM_NEG);
  case R_AVR_CALL:
    return STRINGTIZE(R_AVR_CALL);
  case R_AVR_LDI:
    return STRINGTIZE(R_AVR_LDI);
  case R_AVR_6:
    return STRINGTIZE(R_AVR_6);
  case R_AVR_6_ADIW:
    return STRINGTIZE(R_AVR_6_ADIW);
  case R_AVR_MS8_LDI:
    return STRINGTIZE(R_AVR_MS8_LDI);
  case R_AVR_MS8_LDI_NEG:
    return STRINGTIZE(R_AVR_MS8_LDI_NEG);
  case R_AVR_LO8_LDI_GS:
    return STRINGTIZE(R_AVR_LO8_LDI_GS);
  case R_AVR_HI8_LDI_GS:
    return STRINGTIZE(R_AVR_HI8_LDI_GS);
  case R_AVR_8:
    return STRINGTIZE(R_AVR_8);
  case R_AVR_8_LO8:
    return STRINGTIZE(R_AVR_8_LO8);
  case R_AVR_8_HI8:
    return STRINGTIZE(R_AVR_8_HI8);
  case R_AVR_8_HLO8:
    return STRINGTIZE(R_AVR_8_HLO8);
  case R_AVR_DIFF8:
    return STRINGTIZE(R_AVR_DIFF8);
  case R_AVR_DIFF16:
    return STRINGTIZE(R_AVR_DIFF16);
  case R_AVR_DIFF32:
    return STRINGTIZE(R_AVR_DIFF32);
  case R_AVR_LDS_STS_16:
    return STRINGTIZE(R_AVR_LDS_STS_16);
  case R_AVR_PORT6:
    return STRINGTIZE(R_AVR_PORT6);
  case R_AVR_PORT5:
    return STRINGTIZE(R_AVR_PORT5);
  case R_AVR_32_PCREL:
    return STRINGTIZE(R_AVR_32_PCREL);
  case R_AVR_max:
    return STRINGTIZE(R_AVR_max);
  }
  return "unknown reloc_type";
}
#undef STRINGTIZE
} // namespace avr