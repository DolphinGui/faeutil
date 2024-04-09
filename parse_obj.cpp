#include "parse.hpp"

#include "avr_reloc.hpp"
#include "external/ctre/ctre.hpp"
#include "external/leb128.hpp"
#include <cstdint>
#include <cstdio>
#include <dwarf.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <err.h>
#include <fcntl.h>
#include <fmt/ranges.h>
#include <libelf.h>
#include <span>
#include <stdexcept>
#include <sysexits.h>

#define CHECK(a)                                                               \
  if (auto error_code = a)                                                     \
  throw std::runtime_error(                                                    \
      fmt::format("Error at {}: {}", __LINE__, elf_errmsg(error_code)))

#define IF_PTR(a)                                                              \
  if (a) {                                                                     \
    throw std::runtime_error(fmt::format("IF_PTR failed at line {}: {}",       \
                                         __LINE__, elf_errmsg(elf_errno())));  \
  } else

#define CHECK_DECL(a, cond)                                                    \
  a;                                                                           \
  if (cond)                                                                    \
  throw std::runtime_error(fmt::format("CHECK_DECL failed at line {}: {}",     \
                                       __LINE__, elf_errmsg(elf_errno())))

#define THROW_IF(cond)                                                         \
  if (cond)                                                                    \
  throw std::runtime_error(                                                    \
      fmt::format("Assertion \"{}\" failed at line {}", #cond, __LINE__))

ObjectFile::ObjectFile(int file)
    : file_desc(file), elf(GlobalInitializer::init().open_elf(file)) {
  if (elf == nullptr)
    throw std::runtime_error(
        fmt::format("elf_begin() error: {}", elf_errmsg(-1)));
  if (kind() != ELF_K_ELF)
    throw std::runtime_error("Expected object file");

  size_t section_max{};
  CHECK(elf_getshdrnum(elf, &section_max));
  size_t sh_strtab_index{};
  CHECK(elf_getshdrstrndx(elf, &sh_strtab_index));
  for (size_t i = 1; i != section_max; i++) {
    using namespace std::string_view_literals;
    CHECK_DECL(Elf_Scn *section = elf_getscn(elf, i), !section);
    CHECK_DECL(Elf32_Shdr *header = elf32_getshdr(section), !header);
    CHECK_DECL(auto name = elf_strptr(elf, sh_strtab_index, header->sh_name),
               !name);
    if (name == ".symtab"sv) {
      symtab_index = i;
    } else if (name == ".strtab"sv) {
      strtab_index = i;
    }
  }
  THROW_IF(symtab_index == 0);
  THROW_IF(strtab_index == 0);
}

ObjectFile::~ObjectFile() {
  elf_end(elf);
  if (file_desc)
    close(file_desc);
}

ObjectFile::GlobalInitializer::GlobalInitializer() {
  if (elf_version(EV_CURRENT) == EV_NONE)
    errx(EX_SOFTWARE, " ELF library initialization failed : %s ",
         elf_errmsg(-1));
}
ObjectFile::GlobalInitializer &ObjectFile::GlobalInitializer::init() {
  static ObjectFile::GlobalInitializer initializer = {};
  return initializer;
}

Elf *ObjectFile::GlobalInitializer::open_elf(int file_desc) {
  return elf_begin(file_desc, Elf_Cmd::ELF_C_RDWR, nullptr);
}

using buffer_view = std::span<const uint8_t>;
template <> struct fmt::formatter<buffer> : formatter<buffer_view> {
  auto format(buffer s, format_context &ctx) const {
    return formatter<buffer_view>::format(buffer_view(s.b), ctx);
  }
};

std::string_view ObjectFile::get_str(uint32_t offset) {
  CHECK_DECL(auto result = elf_strptr(elf, strtab_index, offset), !result);
  return result;
}

Elf32_Sym &ObjectFile::get_sym(uint32_t index) {
  CHECK_DECL(Elf_Scn *section = elf_getscn(this->elf, this->symtab_index),
             !section);
  Elf_Data *data{};
  CHECK_DECL(data = elf_getdata(section, data), elf_errno());
  THROW_IF(data->d_type != ELF_T_SYM);
  // haha std::span still has no bounds checking
  THROW_IF(index >= data->d_size / sizeof(Elf32_Sym));
  return static_cast<Elf32_Sym *>(data->d_buf)[index];
}

namespace {
struct exception_sections {
  buffer frame_sections;
  buffer frame_relocations;
  buffer lsda_sections;
  buffer lsda_relocations;
};

exception_sections get_sections(ObjectFile &o) {

  size_t section_max{};
  CHECK(elf_getshdrnum(o.elf, &section_max));
  using namespace std::string_view_literals;

  exception_sections result;

  size_t sh_strtab_index{};
  CHECK(elf_getshdrstrndx(o.elf, &sh_strtab_index));
  // This possibly copies a lot of data. If a lot of time/memory is being spent
  // here, it may be worth it to move to a no-copy iterator type model.
  for (size_t i = 1; i != section_max; i++) {
    CHECK_DECL(Elf_Scn *section = elf_getscn(o.elf, i), !section);
    CHECK_DECL(Elf32_Shdr *header = elf32_getshdr(section), !header);
    CHECK_DECL(auto name = elf_strptr(o.elf, sh_strtab_index, header->sh_name),
               !name);

    auto copy_data = [&](buffer &section_map) {
      Elf_Data *data{};
      while (true) {
        CHECK_DECL(data = elf_getdata(section, data), elf_errno());
        if (!data)
          break;
        section_map.b.append(static_cast<uint8_t *>(data->d_buf), data->d_size);
      }
    };

    if (ctre::match<R"(\.eh_frame.*)">(name)) {
      copy_data(result.frame_sections);
    } else if (ctre::match<R"(\.rela\.eh_frame.*)">(name)) {
      copy_data(result.frame_relocations);
    } else if (ctre::match<R"(\.gcc_except_table.*)">(name)) {
      copy_data(result.lsda_sections);
    } else if (ctre::match<R"(\.rela\.gcc_except_table.*)">(name)) {
      copy_data(result.lsda_sections);
    }
  }
  return result;
}

struct CIE_unextended {
  uint32_t length;
  uint32_t id;
  uint8_t version;
};

template <typename T> T consume(const uint8_t **ptr) {
  T result;
  std::memcpy(&result, *ptr, sizeof(T));
  *ptr += sizeof(T);
  return result;
}
std::string consume_cstr(const uint8_t **ptr) {
  auto result = std::string(reinterpret_cast<const char *>(*ptr));
  *ptr += result.length() + 1;
  return result;
}
struct dwarf_ptr {
  int64_t val;
  bool pc_rel, text_rel, data_rel, func_rel, aligned;
};

dwarf_ptr consume_ptr(const uint8_t **ptr, uint8_t encoding) {
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
    fmt::println("{}", encoding);
    throw std::runtime_error("what is this");
  }
}

struct range {
  uint32_t begin, length;
};

struct CIE_data {
  uint64_t length;
  uint32_t id;
  uint8_t version;
  uint32_t eh_data;
  uint64_t code_alignment;
  int64_t data_alignment;
  std::string augment_str;
  uint64_t return_reg, augmentation_length;
  uint8_t fde_augment_encoding, personality_encoding, fde_ptr_encoding;
  dwarf_ptr personality_ptr;
  const uint8_t *cfi_begin, *cfi_end;
};

struct relocatable {
  std::string symbol;
  avr::reloc_type type{};
  uint64_t default_value{};
  int64_t addend{};
};

struct FDE_data {
  const uint8_t *fde_begin, *fde_end;
  relocatable pc_begin, pc_end;
  CIE_data *cie{};
  relocatable lsda;
  size_t stack_usage{};
  std::unordered_map<uint8_t, ssize_t> register_offsets;
  uint8_t cfa_register;
};

CIE_data parse_cie(const uint8_t *&ptr) {
  CIE_data result;
  result.length = consume<uint32_t>(&ptr);
  const uint8_t *begin = ptr;
  if (result.length == 0xffffffff) {
    result.length = consume<uint64_t>(&ptr);
  }
  result.id = consume<uint32_t>(&ptr);
  THROW_IF(result.id != 0);
  result.version = consume<uint8_t>(&ptr);
  result.augment_str = consume_cstr(&ptr);
  if (result.augment_str.find("eh") != std::string::npos) {
    result.eh_data = consume<uint32_t>(&ptr);
  }
  ptr += bfs::DecodeLeb128<uint64_t>(ptr, ptr - begin, &result.code_alignment);
  ptr += bfs::DecodeLeb128(ptr, ptr - begin, &result.data_alignment);
  ptr += bfs::DecodeLeb128<uint64_t>(ptr, ptr - begin, &result.return_reg);
  ptr += bfs::DecodeLeb128<uint64_t>(ptr, ptr - begin,
                                     &result.augmentation_length);

  for (auto c : result.augment_str) {
    switch (c) {
    case 'z':
      continue;
    case 'L':
      result.fde_augment_encoding = consume<uint8_t>(&ptr);
      break;
    case 'P':
      result.personality_encoding = consume<uint8_t>(&ptr);
      result.personality_ptr = consume_ptr(&ptr, result.personality_encoding);
      break;
    case 'R':
      result.fde_ptr_encoding = consume<uint8_t>(&ptr);
      break;
    default:
      throw std::runtime_error("I'm not handling eh");
    }
  }
  result.cfi_begin = ptr;
  result.cfi_end = begin + result.length;
  THROW_IF(ptr >= begin + result.length);
  return result;
}

void parse_cfi(const uint8_t *ptr, const uint8_t *end, FDE_data &out,
               const uint8_t *begin) {
  while (ptr < end) {
    fmt::println("before: {:#04x} at {:#04x}", *ptr, ptr - begin);
    switch (*ptr++) {
    case DW_CFA_nop:
      fmt::println("nop");
      break;
    case DW_CFA_set_loc:
      fmt::println("set loc");
    case DW_CFA_advance_loc: {
      fmt::println("loc");
      uint64_t length{};
      ptr += bfs::DecodeLeb128(ptr, 4, &length);
      // we don't actually care about location data
    } break;
    case DW_CFA_advance_loc1: {
      fmt::println("loc1");
      ptr += 1;
    } break;
    case DW_CFA_advance_loc2: {
      fmt::println("loc2");
      ptr += 2;
    } break;
    case DW_CFA_advance_loc4: {
      fmt::println("loc4");
      ptr += 4;
    } break;
    case DW_CFA_offset:;
      {
        fmt::println("offset");
        uint64_t reg{}, offset{};
        ptr += bfs::DecodeLeb128(ptr, 4, &reg);
        ptr += bfs::DecodeLeb128(ptr, 4, &offset);
        out.register_offsets[reg] = offset;
      }
      break;
    case DW_CFA_def_cfa_register: {
      fmt::println("cfa_reg");
      uint64_t reg{};
      ptr += bfs::DecodeLeb128(ptr, 4, &reg);
      out.register_offsets[out.stack_usage] = reg;
    } break;
    case DW_CFA_def_cfa_offset: {
      fmt::println("cfa_offset");
      uint64_t offset{};
      ptr += bfs::DecodeLeb128(ptr, 4, &offset);
      out.stack_usage = offset;
    } break;
    case DW_CFA_def_cfa: {
      fmt::println("def_cfa");
      uint64_t reg{}, offset{};
      ptr += bfs::DecodeLeb128(ptr, 4, &reg);
      ptr += bfs::DecodeLeb128(ptr, 4, &offset);
      out.cfa_register = reg;
      out.stack_usage = offset;
    } break;
    // I hate this. I hate dwarf even more. this really requires extensive
    // testing to make sure this doesn't break.
    case 0xa4: {
      ptr += 3;
      out.register_offsets[36] = -1;
    } break;
    default:
      throw std::runtime_error(fmt::format(
          "Unknown CFI type: {:#04x} at {:#04x}", ptr[-1], ptr - begin - 1));
    }
  }
}

bool parse_fde(const uint8_t **ptr, uint8_t encoding, CIE_data &cie,
               const uint8_t *b) {
  uint64_t length = consume<uint32_t>(ptr);
  if (length == 0xffffffff) {
    length = consume<uint64_t>(ptr);
  }
  if (length == 0) {
    fmt::println("end of fdes: {:#04x}", *ptr - b);
    return false;
  }
  auto begin = *ptr;
  fmt::println("begin: {:#04x}", *ptr - b - 4);

  int32_t cie_offset = consume<int32_t>(ptr);
  fmt::println("encoding: {}", encoding);
  dwarf_ptr pc_begin = consume_ptr(ptr, encoding);
  dwarf_ptr pc_range = consume_ptr(ptr, encoding);
  uint64_t augment_length{};
  dwarf_ptr lsda;
  if (cie.augment_str.find('z') != std::string::npos) {
    *ptr += bfs::DecodeLeb128(*ptr, 4, &augment_length);
    lsda = consume_ptr(ptr, cie.fde_augment_encoding);
  }

  FDE_data data;
  parse_cfi(cie.cfi_begin, cie.cfi_end, data, b);
  parse_cfi(*ptr, begin + length, data, b);
  fmt::println("length: {}", length);
  *ptr = begin + length;
  return true;
}

void parse_frames(const uint8_t *ptr, const uint8_t *end) {
  auto begin = ptr;
  while (ptr < end) {
    fmt::println("before: {:#04x}", ptr - begin);
    auto cie = parse_cie(ptr);
    ptr = cie.cfi_end;
    fmt::println("length: {:#04x}", cie.length);
    fmt::println("after assign: {:#04x}", ptr - begin);
    while (parse_fde(&ptr, cie.fde_ptr_encoding, cie, begin) && ptr < end)
      ;
  }
}

void parse_eh(ObjectFile &o, buffer_view eh, std::span<Elf32_Rela> eh_reloc) {
  using namespace avr;
  // for (auto &reloc : eh_reloc) {
  //   auto &symbol = o.get_sym(r_sym(reloc.r_info));
  //   auto symbol_name = o.get_str(symbol.st_name);
  //   auto type = to_string(r_type(reloc.r_info));
  //   fmt::println("{}, {}, {}, {}, section {}", symbol_name, type,
  //                reloc.r_offset, reloc.r_addend, symbol.st_shndx);
  // }
  
  
}

} // namespace

void parse_object(ObjectFile &o) {
  auto n = get_sections(o);
  parse_eh(o, n.frame_sections.b,
           {reinterpret_cast<Elf32_Rela *>(n.frame_relocations.b.data()),
            n.frame_relocations.b.size() / sizeof(Elf32_Rela)});
}