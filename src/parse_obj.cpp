#include "parse.hpp"

#include "avr_reloc.hpp"
#include "consume.hpp"
#include "external/ctre/ctre.hpp"
#include "external/leb128.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <dwarf.h>
#include <elf.h>
#include <elfutils/libdw.h>
#include <err.h>
#include <fcntl.h>
#include <fmt/ranges.h>
#include <libelf.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <sysexits.h>

#define CHECK(a)                                                               \
  do {                                                                         \
    auto elferrnonumber = elf_errno();                                         \
    if (a)                                                                     \
      throw std::runtime_error(fmt::format("Error at {}:{}: {}", __LINE__,     \
                                           __FILE__,                           \
                                           m(elf_errmsg(elferrnonumber))));    \
  } while (0)

#define CHECK_DECL(a, cond)                                                    \
  a;                                                                           \
  do {                                                                         \
    auto elferrnonumber = elf_errno();                                         \
    if (cond)                                                                  \
      throw std::runtime_error(fmt::format("CHECK_DECL failed at {}:{}: {}",   \
                                           __LINE__, __FILE__,                 \
                                           m(elf_errmsg(elferrnonumber))));    \
  } while (0)

#define THROW_IF(cond)                                                         \
  do {                                                                         \
    auto elferrnonumber = elf_errno();                                         \
    if (cond)                                                                  \
      throw std::runtime_error(                                                \
          fmt::format("Assertion \"{}\" failed at {}:{}, {}", #cond, __LINE__, \
                      __FILE__, m(elf_errmsg(elferrnonumber))));               \
  } while (0)

struct GlobalInitializer {
  static GlobalInitializer &init() {
    static GlobalInitializer initializer = {};
    return initializer;
  }

  Elf *open_elf(int file_desc, bool init) {
    if (init)
      return elf_begin(file_desc, Elf_Cmd::ELF_C_WRITE, nullptr);
    else
      return elf_begin(file_desc, Elf_Cmd::ELF_C_RDWR, nullptr);
  }

private:
  GlobalInitializer() {
    if (elf_version(EV_CURRENT) == EV_NONE)
      errx(EX_SOFTWARE, " ELF library initialization failed : %s ",
           elf_errmsg(-1));
  }
};

ObjectFile::ObjectFile(int file)
    : file_desc(file), elf(GlobalInitializer::init().open_elf(file, false)) {
  if (elf == nullptr)
    throw std::runtime_error(
        fmt::format("elf_begin() error: {}", elf_errmsg(-1)));

  if (kind() != ELF_K_ELF)
    throw std::runtime_error("Expected object file");

  size_t section_max{};
  CHECK(elf_getshdrnum(elf, &section_max));

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

ObjectFile::ObjectFile(int file, std::string_view sh)
    : file_desc(file), elf(GlobalInitializer::init().open_elf(file, true)) {
  CHECK_DECL(auto ehdr = elf32_newehdr(elf), !ehdr);
  ehdr->e_machine = EM_AVR;
  ehdr->e_type = ET_REL;
  ehdr->e_version = EV_CURRENT;
  auto a =
      std::to_array<char>({0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
  std::memcpy(ehdr->e_ident, a.data(), a.size());

  using namespace std::string_literals;
  std::string section_strings = "\0.shstrtab\0"s;
  section_strings.append(sh);
  CHECK_DECL(auto sh_strtab = elf_newscn(elf), !sh_strtab);
  CHECK_DECL(auto str = elf_newdata(sh_strtab), !str);
  ehdr->e_shstrndx = elf_ndxscn(sh_strtab);
  sh_strtab_index = elf_ndxscn(sh_strtab);

  str->d_size = section_strings.size() + 1;
  str->d_buf = malloc(section_strings.size() + 1);
  str->d_version = EV_CURRENT;
  std::memcpy(str->d_buf, section_strings.data(), section_strings.size() + 1);

  CHECK_DECL(auto header = elf32_getshdr(sh_strtab), !header);
  header->sh_name = 1;
  header->sh_type = SHT_STRTAB;
  header->sh_flags = SHF_STRINGS;
  update(elf);
}

ObjectFile::~ObjectFile() {
  elf_end(elf);
  if (file_desc)
    close(file_desc);
}

std::string_view ObjectFile::get_str(uint32_t offset) {
  CHECK_DECL(auto result = elf_strptr(elf, strtab_index, offset), !result);
  return result;
}
namespace {
uint32_t get_offset(std::string_view name, Elf *elf, uint32_t str_index) {
  uint32_t offset = 0;
  Elf_Data *data{};
  do {
    data = elf_getdata(elf_getscn(elf, str_index), data);
    auto n =
        std::string_view(static_cast<const char *>(data->d_buf), data->d_size);
    auto result = n.find(name);
    if (result != static_cast<size_t>(-1)) {
      return offset + result;
    }
    offset += data->d_size;
  } while (data != nullptr);
  return 0;
}
} // namespace
uint32_t ObjectFile::get_section_offset(std::string_view name) {
  size_t sh_index{};
  CHECK(elf_getshdrstrndx(elf, &sh_index));
  return get_offset(name, elf, sh_index);
}

uint32_t ObjectFile::get_str_offset(std::string_view name) {
  return get_offset(name, elf, strtab_index);
}

uint32_t ObjectFile::make_section(Elf32_Shdr header) {
  CHECK_DECL(Elf_Scn *scn = elf_newscn(elf), !scn);
  CHECK_DECL(Elf32_Shdr *h = elf32_getshdr(scn), !h);
  *h = header;
  uint32_t index = elf_ndxscn(scn);
  CHECK(elf_errno());
  return index;
}

uint32_t ObjectFile::find_index(std::string_view name) {
  size_t section_max{};
  CHECK(elf_getshdrnum(elf, &section_max));
  for (size_t i = 1; i != section_max; i++) {
    CHECK_DECL(Elf_Scn *section = elf_getscn(elf, i), !section);
    CHECK_DECL(Elf32_Shdr *header = elf32_getshdr(section), !header);
    CHECK_DECL(auto section_name =
                   elf_strptr(elf, sh_strtab_index, header->sh_name),
               !section_name);
    if (section_name == name)
      return i;
  }
  throw std::out_of_range("Section not found!");
}

Elf_Scn *ObjectFile::find_scn(std::string_view name) {
  auto index = find_index(name);
  CHECK_DECL(auto scn = elf_getscn(elf, index), !scn);
  return scn;
}

tl::generator<Elf_Scn *> ObjectFile::iterate_sections() {
  size_t section_max{};
  CHECK(elf_getshdrnum(elf, &section_max));
  for (size_t i = 1; i != section_max; i++) {
    CHECK_DECL(Elf_Scn *section = elf_getscn(elf, i), !section);
    co_yield section;
  }
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

std::string_view ObjectFile::get_section_name(uint32_t index) {
  CHECK_DECL(auto section = elf_getscn(elf, index), !section);
  CHECK_DECL(auto header = elf32_getshdr(section), !header);
  CHECK_DECL(auto result = elf_strptr(elf, sh_strtab_index, header->sh_name),
             !result);
  return result;
}

uint32_t ObjectFile::get_section_number() {
  size_t section_max{};
  CHECK(elf_getshdrnum(elf, &section_max));
  return section_max;
}

namespace {
struct buffer {
  std::basic_string<uint8_t> b;
};

struct exception_sections {
  Elf_Data *frame_sections;
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
      CHECK_DECL(Elf_Data *data = elf_getdata(section, nullptr), elf_errno());
      result.frame_sections = data;
    } else if (ctre::match<R"(\.rela\.eh_frame.*)">(name)) {
      copy_data(result.frame_relocations);
    } else if (ctre::match<R"(\.gcc_except_table.*)">(name)) {
      copy_data(result.lsda_sections);
    } else if (ctre::match<R"(\.rela\.gcc_except_table.*)">(name)) {
      copy_data(result.lsda_sections);
    }
  }

  if (!result.frame_sections) {
    std::exit(1);
  }

  return result;
}

struct Aug {
  uint8_t fde_aug_encoding{}, personality_encoding = DW_EH_PE_omit,
                              fde_ptr_encoding{};
  dwarf_ptr personality{};
  const uint8_t *begin_instruction{}, *end_instruction{};
};

void parse_cie(Dwarf_CIE const &cie, Dwarf_Off offset,
               std::unordered_map<uint64_t, Aug> &cies) {
  auto ptr = cie.augmentation_data;
  auto aug = std::string_view(cie.augmentation);

  Aug result{};
  result.begin_instruction = cie.initial_instructions;
  result.end_instruction = cie.initial_instructions_end;
  if (aug.find('z') != std::string_view::npos)
    for (auto c : aug) {
      switch (c) {
      case 'z':
        continue;
      case 'L':
        result.fde_aug_encoding = consume<uint8_t>(&ptr);
        break;
      case 'P': {
        auto personality_encoding = consume<uint8_t>(&ptr);
        result.personality_encoding = personality_encoding;
        result.personality = consume_ptr(&ptr, personality_encoding);
      } break;
      case 'R':
        result.fde_ptr_encoding = consume<uint8_t>(&ptr);
        break;
      default:
        throw std::runtime_error("I'm not handling eh");
      }
    }
  cies.insert({offset, std::move(result)});
}

void parse_fde(Dwarf_Off offset, std::unordered_map<uint64_t, Aug> &cies,
               std::vector<frame> &frames, const uint8_t *const segment_begin) {
  frames.push_back({});
  frame &f = frames.back();
  auto ptr = segment_begin + offset;
  uint64_t length = consume<uint32_t>(&ptr);
  if (length == 0xffffffff) {
    length = consume<uint64_t>(&ptr);
  }
  if (length == 0)
    return;
  auto fde_offset = ptr - segment_begin;
  auto cie_offset = fde_offset - consume<uint32_t>(&ptr);
  auto &cie = cies.at(cie_offset);
  f.begin = relocatable_t::make(&ptr, cie.fde_ptr_encoding, segment_begin);
  f.range = relocatable_t::make(&ptr, cie.fde_ptr_encoding, segment_begin);
  if (cie.personality_encoding != DW_EH_PE_omit) {
    std::size_t lsda_len{};
    ptr += bfs::DecodeLeb128(ptr, 4, &lsda_len);
    f.lsda = relocatable_t::make(&ptr, cie.personality_encoding, segment_begin);
  }
  f.frame = parse_cfi({cie.begin_instruction, cie.end_instruction},
                      {ptr, length + fde_offset + segment_begin});
}

std::vector<frame> parse_eh(ObjectFile &o, Elf_Data *eh,
                            std::span<Elf32_Rela> eh_reloc) {
  CHECK_DECL(auto *n = elf32_getehdr(o.elf);, !n);
  CHECK_DECL(auto cfi = dwarf_getcfi_elf(o.elf), !cfi);
  Dwarf_Off offset{};
  Dwarf_CFI_Entry entry{};
  std::unordered_map<uint64_t, Aug> cies;
  std::vector<frame> frames;
  const uint8_t *const segment_begin = static_cast<const uint8_t *>(eh->d_buf);
  while (offset != static_cast<Dwarf_Off>(-1)) {
    if (offset >= eh->d_size)
      break;
    Dwarf_Off next_offset{};
    THROW_IF(dwarf_next_cfi(n->e_ident, eh, true, offset, &next_offset,
                            &entry) == -1);
    if (entry.CIE_id == DW_CIE_ID_64) {
      parse_cie(entry.cie, offset, cies);
    } else {
      parse_fde(offset, cies, frames, segment_begin);
    }
    offset = next_offset;
  }

  for (auto &reloc : eh_reloc) {
    if (relocatable_t::index.contains(reloc.r_offset)) {
      using namespace avr;
      auto &r = relocatable_t::index.at(reloc.r_offset).get();
      r.symbol_index = r_sym(reloc.r_info);
      r.type = r_type(reloc.r_info);
      r.addend = reloc.r_addend;
    }
  }

  return frames;
}

} // namespace

std::vector<frame> parse_object(ObjectFile &o) {
  auto n = get_sections(o);
  return parse_eh(o, n.frame_sections,
                  {reinterpret_cast<Elf32_Rela *>(n.frame_relocations.b.data()),
                   n.frame_relocations.b.size() / sizeof(Elf32_Rela)});
}