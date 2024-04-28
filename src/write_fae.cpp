#include "avr_reloc.hpp"
#include "concat_str.hpp"
#include "external/ctre/ctre.hpp"
#include "fae.hpp"
#include "parse.hpp"
#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <iterator>
#include <libelf.h>
#include <numeric>
#include <range/v3/range/conversion.hpp>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace {
namespace vs = std::ranges::views;

struct reg_offset {
  uint8_t reg;
  int32_t offset;
};

struct entry_info {
  relocatable_t *begin{}, *range{}, *lsda{};
  uint32_t cfa_reg;
  std::vector<fae::frame_inst> instructions;
};

entry_info create_entry(frame &f, uint8_t ret_size) {
  std::vector<reg_offset> offsets;
  for (auto &[reg, offset] : f.frame.register_offsets) {
    if (reg < 32) {
      offsets.push_back({static_cast<uint8_t>(reg),
                         -1 * static_cast<int32_t>(offset) - ret_size + 1});
    }
  }

  if (!f.begin || !f.range) {
    throw std::runtime_error("failed to parse begin or range!");
  }

  if (f.frame.cfa_offset == 0 || offsets.empty()) {
    return {f.begin, f.range, f.lsda, f.frame.cfa_register, {}};
  }

  std::ranges::sort(offsets, {}, [](auto &o) { return o.offset; });
  std::vector<fae::frame_inst> entry;
  int32_t sp = f.frame.cfa_offset * -1 - ret_size;
  entry.reserve(sp);
  while (sp > 0) {
    auto &top = offsets.back();
    if (top.offset == sp) {
      entry.push_back(fae::pop(fae::enumerate(top.reg)));
      offsets.pop_back();
      --sp;
    } else {
      entry.push_back(fae::skip(sp - top.offset));
      sp -= sp - top.offset;
    }
  }

  entry.push_back(fae::skip(0));
  // enforce alignment
  if (entry.size() % 2 != 0) {
    entry.push_back(fae::skip(0));
  }

  return {f.begin, f.range, f.lsda, f.frame.cfa_register, std::move(entry)};
}
using namespace std::string_view_literals;
constexpr auto a = ".fae_entries\0"sv, b = ".fae_info\0"sv,
               c = ".rela.fae_info\0"sv;
constexpr auto section_names = join_v<a, b, c>;

void create_entry_symbol(ObjectFile &o, size_t entry_section_index,
                         std::string_view filename) {
  auto str_table = elf_getscn(o.elf, o.strtab_index);
  auto size = get_scn_size(str_table);

  std::string sym_name = '.' + std::string(filename) + "_fae_frames";
  write_section(o, o.strtab_index,
                std::span{sym_name.c_str(), sym_name.size() + 1});

  Elf32_Sym entry_symbol{};
  entry_symbol.st_name = size;
  entry_symbol.st_shndx = entry_section_index;
  entry_symbol.st_value = 0;
  entry_symbol.st_info = ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT);
  write_section(o, o.symtab_index,
                std::span<const Elf32_Sym, 1>{{entry_symbol}});
}

void create_text_symbol(ObjectFile &o, std::string_view filename) {
  elf_update(o.elf, ELF_C_NULL);
  auto max = o.get_section_number();
  auto is_text = ctre::match<R"(\.text.*)">;
  for (size_t index = 1; index != max; index++) {
    auto n = o.get_section_name(index);
    if (is_text(n)) {
      std::string sym_name = ('.' + std::string(filename) + ".begin")
                                 .append(o.get_section_name(index));
      write_section(o, o.strtab_index,
                    std::span{sym_name.c_str(), sym_name.size() + 1});
      elf_update(o.elf, ELF_C_NULL);

      Elf32_Sym entry_symbol{};
      entry_symbol.st_name = o.get_str_offset(sym_name);
      entry_symbol.st_shndx = index;
      entry_symbol.st_value = 0;
      entry_symbol.st_info = ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE);
      write_section(o, o.symtab_index,
                    std::span<const Elf32_Sym>{{entry_symbol}});
    }
  }
}

size_t create_entries_section(ObjectFile &o, size_t name_offset,
                              std::ranges::range auto entries) {
  auto section = elf_newscn(o.elf);
  auto header = elf32_getshdr(section);
  header->sh_type = SHT_PROGBITS;
  header->sh_flags |= SHF_ALLOC;
  header->sh_name = name_offset + section_names.find(".fae_entries");

  auto sizes =
      entries | vs::transform([](auto &&e) { return e.instructions.size(); });
  auto total_size = std::reduce(sizes.begin(), sizes.end());

  auto data = elf_newdata(section);
  data->d_type = ELF_T_BYTE;
  data->d_align = 2;
  data->d_size = total_size;
  data->d_buf = std::aligned_alloc(2, data->d_size);
  auto ptr = static_cast<uint8_t *>(data->d_buf);
  for (auto &&entry : entries) {
    if (!entry.instructions.empty())
      std::memcpy(ptr, entry.instructions.data(), entry.instructions.size());
    ptr += entry.instructions.size();
  }
  return elf_ndxscn(section);
}

uint32_t create_info_section(ObjectFile &o, size_t name_offset,
                             std::ranges::sized_range auto entries) {
  auto section = elf_newscn(o.elf);
  auto header = elf32_getshdr(section);
  header->sh_type = 0x81100000;
  header->sh_name = name_offset + section_names.find(".fae_info");
  header->sh_flags = SHF_GNU_RETAIN;

  fae::info info_header{.length = static_cast<uint32_t>(
                            entries.size() * sizeof(fae::info::entry))};
  write_section(section, std::array{info_header});
  uint32_t offset = 0;
  write_section(
      section,
      entries | vs::transform([&](entry_info &&entry) {
        fae::info::entry e{
            .offset = entry.instructions.empty() ? -1 : offset,
            .length = static_cast<uint32_t>(entry.instructions.size()),
            .begin = entry.begin->default_value,
            .begin_pc_symbol = entry.begin->symbol_index,
            .range = entry.range->default_value,
            .range_pc_symbol = entry.range->default_value,
            .lsda_symbol = !entry.lsda ? 0xffffffff : entry.lsda->symbol_index,
            .cfa_reg = entry.cfa_reg};
        offset += static_cast<uint32_t>(entry.instructions.size());
        return e;
      }));
  return elf_ndxscn(section);
}

tl::generator<const Elf32_Rela> generate_rela(uint32_t offset,
                                              entry_info info) {
  fmt::println("symbol {}, {}", info.begin->symbol_index,
               info.range->symbol_index);
  co_yield Elf32_Rela{
      static_cast<Elf32_Addr>(offset + offsetof(fae::info::entry, begin)),
      ELF32_R_INFO(info.begin->symbol_index, avr::R_AVR_32), 0};
  co_yield Elf32_Rela{
      static_cast<Elf32_Addr>(offset + offsetof(fae::info::entry, range)),
      ELF32_R_INFO(info.range->symbol_index, avr::R_AVR_DIFF32), 0};
}

void create_rela(ObjectFile &o, size_t name_offset, uint32_t info_index,
                 std::ranges::sized_range auto entries) {
  Elf32_Shdr header{};
  header.sh_type = SHT_RELA;
  header.sh_name = name_offset + section_names.find(".rela.fae_info");
  header.sh_flags = SHF_INFO_LINK;
  header.sh_link = o.find_index(".symtab");
  header.sh_info = info_index;
  auto section = o.make_section(header);

  auto n = entries | std::views::enumerate |
           std::views::transform([&](auto &&pair) {
             auto &&[index, info] = pair;
             return generate_rela(
                 index * sizeof(fae::info::entry) + sizeof(fae::info), info);
           }) |
           std::views::join;

  std::vector<Elf32_Rela> relocations;
  relocations.reserve(entries.size() * 2);
  std::ranges::copy(n, std::back_inserter(relocations));
  for (auto &r : relocations) {
    fmt::println("symbol: {}", ELF32_R_SYM(r.r_info));
  }
  write_section(o, section, relocations);
}
} // namespace

void write_fae(ObjectFile &o, std::span<frame> frames,
               std::string_view filename) {
  // todo: determine size of return address via mcu architecture
  // some avrs use sp registers 3 bytes large
  auto entries =
      frames | vs::transform([](auto &f) { return create_entry(f, 2); });

  auto offset = write_section(o, o.sh_strtab_index, section_names);
  auto entries_index = create_entries_section(o, offset, entries);
  auto info = create_info_section(o, offset, entries);
  create_entry_symbol(o, entries_index, filename);
  create_text_symbol(o, filename);
  create_rela(o, offset, info, entries);

  elf_update(o.elf, Elf_Cmd::ELF_C_WRITE);
}