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
#include <libelf.h>
#include <numeric>
#include <range/v3/range/conversion.hpp>
#include <ranges>
#include <span>
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

  if (f.frame.cfa_offset == 0 || offsets.empty()) {
    return {f.begin.value(),
            f.range.value(),
            f.lsda.value_or(nullptr),
            f.frame.cfa_register,
            {}};
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

  return {f.begin.value(), f.range.value(), f.lsda.value_or(nullptr),
          f.frame.cfa_register, std::move(entry)};
}

std::pair<size_t, size_t> append_section_names(ObjectFile &o) {
  constexpr char name_data[] = {'.', 'f', 'a', 'e', '_', 'e', 'n', 't',
                                'r', 'i', 'e', 's', 0,   '.', 'f', 'a',
                                'e', '_', 'i', 'n', 'f', 'o', 0};
  auto offset = write_section(o, o.sh_strtab_index, std::span{name_data});
  return {offset, offset + 13};
}

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

size_t create_entries_section(ObjectFile &o, size_t entry_name_offset,
                              std::ranges::range auto entries) {
  auto section = elf_newscn(o.elf);
  auto header = elf32_getshdr(section);
  header->sh_type = SHT_PROGBITS;
  header->sh_flags |= SHF_ALLOC;
  header->sh_name = entry_name_offset;

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
    std::memcpy(ptr, entry.instructions.data(), entry.instructions.size());
    ptr += entry.instructions.size();
  }
  return elf_ndxscn(section);
}

void create_info_section(ObjectFile &o, size_t entry_name_offset,
                         std::ranges::range auto entries) {
  auto section = elf_newscn(o.elf);
  auto header = elf32_getshdr(section);
  header->sh_type = 0x81100000;
  header->sh_name = entry_name_offset;

  auto data = elf_newdata(section);
  data->d_type = ELF_T_BYTE;
  data->d_align = 4;
  data->d_size = sizeof(fae::info) + entries.size() * sizeof(fae::info::entry);
  data->d_buf = std::aligned_alloc(4, data->d_size);
  char *ptr = static_cast<char *>(data->d_buf);
  fae::info info_header{.length = static_cast<uint32_t>(
                            entries.size() * sizeof(fae::info::entry))};
  std::memcpy(ptr, &info_header, sizeof(info_header));
  ptr += sizeof(info_header);

  uint32_t offset{};
  for (auto &&entry : entries) {
    uint32_t off = offset;
    if (entry.instructions.empty()) {
      off = -1;
    }
    fae::info::entry e{.offset = off,
                       .length =
                           static_cast<uint32_t>(entry.instructions.size()),
                       .begin = entry.begin->default_value,
                       .begin_pc_symbol = entry.begin->symbol_index,
                       .range = entry.range->default_value,
                       .range_pc_symbol = entry.range->symbol_index,
                       .cfa_reg = entry.cfa_reg};
    if (entry.lsda) {
      e.lsda_symbol = entry.lsda->symbol_index;
    } else {
      e.lsda_symbol = 0xffffffff;
    }
    std::memcpy(ptr, &e, sizeof(e));
    ptr += sizeof(e);
    offset += static_cast<uint32_t>(entry.instructions.size());
  }
}
} // namespace

void write_fae(ObjectFile &o, std::span<frame> frames,
               std::string_view filename) {
  // todo: determine size of return address via mcu architecture
  // some avrs use sp registers 3 bytes large
  auto entries =
      frames | vs::transform([](auto &f) { return create_entry(f, 2); });

  auto [entries_offset, info_offset] = append_section_names(o);
  auto entries_index = create_entries_section(o, entries_offset, entries);
  create_info_section(o, info_offset, entries);
  create_entry_symbol(o, entries_index, filename);
  create_text_symbol(o, filename);

  elf_update(o.elf, Elf_Cmd::ELF_C_WRITE);
}