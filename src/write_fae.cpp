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
  relocatable *begin{}, *range{}, *lsda{};
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

size_t get_scn_size(Elf_Scn *section) {
  Elf_Data *data{};
  size_t total{};
  while (true) {
    data = elf_getdata(section, data);
    if (!data)
      break;
    total += data->d_size;
  }
  return total;
}

template <typename T, size_t alignment = 0, size_t extent>
size_t write_section(ObjectFile &o, size_t index, std::span<const T, extent> input) {
  auto section = elf_getscn(o.elf, index);
  auto offset = get_scn_size(section);
  auto data = elf_newdata(section);
  data->d_size = input.size_bytes();
  data->d_buf = calloc(input.size(), sizeof(T));
  if constexpr (alignment != 0) {
    data->d_align = alignment;
  } else {
    data->d_align = alignof(T);
  }
  data->d_off = offset;
  std::memcpy(data->d_buf, input.data(), input.size_bytes());
  return offset;
}

std::pair<size_t, size_t> append_section_names(ObjectFile &o) {
  constexpr char name_data[] = {'.', 'f', 'a', 'e', '_', 'e', 'n', 't',
                                'r', 'i', 'e', 's', 0,   '.', 'f', 'a',
                                'e', '_', 'i', 'n', 'f', 'o', 0};
  auto offset = write_section(o, o.sh_strtab_index, std::span{name_data});
  return {offset, offset + 13};
}

void create_entry_symbol(ObjectFile &o, size_t entry_section_index) {
  auto str_table = elf_getscn(o.elf, o.strtab_index);
  auto size = get_scn_size(str_table);

  std::string sym_name = o.name;
  sym_name += "_fae_frames";
  write_section(o, o.strtab_index, std::span{sym_name.c_str(), sym_name.size() + 1});

  Elf32_Sym entry_symbol{};
  entry_symbol.st_name = size;
  entry_symbol.st_shndx = entry_section_index;
  entry_symbol.st_value = 0;
  entry_symbol.st_info = ELF32_ST_INFO(STB_GLOBAL, STT_OBJECT);
  // write_section(o, o.symtab_index, std::span{&entry_symbol, 1});
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
    fae::info::entry e{.offset = offset,
                       .length =
                           static_cast<uint32_t>(entry.instructions.size()),
                       .begin_pc_symbol = entry.begin->symbol_index,
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

void write_fae(ObjectFile &o, std::span<frame> frames) {
  // todo: determine size of return address via mcu architecture
  // some avrs use sp registers 3 bytes large
  auto entries =
      frames | vs::transform([](auto &f) { return create_entry(f, 2); });

  auto [entries_offset, info_offset] = append_section_names(o);
  auto entries_index = create_entries_section(o, entries_offset, entries);
  create_info_section(o, info_offset, entries);
  create_entry_symbol(o, entries_index);

  elf_update(o.elf, Elf_Cmd::ELF_C_WRITE);
}