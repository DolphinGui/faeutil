#include "fae.hpp"
#include "parse.hpp"
#include <algorithm>
#include <array>
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

constexpr std::string_view entries_name = ".fae_entries",
                           info_name = ".fae_info";

std::pair<size_t, size_t> append_section_names(ObjectFile &o) {
  auto sh_str_table = elf_getscn(o.elf, o.sh_strtab_index);
  auto size = get_scn_size(sh_str_table);
  auto data = elf_newdata(sh_str_table);
  data->d_buf = malloc(entries_name.size() + info_name.size() + 2);
  data->d_size = entries_name.size() + info_name.size() + 2;
  std::memcpy(data->d_buf, entries_name.data(), entries_name.size() + 1);
  std::memcpy(static_cast<char *>(data->d_buf) + entries_name.size() + 1,
              info_name.data(), info_name.size() + 1);
  data->d_align = 1;
  data->d_off = size;
  return {size, size + entries_name.size() + 1};
}

void create_entries_section(ObjectFile &o, size_t entry_name_offset,
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
  create_entries_section(o, entries_offset, entries);
  create_info_section(o, info_offset, entries);

  elf_update(o.elf, Elf_Cmd::ELF_C_WRITE);
}