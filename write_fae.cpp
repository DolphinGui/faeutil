#include "aef.hpp"
#include "parse.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <functional>
#include <libelf.h>
#include <ranges>
#include <string_view>
#include <vector>

namespace {
std::array<uint8_t, 32> reg_map{2,  3,  4,  5,  6,  7,  8,  9,  10,
                                11, 12, 13, 14, 15, 16, 17, 28, 29};

struct reg_offset {
  uint8_t reg;
  int32_t offset;
};

std::vector<reg_offset> create_entry(frame &f, uint8_t ret_size) {
  std::vector<reg_offset> offsets;
  for (auto &[reg, offset] : f.frame.register_offsets) {
    if (reg < 32) {
      offsets.push_back({static_cast<uint8_t>(reg),
                         -1 * static_cast<int32_t>(offset) - ret_size + 1});
    }
  }
  std::ranges::sort(offsets, {}, [](auto &o) { return o.offset; });
  namespace vs = std::ranges::views;
  fmt::println("usage: {}, offsets: {}", f.frame.cfa_offset,
               offsets | vs::transform([](auto &&a) {
                 return std::pair{a.reg, a.offset};
               }));
  std::vector<fae::frame_inst> entry;
  entry.reserve(f.frame.cfa_offset * -1);
  int32_t sp = f.frame.cfa_offset * -1 - ret_size;
  while (sp > 0) {
    auto &top = offsets.back();
    if (top.offset == sp) {
      entry.push_back(fae::pop(top.reg));
      offsets.pop_back();
      --sp;
    } else {
      entry.push_back(fae::skip(sp - top.offset));
      sp -= sp - top.offset;
    }
  }
  return offsets;
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
  auto sh_str_table = elf_getscn(o.elf, o.strtab_index);
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

Elf_Scn *create_entries_section(ObjectFile &o, size_t entry_name_offset) {
  auto section = elf_newscn(o.elf);
  auto header = elf32_getshdr(section);
  header->sh_type = SHT_PROGBITS;
  header->sh_flags |= SHF_ALLOC;
  header->sh_name = entry_name_offset;

  return section;
}
// void write_entry(std::span<reg_offset> entry, ){}
} // namespace

void write_fae(ObjectFile &o, std::span<frame> frames) {
  // todo: determine size of return address via mcu architecture
  // some avrs use sp registers 3 bytes large
  // auto fae_entries = create_entries_section(o);

  auto str_table = elf_getscn(o.elf, o.sh_strtab_index);
  fmt::println("sh_strtab size: {}", get_scn_size(str_table));
  for (auto &f : frames) {
    create_entry(f, 2);
  }
}