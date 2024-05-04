
#include "avr_reloc.hpp"
#include "external/ctre/ctre.hpp"
#include "external/generator.hpp"
#include "external/scope_guard.hpp"
#include "fae.hpp"
#include "range/v3/view/concat.hpp"
#include "read_fae.hpp"
#include <algorithm>
#include <cassert>
#include <concat_str.hpp>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <elf.h>
#include <fmt/ranges.h>
#include <iterator>
#include <libelf.h>
#include <limits>
#include <map>
#include <range/v3/range/conversion.hpp>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include "parse.hpp"

namespace {
using fae_map = std::vector<std::vector<fae::frame_inst>>;

struct mapping {
  std::vector<uint16_t> offsets;
  std::vector<fae::frame_inst> data;
};

uint16_t cast16(size_t s) {
  if (s > std::numeric_limits<uint16_t>::max()) {
    throw std::overflow_error("cast16 overflow!");
  }
  return static_cast<uint16_t>(s);
}

fae_map create_map(ObjectFile &obj) {
  std::vector<fae::frame_inst> frame_instructions;
  std::ranges::copy(
      obj.iterate_data<fae::frame_inst>(obj.find_scn(".fae_entries")),
      std::back_inserter(frame_instructions));
  std::span inst = frame_instructions;

  auto infos = obj.iterate_data<fae::info_entry>(obj.find_scn(".fae_info"));
  size_t offset = 0;

  fae_map result;
  for (auto const &info : infos) {
    if (info.offset == 0xffffffff)
      continue;
    auto sub = inst.subspan(offset, info.length / sizeof(fae::frame_inst));
    auto subframe = std::vector<fae::frame_inst>{sub.begin(), sub.end()};
    fmt::println("offset {}, size {}", info.offset, subframe.size());
    result.push_back(std::move(subframe));
    offset += info.length;
  }
  return result;
}

// for now this does a dumb push
mapping relocate(fae_map f) {
  mapping result;
  uint32_t off = 0;
  result.offsets.reserve(f.size());
  // this should really be a cumulative sum but for now I want to print stuff
  for (auto &data : f) {
    fmt::println("{}, {}", off, data.size());
    std::ranges::copy(data, std::back_inserter(result.data));
    result.offsets.push_back(off);
    off += result.data.size() * sizeof(result.data.back());
  }
  return result;
}
using namespace std::string_view_literals;
constexpr auto section_names = ".fae_data\0"sv;

uint32_t make_fae_data_scn(ObjectFile &out) {
  Elf32_Shdr header{};
  header.sh_name = out.get_section_offset(".fae_data");
  header.sh_type = SHT_LOUSER | 0x110000;
  header.sh_addralign = 2;
  header.sh_flags = SHF_ALLOC;
  return out.make_section(header);
}

void write_table(ObjectFile &obj, ObjectFile &out) {
  auto text = obj.find_scn(".text");
  auto map = relocate(create_map(obj));
  auto infos = obj.iterate_data<fae::info_entry>(obj.find_scn(".fae_info")) |
               ranges::to<std::vector>;
  auto offset = get_scn_size(text) + infos.size() * sizeof(fae::table_entry);
  std::ranges::reverse(map.offsets);
  auto n =
      infos | std::views::transform([&](fae::info_entry const &entry) {
        uint16_t off = 0xffff;
        if (entry.offset != 0xffffffff) {
          off = map.offsets.back() + offset;
          fmt::println("total offset: {}, {}", map.offsets.back(), offset);
          map.offsets.pop_back();
        }
        return fae::table_entry{.pc_begin = cast16(entry.begin),
                                .pc_end = cast16(entry.begin + entry.range),
                                .data = off,
                                .length = cast16(entry.length),
                                .lsda = 0};
      }) |
      ranges::to<std::vector>;

  auto fae_data = make_fae_data_scn(out);
  fae::header header{.length = cast16(n.size() * sizeof(fae::table_entry))};
  write_section(out, fae_data, std::array{header});
  write_section(out, fae_data, n);
  write_section(out, fae_data, map.data);
  elf_update(out.elf, ELF_C_WRITE);
}

} // namespace

int main(int argc, char **argv) {
  assert(argc == 2);
  std::vector<std::string> symbol_names;
  assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[1]));
  auto f = fopen(argv[1], "r+");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });
  auto linked = ObjectFile(fileno_unlocked(f));

  auto out_file = fopen("__fae_data.o", "w");
  auto g2 = sg::make_scope_guard([&]() { fclose(out_file); });
  auto data_obj = ObjectFile(fileno_unlocked(out_file), section_names);

  write_table(linked, data_obj);

  elf_update(linked.elf, Elf_Cmd::ELF_C_WRITE);
}