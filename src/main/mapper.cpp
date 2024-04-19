#include "avr_reloc.hpp"
#include "external/ctre/ctre.hpp"
#include "external/scope_guard.hpp"
#include "read_fae.hpp"
#include <algorithm>
#include <cassert>
#include <concat_str.hpp>
#include <cstdio>
#include <libelf.h>
#include <map>
#include <range/v3/range/conversion.hpp>
#include <ranges>
#include <span>
#include <vector>

#include "parse.hpp"

namespace {
size_t get_symbols(ObjectFile &o) {
  Elf_Data *data = elf_getdata(elf_getscn(o.elf, o.symtab_index), nullptr);
  assert(data->d_type == ELF_T_SYM);
  std::vector<Elf32_Sym> result;
  result.reserve(data->d_size / sizeof(Elf32_Sym) + 1);
  auto match_entry = ctre::match<R"(^\.(.+)_fae_frames$)">;
  size_t i = 0;
  while (data != nullptr) {
    auto span = std::span<Elf32_Sym>(static_cast<Elf32_Sym *>(data->d_buf),
                                     data->d_size / sizeof(Elf32_Sym));
    for (auto &s : span) {
      if (match_entry(o.get_str(s.st_name))) {
        return i;
      }
      ++i;
    }
    data = elf_getdata(elf_getscn(o.elf, o.symtab_index), data);
  }
  return 0;
}

struct Range {
  size_t begin{}, end{};
  uint32_t begin_sym{}, end_sym{};
  uint32_t lsda_sym{};
  uint32_t offset{};
  uint32_t length{};
};

using addr_space = std::map<std::string_view, std::vector<Range>>;

void read_file(std::string_view path, addr_space &output) {
  auto f = fopen(path.data(), "r+");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });
  auto o = ObjectFile(fileno_unlocked(f));

  auto &info = fae::read_info(o);
  if (info.length == 0) {
    return;
  }

  auto data = std::span(info.data, info.length / sizeof(info.data[0]));
  for (auto &entry : data) {
    auto begin = o.get_sym(entry.begin_pc_symbol);
    auto range = o.get_sym(entry.range_pc_symbol);
    auto &section = output[o.get_section_name(begin.st_shndx)];
    section.push_back(Range{begin.st_value + entry.begin, range.st_value,
                            entry.begin_pc_symbol, entry.range_pc_symbol,
                            entry.lsda_symbol, entry.offset, entry.length});
  }
}

std::vector<Range> merge_text(addr_space &&s) {
  std::vector<Range> text;
  namespace vs = std::ranges::views;
  addr_space sections = std::move(s);
  size_t size{};
  std::ranges::for_each(sections | vs::values,
                        [&](auto &&n) { size += n.size(); });
  text.reserve(size);
  auto &text_section = sections[".text"];
  text.insert(text.end(), text_section.begin(), text_section.end());
  sections.erase(".text");
  for (auto &&[_, section] : sections) {
    text.insert(text.end(), section.begin(), section.end());
  }
  return text;
}

void relocate_range(std::span<Range> ranges) {
  uint32_t last_end{};
  for (auto &range : ranges) {
    if (range.begin < last_end) {
      range.begin += last_end;
      range.end += last_end;
    }
    last_end = range.end;
  }
}
using namespace std::string_view_literals;
constexpr std::string_view a = ".strtab\0"sv, b = ".symtab\0"sv,
                           c = "fae_table\0"sv;
constexpr auto n = join_v<a, b, c>;
constexpr std::string_view sh_strtab = join_v<a, b, c>;
} // namespace

int main(int argc, char **argv) {
  assert(argc > 1);
  addr_space text_sections;
  for (int i = 1; i != argc; ++i) {
    assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[i]));
    read_file(argv[i], text_sections);
  }

  auto text = merge_text(std::move(text_sections));

  relocate_range(text);

  auto f = fopen("map.o", "w");
  auto output = ObjectFile(fileno_unlocked(f), sh_strtab);
  fmt::println("result: {}", output.get_section_offset("fae_table"));
  elf_update(output.elf, Elf_Cmd::ELF_C_WRITE);
  for (auto &range : text) {
    fmt::println("{}, {}, {}, {}", range.begin, range.end, range.offset,
                 range.length);
  }
}