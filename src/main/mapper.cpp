
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
#include <map>
#include <range/v3/range/conversion.hpp>
#include <ranges>
#include <span>
#include <vector>

#include "macros.hpp"
#include "parse.hpp"

namespace {
struct Range {
  size_t begin{}, end{};
  uint32_t begin_sym{}, end_sym{};
  uint32_t lsda_sym{};
  uint32_t offset{};
  uint32_t length{};
  std::string symbol_name;
};

using addr_space = std::map<std::string_view, std::vector<Range>>;

void read_file(std::string_view path, addr_space &output,
               std::vector<std::string> &out_sections) {
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
    section.push_back(Range{
        begin.st_value + entry.begin, range.st_value, entry.begin_pc_symbol,
        entry.range_pc_symbol, entry.lsda_symbol, entry.offset, entry.length,
        std::string(".").append(path).append(".begin").append(
            o.get_section_name(begin.st_shndx))});
  }

  auto match_text = ctre::match<R"(\.text.*)">;
  uint32_t max = o.get_section_number();
  for (uint32_t i = 1; i != max; ++i) {
    auto n = o.get_section_name(i);
    if (match_text(n)) {
      auto result = std::string{"."};
      out_sections.push_back(result.append(path).append(".begin").append(n));
    }
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
                           c = "fae_table\0"sv, d = ".rela.fae_table\0"sv;
constexpr std::string_view sh_strtab = join_v<a, b, c, d>;

void write_symbols(ObjectFile &output, std::span<std::string> symbol_names) {
  using namespace std::literals;

  auto strings = output.make_section(
      {.sh_name = output.get_section_offset(".strtab"), .sh_type = SHT_STRTAB});
  std::string str_table = "\0"s;
  str_table += symbol_names | std::views::join_with('\0') |
               ranges::to<std::string>() += '\0';
  write_section(output, strings, str_table);
  CHECK(elf_errno());
  auto symbols =
      output.make_section({.sh_name = output.get_section_offset(".symtab"),
                           .sh_type = SHT_SYMTAB,
                           .sh_link = strings,
                           .sh_info = 1});

  std::array<Elf32_Sym, 1> null{};
  auto r =
      symbol_names | std::views::transform([&](std::string &s) {
        return Elf32_Sym{.st_name = static_cast<Elf32_Word>(str_table.find(s)),
                         .st_info = ELF32_ST_INFO(STB_GLOBAL, STT_NOTYPE)};
      });
  write_section(output, symbols, ranges::views::concat(null, r));
}

void write_table(ObjectFile &output, std::span<Range> table) {
  Elf32_Shdr header{.sh_name = output.get_section_offset("fae_table"),
                    .sh_type = SHT_PROGBITS,
                    .sh_flags = SHF_ALLOC | SHF_WRITE};

  auto newscn = output.make_section(header);
  write_section(output, newscn,
                table | std::views::transform([](Range r) {
                  return fae::table_entry{
                      .pc_begin = static_cast<uint16_t>(r.begin),
                      .pc_end = static_cast<uint16_t>(r.end)};
                }));
}

tl::generator<const Elf32_Rela> create(uint32_t offset, Range &range,
                                       std::span<std::string> symbols) {
  auto symbol_index = std::distance(
      symbols.begin(), std::ranges::find(symbols, range.symbol_name));
  fmt::println("index: {}, {}", symbol_index, range.symbol_name);
  co_yield Elf32_Rela{offset, ELF32_R_INFO(symbol_index, avr::R_AVR_DIFF16),
                      static_cast<Elf32_Sword>(range.begin)};
  co_yield Elf32_Rela{offset + 2, ELF32_R_INFO(symbol_index, avr::R_AVR_DIFF16),
                      static_cast<Elf32_Sword>(range.end)};
  // co_yield Elf32_Rela{offset + 4,
  //                     ELF32_R_INFO(range.lsda_sym, avr::R_AVR_DIFF16), 0};
}

void write_relocataions(ObjectFile &output, std::span<Range> relocations,
                        std::span<std::string> symbols) {
  Elf32_Shdr header{.sh_name = static_cast<Elf32_Word>(
                        output.get_section_offset(".rela.fae_table")),
                    .sh_type = SHT_RELA,
                    .sh_flags = SHF_INFO_LINK,
                    .sh_link = output.find_index(".symtab"),
                    .sh_info = output.find_index("fae_table")};
  auto index = output.make_section(header);

  write_section<ELF_T_RELA>(
      elf_getscn(output.elf, index),
      relocations | std::views::enumerate |
          std::views::transform([&](auto &&r) {
            auto &&[index, range] = r;
            return create(index * sizeof(fae::table_entry), range, symbols);
          }) |
          std::views::join,
      symbols.size() * 2);
}

} // namespace

int main(int argc, char **argv) {
  assert(argc > 1);
  addr_space text_sections;
  std::vector<std::string> symbol_names;
  for (int i = 1; i != argc; ++i) {
    assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[i]));
    read_file(argv[i], text_sections, symbol_names);
  }
  auto text = merge_text(std::move(text_sections));
  relocate_range(text);

  auto f = fopen("map.o", "w");
  auto output = ObjectFile(fileno_unlocked(f), sh_strtab);
  write_symbols(output, symbol_names);
  write_table(output, text);
  write_relocataions(output, text, symbol_names);

  elf_update(output.elf, Elf_Cmd::ELF_C_WRITE);
}