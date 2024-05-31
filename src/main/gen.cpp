#include "elf/elf.hpp"
#include "external/ctre/ctre.hpp"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <fmt/ranges.h>
#include <functional>
#include <libelf.h>
#include <limits>
#include <map>
#include <ranges>
#include <stdexcept>
#include <unordered_map>

#include "fae.hpp"
#include "io.hpp"
#include "parse.hpp"

using unwind_ref = std::reference_wrapper<const callstack>;
template <> struct std::hash<unwind_ref> {
  std::size_t operator()(unwind_ref map) const noexcept {
    size_t hash = 0;
    for (auto &&[k, v] : map.get().register_offsets) {
      // this needs to be commutative since unordered_map is unordered
      hash ^= k + 0x9e3779b9 + (v << 6) + (v >> 2);
    }
    hash = hash + 0x9e3779b9 + (map.get().cfa_offset << 6) +
           (map.get().cfa_offset >> 2);
    hash = hash + 0x9e3779b9 + (map.get().cfa_register << 6) +
           (map.get().cfa_register >> 2);
    return hash;
  }
};

namespace {
using namespace std::string_view_literals;

uint16_t cast16(int64_t i) {
  if (i > std::numeric_limits<uint16_t>::max()) {
    throw std::out_of_range(fmt::format("cast16: {} is out of range", i));
  }
  return static_cast<uint16_t>(i);
}
uint8_t cast8(int64_t i) {
  if (i > std::numeric_limits<uint8_t>::max()) {
    throw std::out_of_range(fmt::format("cast16: {} is out of range", i));
  }
  return static_cast<uint8_t>(i);
}
struct unwind_range {
  uint16_t data;
  uint8_t size;
};

std::vector<fae::frame_inst>
create_data(std::unordered_map<unwind_ref, unwind_range> &out) {
  std::vector<fae::frame_inst> result;
  for (auto &&[unwind, range] : out) {
    range.data = result.size();
    std::map<int64_t, int32_t> offset_to_reg;
    for (auto &&[reg, offset] : unwind.get().register_offsets) {
      if (reg < 32)
        offset_to_reg.insert(
            {offset * -1 - 2 + 1, reg}); // stack grows downwards
    }

    int32_t stack = unwind.get().cfa_offset * -1 - 2;
    while (stack != 0 && !offset_to_reg.empty()) {
      auto [back_off, back_reg] = *offset_to_reg.rbegin();
      if (stack == back_off) {
        result.push_back({fae::enumerate(back_reg)});
        offset_to_reg.erase(back_off);
        stack--;
      } else {
        uint32_t needed_stack = stack - back_off;
        while (needed_stack > 0) {
          uint32_t skipped_stack =
              std::min(needed_stack, fae::skip::max_skip_bytes);
          result.push_back({fae::skip(skipped_stack)});
          needed_stack -= skipped_stack;
        }
        stack -= stack - back_off;
      }
    }
    if (stack != 0) {
      result.push_back({fae::skip(stack)});
    }

    range.size = result.size() - range.data;
  }
  return result;
}

auto to_entry(std::unordered_map<unwind_ref, unwind_range> const &mapping,
              uint32_t data_offset) {

  return std::views::transform([&, data_offset](frame &f) {
    auto range = mapping.at(std::cref(f.stack));
    if (f.stack.cfa_register != 28 && f.stack.cfa_register != 32) {
      throw std::runtime_error("CFA_register is not r28 or r32!");
    }
    return fae::table_entry{.pc_begin = cast16(f.begin),
                            .pc_end = cast16(f.begin + f.range),
                            .data = cast16(range.data + data_offset),
                            .frame_reg = cast8(f.stack.cfa_register),
                            .length = range.size,
                            .lsda = cast16(f.lsda)};
  });
}

elf::file create_obj(elf::u32 flags) {
  elf::file r{.format = elf::e32,
              .endian = elf::little,
              .abi = elf::os_abi::sys_v,
              .abi_version = 0,
              .type = elf::rel,
              .machine = elf::machine_type::avr,
              .entry_point = 0,
              .flags = flags,
              .sh_str_index = 1,
              .program_headers = {}};
  constexpr auto data = "\0.shstrtab\0.fae_data\0"sv;
  elf::section sh_str = {.name = "shstrtab",
                         .type = elf::sh::str_tab,
                         .flags = {},
                         .file_offset = r.header_size(),
                         .data = {data.begin(), data.end()}};
  return r;
}

void create_fae_obj(elf::file &obj, std::span<frame> frames) {
  std::unordered_map<unwind_ref, unwind_range> offset_mapping;
  offset_mapping.reserve(frames.size());
  for (auto &f : frames) {
    offset_mapping.insert({std::cref(f.stack), {}});
  }
  auto unwind_data = create_data(offset_mapping);
  auto text_size = obj.get_section(".text").data.size();
  uint32_t offset = text_size + frames.size() * sizeof(fae::table_entry) +
                    sizeof(fae::header);
  auto entries = frames | to_entry(offset_mapping, offset);

  // auto out_file = fopen("__fae_data.o", "w");
  // auto g = sg::make_scope_guard([&]() { fclose(out_file); });
  // auto out = ObjectFile(fileno_unlocked(out_file), section_names);

  // Elf32_Shdr header{};
  // header.sh_name = out.get_section_offset(".fae_data");
  // header.sh_type = SHT_PROGBITS;
  // header.sh_flags = SHF_ALLOC;
  // header.sh_addr = text_size;

  // auto scn = out.make_section(header);
  // write_section(
  //     out, scn,
  //     std::array{fae::header{
  //         .length = cast16(entries.size() * sizeof(fae::table_entry))}});
  // write_section(out, scn, entries);
  // write_section(out, scn, unwind_data);
  // out.update(true);
}
} // namespace

int main(int argc, char **argv) {
  assert(argc == 2);
  assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[1]));

  auto n = read_file(argv[1]);

  auto frames = parse_object(n);
  // create_fae_obj(o, frames);
}