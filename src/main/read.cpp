#include "external/ctre/ctre.hpp"
#include "external/scope_guard.hpp"
#include "fae.hpp"
#include "parse.hpp"
#include <cassert>
#include <elf.h>
#include <fmt/ranges.h>
#include <iterator>
#include <libelf.h>
#include <range/v3/range/conversion.hpp>
#include <stdexcept>

namespace {
template <typename Except>
auto catch_val(auto fn, auto &&...args)
    -> std::optional<std::invoke_result_t<decltype(fn), decltype(args)...>> {
  try {
    return fn(args...);
  } catch (Except) {
    return std::nullopt;
  }
}

using namespace std::string_view_literals;
std::tuple<std::vector<fae::table_entry>, std::vector<fae::frame_inst>,
           uint32_t>
read_fae(ObjectFile &o) {
  std::vector<fae::table_entry> table;
  std::vector<fae::frame_inst> data;
  std::vector<uint8_t> raw;

  auto scn = o.find_scn(".fae_data");
  std::ranges::copy(o.iterate_data<uint8_t>(scn), std::back_inserter(raw));
  uint8_t const *ptr = raw.data();
  auto header = reinterpret_cast<fae::header const *>(ptr);
  if (header->header != "avrc++0"sv) {
    throw std::runtime_error(".fae_data header does not match!");
  }
  ptr += sizeof(fae::header);
  table.reserve(header->length / sizeof(fae::table_entry));
  std::ranges::copy(std::span(reinterpret_cast<const fae::table_entry *>(ptr),
                              header->length / sizeof(fae::table_entry)),
                    std::back_inserter(table));

  ptr += header->length;
  auto data_len = (raw.size() - header->length - sizeof(fae::header)) /
                  sizeof(fae::frame_inst);
  data.reserve(data_len);
  std::ranges::copy(
      std::span(reinterpret_cast<const fae::frame_inst *>(ptr),
                reinterpret_cast<const fae::frame_inst *>(raw.end().base())),
      std::back_inserter(data));

  uint32_t offset = 0;
  auto sh_header = elf32_getshdr(scn);
  offset = sh_header->sh_addr + header->length + sizeof(fae::header);
  fmt::println("offset: {:#0x}", offset);

  return {std::move(table), std::move(data), offset};
}
} // namespace

int main(int argc, char **argv) {
  assert(argc == 2);
  assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[1]));

  auto f = fopen(argv[1], "r+");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });
  auto o = ObjectFile(fileno_unlocked(f), false, false);
  auto [table, data, offset] = read_fae(o);
  fmt::println("{} entries", table.size());
  int i = 0;
  for (auto const &frame : table) {
    fmt::println("{}: [{:#0x}, {:#0x}], stack in r{}, lsda: {:#0x}", i++,
                 frame.pc_begin, frame.pc_end, frame.frame_reg, frame.lsda);
    if (frame.length != 0) {
      fmt::println("frame inst [{:#0x}]:", frame.data);
      auto n = std::span(data);
      for (auto inst : n.subspan(frame.data - offset, frame.length)) {
        fmt::println("  {}", fae::format_as(inst));
      }
    }
  }
}