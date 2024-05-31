#include "elf/elf.hpp"
#include "external/ctre/ctre.hpp"
#include "fae.hpp"
#include "io.hpp"
#include <cassert>
#include <elf.h>
#include <fmt/ranges.h>
#include <iterator>
#include <libelf.h>
#include <stdexcept>

namespace {
using namespace std::string_view_literals;
std::tuple<std::vector<fae::table_entry>, std::vector<fae::frame_inst>,
           uint32_t>
read_fae(elf::file &o) {
  std::vector<fae::table_entry> table;
  std::vector<fae::frame_inst> data;

  auto scn = o.get_section(".fae_data");
  uint8_t const *ptr = scn.data.data();
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
  auto data_len = (scn.data.size() - header->length - sizeof(fae::header)) /
                  sizeof(fae::frame_inst);
  data.reserve(data_len);
  std::ranges::copy(std::span(reinterpret_cast<const fae::frame_inst *>(ptr),
                              reinterpret_cast<const fae::frame_inst *>(
                                  scn.data.end().base())),
                    std::back_inserter(data));

  uint32_t offset = scn.address + header->length + sizeof(fae::header);
  fmt::println("offset: {:#0x}", offset);

  return {std::move(table), std::move(data), offset};
}
} // namespace

int main(int argc, char **argv) {
  assert(argc == 2);
  assert(ctre::match<R"(.+(:?\.o|\.elf))">(argv[1]));

  auto f = read_file(argv[1]);
  auto elf = elf::parse_buffer(f);

  auto [table, data, offset] = read_fae(elf);
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