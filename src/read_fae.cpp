#include "read_fae.hpp"
#include "fae.hpp"
#include "parse.hpp"
#include <cstdlib>
#include <elf.h>
#include <iterator>
#include <libelf.h>
#include <stdexcept>

using namespace std::string_view_literals;

namespace {
auto get_scn(ObjectFile &o, std::string_view name) {
  auto header = elf32_getehdr(o.elf);
  auto max = header->e_shnum;
  for (int i = 1; i != max; i++) {
    auto section = elf_getscn(o.elf, i);
    auto section_header = elf32_getshdr(section);
    if (elf_strptr(o.elf, o.sh_strtab_index, section_header->sh_name) == name) {
      return section;
    }
  }
  throw std::out_of_range(fmt::format("{} not found!", name));
}
} // namespace

namespace fae {
std::vector<info_entry> read_info(ObjectFile &o) {
  auto section = get_scn(o, ".fae_info");
  auto data = elf_getdata(section, nullptr);
  if (!data || elf_errno())
    throw std::runtime_error("no data associated with .fae_info");

  std::vector<info_entry> result;
  while (data != nullptr) {
    result.reserve(data->d_size / sizeof(fae::info_entry) + result.size());
    std::ranges::copy(
        std::span(reinterpret_cast<fae::info_entry *>(data->d_buf),
                  data->d_size / sizeof(fae::info_entry)),
        std::back_inserter(result));
    data = elf_getdata(section, data);
  }

  return result;
}

fae::frame_inst *get_inst(ObjectFile &o) {
  auto section = get_scn(o, ".fae_entries");
  auto data = elf_rawdata(section, nullptr);
  if (!data || !data->d_buf)
    throw std::runtime_error("no data associated with .fae_info");
  return static_cast<fae::frame_inst *>(data->d_buf);
}
} // namespace fae