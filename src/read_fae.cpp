#include "fae.hpp"
#include "parse.hpp"
#include <elf.h>
#include <libelf.h>
#include <stdexcept>

using namespace std::string_view_literals;

namespace {
auto get_scn(ObjectFile &o, std::string_view name) {
  auto header = elf32_getehdr(o.elf);
  auto max = header->e_shnum;
  Elf_Scn *section{};
  for (int i = 0; i != max; i++) {
    section = elf_getscn(o.elf, i);
    auto section_header = elf32_getshdr(section);
    if (elf_strptr(o.elf, o.sh_strtab_index, section_header->sh_name) == name) {
      break;
    }
  }
  if (!section)
    throw std::runtime_error(fmt::format("{} not found!", name));
  return section;
}
} // namespace

namespace fae {
fae::info &read_info(ObjectFile &o) {
  auto section = get_scn(o, ".fae_info");
  auto data = elf_getdata(section, nullptr);
  if (!data)
    throw std::runtime_error("no data associated with .fae_info");
  fae::info &info = *static_cast<fae::info *>(data->d_buf);
  if (info.version != 0)
    throw std::runtime_error(".fae_info version mismatch!");
  return info;
}

fae::frame_inst *get_inst(ObjectFile &o) {
  auto section = get_scn(o, ".fae_entries");
  auto data = elf_rawdata(section, nullptr);
  if (!data || !data->d_buf)
    throw std::runtime_error("no data associated with .fae_info");
  return static_cast<fae::frame_inst *>(data->d_buf);
}
} // namespace fae