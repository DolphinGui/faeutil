#include "read_fae.hpp"
#include "fae.hpp"
#include "parse.hpp"
#include <elf.h>
#include <iterator>
#include <libelf.h>
#include <ranges>
#include <stdexcept>

using namespace std::string_view_literals;

namespace {} // namespace

namespace fae {
std::vector<info_entry> read_info(ObjectFile &o) {
  auto section = o.find_scn(".fae_info");
  std::vector<info_entry> result;
  result.reserve(get_scn_size(section));
  std::ranges::copy(o.iterate_data<info_entry>(section),
                    std::back_inserter(result));
  return result;
}

fae::frame_inst *get_inst(ObjectFile &o) {
  auto section = o.find_scn(".fae_entries");
  auto data = elf_rawdata(section, nullptr);
  if (!data || !data->d_buf)
    throw std::runtime_error("no data associated with .fae_info");
  return static_cast<fae::frame_inst *>(data->d_buf);
}
} // namespace fae