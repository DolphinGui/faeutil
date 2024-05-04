#pragma once

#include "fae.hpp"
#include "parse.hpp"
#include <vector>

namespace fae {

std::vector<info_entry> read_info(ObjectFile &o);
inline auto get_inst(ObjectFile &o) {
  auto section = o.find_scn(".fae_entries");
  return o.iterate_data<fae::frame_inst>(section);
}
} // namespace fae