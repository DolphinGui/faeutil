#pragma once

#include "fae.hpp"
#include "parse.hpp"
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace fae {

std::vector<info_entry> read_info(ObjectFile &o);
fae::frame_inst *get_inst(ObjectFile &);
} // namespace fae