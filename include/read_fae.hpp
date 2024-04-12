#pragma once

#include "fae.hpp"
#include "parse.hpp"
#include <cstdint>
#include <span>
#include <vector>

namespace fae {
fae::info &read_info(ObjectFile &o);
fae::frame_inst* get_inst(ObjectFile&);
}