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
  auto section = o.find_scn(".fae_data");
  std::vector<info_entry> result;
  result.reserve(get_scn_size(section));
  std::ranges::copy(o.iterate_data<info_entry>(section),
                    std::back_inserter(result));
  return result;
}

} // namespace fae