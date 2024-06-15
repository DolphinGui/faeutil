#include "binary_parsing.hpp"
#include "elf/elf.hpp"
#include "parse.hpp"

#include "consume.hpp"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <fmt/core.h>
#include <fmt/ranges.h>
#include <span>
#include <stdexcept>
#include <string_view>

namespace {
struct cie {
  uint8_t lsda_encoding = DW_EH_PE_omit, personality_encoding = DW_EH_PE_omit,
          ptr_encoding = DW_EH_PE_omit;
  int64_t personality{}, code_align{}, data_align{}, ret_addr_reg{};
  const uint8_t *begin_instruction{}, *end_instruction{};
};

cie parse_cie(Reader data) {
  cie result{};
  auto version = data.consume<uint8_t>();
  assert(version == 1 || version == 3);

  auto aug = data.consume_cstr();
  result.code_align = data.consume_uleb();
  result.data_align = data.consume_sleb();
  if (version == 1) {
    result.ret_addr_reg = data.consume<uint8_t>();
  } else {
    result.ret_addr_reg = data.consume_uleb();
  }

  if (aug.find('z') != std::string_view::npos) {
    uint64_t aug_len = data.consume_uleb();
    auto aug_data = data.consume_vec<uint8_t>(aug_len);
    auto aug_reader = Reader(aug_data);
    for (auto c : aug) {
      switch (c) {
      case 'z':
        continue;
      case 'L':
        result.lsda_encoding = aug_reader.consume<uint8_t>();
        break;
      case 'P': {
        result.personality_encoding = aug_reader.consume<uint8_t>();
        result.personality =
            consume_ptr(aug_reader, result.personality_encoding);
      } break;
      case 'R':
        result.ptr_encoding = aug_reader.consume<uint8_t>();
        break;
      default:
        throw std::runtime_error("I'm not handling eh");
      }
    }
  }
  result.begin_instruction = data.begin;
  result.end_instruction = data.end;
  return result;
}

frame parse_fde(Reader r, cie &cie, uint64_t base_pc) {
  frame f = {};
  f.begin = consume_ptr(r, cie.ptr_encoding, {.pc = base_pc + r.bytes_read});
  f.range = consume_ptr(r, cie.ptr_encoding & 0b0000'1111,
                        {.pc = base_pc + r.bytes_read});
  if (cie.lsda_encoding != DW_EH_PE_omit) {
    uint64_t _ = r.consume_uleb(); // lsda_len
    // we don't actually know the function at this point in
    //  time function base address is added when parsing in personality f.lsda =
    f.lsda = consume_ptr(r, cie.lsda_encoding, {.func = 0});
  }
  f.stack =
      parse_cfi({cie.begin_instruction, cie.end_instruction}, {r.begin, r.end});
  return f;
}

std::vector<frame> parse_eh(std::span<uint8_t> o) {
  elf::file e = elf::parse_buffer(o);
  std::unordered_map<uint64_t, cie> cies;
  std::vector<frame> frames;
  auto section = e.get_section(".eh_frame");
  auto data = Reader(section.data);
  while (!data.empty()) {
    auto pos = data.bytes_read;
    uint64_t length = data.consume<uint32_t>();

    if (length == 0)
      break;
    if (length == 0xffff'ffff) {
      length = data.consume<uint64_t>();
    }
    int32_t cie_ptr = data.consume<int32_t>();
    try {
      // this doesn't actually handle extended length properly, but hopefully
      // nobody actually creates a hideously long CIE
      if (cie_ptr == 0) {
        cies.insert({pos, parse_cie(data.subspan(length - 4))});
      } else {
        auto cie_off = data.bytes_read - cie_ptr - sizeof(cie_ptr);
        frames.push_back(parse_fde(data.subspan(length - 4), cies.at(cie_off),
                                   section.address));
      }
    } catch (std::out_of_range const &e) {
      fmt::println(stderr, "Error while parsing cie: {}", e.what());
    }
    data.increment(length - sizeof(cie_ptr));
  }
  return frames;
}

} // namespace

std::vector<frame> parse_object(std::span<uint8_t> o) { return parse_eh(o); }