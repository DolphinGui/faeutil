#include "external/ctre/ctre.hpp"
#include "parse.hpp"
#include <fmt/core.h>
#include <fstream>
#include <range/v3/range/conversion.hpp>
#include <ranges>
#include <unordered_map>

namespace {
state parse(std::string_view fun) {
  using namespace std::string_view_literals;
  auto detect_cfi = ctre::multiline_range<R"(\.cfi_(.+))">;
  auto extract_arg = ctre::search<R"((\S+))">;
  auto extract_args = ctre::search<R"((\S+),\s*(\S+))">;

  state result;
  for (auto match : detect_cfi(fun)) {
    auto str = match.get<1>().to_view();
    if (str.starts_with("def_cfa_offset")) {
      auto s = "def_cfa_offset"sv;
      result.cfa_offset = extract_arg(str.substr(s.length())).to_number();
    } else if (str.starts_with("offset")) {
      auto s = "offset"sv;
      auto [_, reg, offset] = extract_args(str.substr(s.length()));
      result.registers[reg.to_number()] = offset.to_number();
    } else if (str.starts_with("def_cfa_register")) {
      auto s = "def_cfa_register"sv;
      result.cfa_register = extract_arg(str.substr(s.length())).to_number();
    } else if (str.starts_with("personality")) {
      auto [_, encoding, section] =
          extract_args(str.substr(("personality"sv).length()));
      result.personality_encoding = encoding.to_number();
      result.personality_section = section;
    } else if (str.starts_with("lsda")) {
      auto [_, encoding, section] =
          extract_args(str.substr(("lsda"sv).length()));
      result.lsda_encoding = encoding.to_number();
      result.lsda_section = section;
    } else if (str.starts_with("startproc") || str.starts_with("endproc")) {
      // does nothing
    } else {
      throw std::runtime_error(
          fmt::format("Unknown cfi directive found: {}", str));
    }
  }

  return result;
}

std::string get_data(std::string_view s) {
  auto f = std::fstream(s.data());
  assert(f.is_open() && f.good());
  return std::string(std::istreambuf_iterator<char>(f),
                     std::istreambuf_iterator<char>());
}
} // namespace

std::vector<state> parse_asm(std::string_view path) {
  std::string assembly = get_data(path);
  std::vector<std::pair<std::string_view, std::string_view>> functions;

  auto find_func = ctre::multiline_range<
      R"(\.type\s+(\S)+, @function(?:\s|\n|\r\n)*((?:.|\n|\r\n)+?\.cfi_endproc))">;

  for (auto match : find_func(assembly)) {
    functions.push_back({match.get<1>().to_view(), match.get<2>().to_view()});
  }
  namespace vs = std::ranges::views;

  return find_func(assembly) | vs::transform([](auto &&match) {
           auto a = parse(match.template get<2>().to_view());
           a.function_name = match.template get<1>().to_string();
           return a;
         }) |
         ranges::to<std::vector>();
}