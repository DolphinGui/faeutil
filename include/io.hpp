#pragma once

#include "external/scope_guard.hpp"
#include <cstdio>
#include <fmt/core.h>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

inline auto read_file(std::string_view path) {
  auto f = fopen(path.data(), "rb+");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });

  if (int err = fseek(f, 0, SEEK_END)) {
    throw std::runtime_error(fmt::format("failed to fseek: {}", err));
  }

  std::vector<uint8_t> result;
  result.resize(ftell(f));
  fseek(f, 0, SEEK_SET);
  fread(result.data(), 1, result.size(), f);
  return result;
}

inline void write_file(std::span<uint8_t> buffer, std::string_view output = "a.out") {
  auto f = fopen(output.data(), "wb");
  auto guard = sg::make_scope_guard([&]() { fclose(f); });
  fwrite(buffer.data(), 1, buffer.size_bytes(), f);
}