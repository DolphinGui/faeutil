#pragma once

#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

struct callstack {
  std::unordered_map<uint32_t, int64_t> register_offsets;
  int32_t cfa_offset{};
  uint32_t cfa_register;
};

inline bool operator==(callstack const &lhs,
                       callstack const &rhs) noexcept {
  return lhs.register_offsets == rhs.register_offsets &&
         lhs.cfa_register == rhs.cfa_register &&
         lhs.cfa_offset == rhs.cfa_offset;
}

struct frame {
  int64_t begin{}, range{}, lsda{};
  callstack stack;
};

callstack parse_cfi(std::span<const uint8_t> cfi_initial,
                      std::span<const uint8_t> fde_cfi);

std::vector<frame> parse_object(std::span<uint8_t>);

std::vector<uint8_t> write_fae(std::span<frame>);