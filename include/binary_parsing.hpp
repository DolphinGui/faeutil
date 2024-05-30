#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <type_traits>

template <typename T>
concept trivially_copyable = std::is_trivially_copyable_v<T>;

struct Reader {
  uint8_t *begin{}, *end{};
  Reader(std::span<uint8_t> buffer_view)
      : begin(buffer_view.data()), end(buffer_view.end().base()) {}

  template <trivially_copyable T> T consume() {
    if (begin >= end)
      throw std::out_of_range("consuming ptr is out of bounds");
    T result = view<T>();
    begin += sizeof(T);
    return result;
  }

  template <trivially_copyable T> T view() {
    T result;
    std::memcpy(&result, begin, sizeof(T));
    return result;
  }
};