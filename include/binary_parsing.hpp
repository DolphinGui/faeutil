#pragma once

#include <concepts>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <type_traits>
#include <vector>

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

template <std::invocable<void *, size_t> Callback> struct Writer {
  Callback callback;
  Writer(Callback c) : callback(std::move(c)) {}
  template <trivially_copyable T, size_t extent>
  void write(std::span<T, extent> data) {
    callback(data.data(), data.size_bytes());
  }
};

inline auto write_vector(std::vector<uint8_t> &vec) {
  return Writer([&](void *data, size_t size) {
    auto begin = vec.end().base();
    vec.resize(vec.size() + size);
    std::memcpy(begin, data, size);
  });
}