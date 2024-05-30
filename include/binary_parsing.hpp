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

template <std::invocable<const void *, size_t> Callback> struct Writer {
  Callback callback;
  size_t bytes_written = 0;
  Writer(Callback c) : callback(std::move(c)) {}
  template <trivially_copyable T, size_t extent>
  void write(std::span<T, extent> data) {
    callback(data.data(), data.size_bytes());
    bytes_written += data.size_bytes();
  }
  template <trivially_copyable T> void write(T const &data) {
    callback(&data, sizeof(T));
    bytes_written += sizeof(T);
  }
};

inline auto write_vector(auto &vec) {
  return Writer([&](const void *data, size_t size) {
    auto begin = vec.end().base();
    using T = std::decay_t<decltype(*vec.data())>;
    vec.resize((vec.size() * sizeof(T) + size) / sizeof(T));
    std::memcpy(begin, data, size);
  });
}