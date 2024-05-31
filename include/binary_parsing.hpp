#pragma once

#include "external/leb128.hpp"
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
  const uint8_t *begin{}, *end{};
  size_t bytes_read = 0;
  Reader(std::span<const uint8_t> buffer_view, size_t pos = 0)
      : begin(buffer_view.data()), end(buffer_view.end().base()),
        bytes_read(pos) {}

  Reader subspan(uint64_t len) {
    return Reader(std::span(begin, len), bytes_read);
  }

  template <trivially_copyable T> T consume() {
    T result = view<T>();
    increment(sizeof(T));
    return result;
  }

  template <trivially_copyable T> T view() {
    T result;
    std::memcpy(&result, begin, sizeof(T));
    return result;
  }

  std::string_view consume_cstr() {
    auto n = std::memchr(begin, '\0', end - begin);
    if (!n)
      throw std::out_of_range("consume_str could not find a null character");
    auto result = std::string_view(reinterpret_cast<const char *>(begin),
                                   static_cast<const uint8_t *>(n) - begin);
    increment(static_cast<const uint8_t *>(n) - begin + 1);
    return result;
  }

  uint64_t consume_uleb() {
    uint64_t result{};
    increment(bfs::DecodeLeb128(begin, 4, &result));
    return result;
  }

  int64_t consume_sleb() {
    int64_t result{};
    increment(bfs::DecodeLeb128(begin, 4, &result));
    return result;
  }

  template <trivially_copyable T> std::vector<T> consume_vec(uint64_t size) {
    std::vector<T> result;
    result.resize(size);
    std::memcpy(result.data(), begin, size * sizeof(T));
    increment(size * sizeof(T));
    return result;
  }

  void increment(uint64_t len) {
    if (len + begin > end)
      throw std::out_of_range("incremented out of range");
    begin += len;
    bytes_read += len;
  }

  bool empty() const noexcept { return begin >= end; }
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