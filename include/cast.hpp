#pragma once

#include <concepts>
#include <exception>
#include <fmt/format.h>
#include <limits>
#include <type_traits>

template <std::integral To, std::integral From>
inline constexpr To cast(From i)
  requires(!std::is_same_v<To, From>)
{
  if (i < std::numeric_limits<To>::min() ||
      i > std::numeric_limits<To>::max()) {
    throw std::runtime_error(
        fmt::format("Cast from integral of size {} to {} failed", sizeof(From),
                    sizeof(To)));
  }
  return static_cast<To>(i);
}

template <typename Id> inline constexpr Id cast(Id i) { return i; }
