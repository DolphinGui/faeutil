#pragma once

#include "avr_reloc.hpp"
#include "consume.hpp"

#include <algorithm>
#include <cstdint>
#include <elf.h>
#include <external/generator.hpp>
#include <functional>
#include <libelf.h>
#include <map>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "macros.hpp"

struct ObjectFile {
  // takes ownership of file
  explicit ObjectFile(int file_desc);
  // .shstrtab is always appended to sh_strings
  explicit ObjectFile(int file_desc, std::string_view sh_strings);
  ObjectFile(ObjectFile &&o) : file_desc(o.file_desc), elf(o.elf) {
    o.file_desc = 0;
    o.elf = nullptr;
  }
  ObjectFile(ObjectFile const &) = delete;
  ~ObjectFile();

  Elf_Kind kind() const { return elf_kind(elf); }

  int file_desc{};
  Elf *elf{};
  size_t strtab_index{}, symtab_index{}, sh_strtab_index{};

  std::string_view get_str(uint32_t offset);
  Elf32_Sym &get_sym(uint32_t index);
  std::string_view get_section_name(uint32_t section_index);
  uint32_t get_section_offset(std::string_view name);
  uint32_t get_str_offset(std::string_view name);
  uint32_t make_section(Elf32_Shdr);
  uint32_t get_section_number();

  uint32_t find_index(std::string_view name);
  Elf_Scn *find_scn(std::string_view name);

  tl::generator<Elf_Scn *> iterate_sections();
  struct DataSentinal {};
  template <typename T> struct DataIterator {
    Elf_Data *data{};
    size_t index = 0;
    Elf_Scn *scn{};
    DataIterator(Elf_Data *, Elf_Scn *);
    bool operator==(DataSentinal) const noexcept;
    bool operator==(DataIterator const &) const noexcept;
    DataIterator &operator++();
    DataIterator operator++(int);
    T &operator*();
    T &operator*() const;
    using difference_type = int;
    using value_type = T;
    using reference_type = T &;
    using const_reference_type = T const &;
  };
  template <typename T> struct DataRange {
    Elf_Scn *scn{};
    DataIterator<T> begin();
    DataIterator<const T> cbegin() const;
    DataSentinal end() const { return {}; }
  };
  template <typename T> DataRange<T> iterate_data(uint32_t index) {
    CHECK_DECL(auto scn = elf_getscn(elf, index), !scn);
    return DataRange<T>{scn};
  }
  template <typename T> DataRange<T> iterate_data(Elf_Scn *scn) {
    return DataRange<T>{scn};
  }
};

template <typename T>
inline constexpr bool
    std::ranges::enable_borrowed_range<ObjectFile::DataRange<T>> = true;

inline size_t get_scn_size(Elf_Scn *section) noexcept {
  Elf_Data *data{};
  size_t total{};
  while (true) {
    data = elf_rawdata(section, data);
    if (!data)
      break;
    total += data->d_size;
  }
  return total;
}

template <Elf_Type type = ELF_T_BYTE, std::ranges::sized_range Input,
          size_t alignment = alignof(std::ranges::range_value_t<Input>)>
size_t write_section(Elf_Scn *section, Input input) {
  auto offset = get_scn_size(section);
  auto data = elf_newdata(section);
  data->d_type = type;
  data->d_size = input.size() * sizeof(std::ranges::range_value_t<Input>);
  data->d_buf = calloc(input.size(), sizeof(std::ranges::range_value_t<Input>));
  data->d_align = alignof(std::ranges::range_value_t<Input>);
  data->d_off = offset;
  std::ranges::copy(
      input,
      reinterpret_cast<std::ranges::range_value_t<Input> *>(data->d_buf));
  return offset;
}

template <Elf_Type type = ELF_T_BYTE, std::ranges::sized_range Input,
          size_t alignment = alignof(std::ranges::range_value_t<Input>)>
size_t write_section(ObjectFile &o, size_t index, Input input) {
  return write_section(elf_getscn(o.elf, index), input);
}

struct relocatable_t {
  uint32_t symbol_index{};
  avr::reloc_type type{};
  int64_t default_value{};
  int32_t addend{};
  uint32_t offset{};

  static relocatable_t *make(const uint8_t **ptr, uint8_t encoding,
                             const uint8_t *const begin) {
    auto offset = *ptr - begin;
    // yes this leaks memory
    // no I literally do not care. this program is expected to be very short
    // lived
    auto n = new relocatable_t(consume_ptr(ptr, encoding).val, offset);
    return n;
  }

  static inline std::unordered_map<uint64_t,
                                   std::reference_wrapper<relocatable_t>>
      index{};

private:
  relocatable_t(uint32_t value, uint32_t offset)
      : default_value(value), offset{offset} {
    if (index.contains(offset))
      throw std::runtime_error("relocatable already found!");
    index.insert({offset, std::ref(*this)});
  }
};
using relocatable = std::reference_wrapper<relocatable_t>;

struct unwind_info {
  std::unordered_map<uint32_t, int64_t> register_offsets;
  int32_t cfa_offset{};
  uint32_t cfa_register;
};

inline bool operator==(unwind_info const &lhs,
                       unwind_info const &rhs) noexcept {
  return lhs.register_offsets == rhs.register_offsets &&
         lhs.cfa_register == rhs.cfa_register &&
         lhs.cfa_offset == rhs.cfa_offset;
}

struct frame {
  dwarf_ptr begin{}, range{}, lsda{};
  unwind_info frame;
};

unwind_info parse_cfi(std::span<const uint8_t> cfi_initial,
                      std::span<const uint8_t> fde_cfi);

std::vector<frame> parse_object(ObjectFile &);

void write_fae(ObjectFile &, std::span<frame>);

// template implementations start
template <typename T>
ObjectFile::DataIterator<T>::DataIterator(Elf_Data *data, Elf_Scn *scn)
    : data(data), scn(scn) {}

template <typename T>
bool ObjectFile::DataIterator<T>::operator==(DataSentinal) const noexcept {
  return data == nullptr;
}
template <typename T>
bool ObjectFile::DataIterator<T>::operator==(
    DataIterator const &other) const noexcept {
  return data == other.data && index == other.index;
}
template <typename T>
ObjectFile::DataIterator<T> &ObjectFile::DataIterator<T>::operator++() {
  ++index;
  if (index * sizeof(T) >= data->d_size) {
    data = elf_getdata(scn, data);
    CHECK(elf_errno());
    index = 0;
  }
  return *this;
}
template <typename T>
ObjectFile::DataIterator<T> ObjectFile::DataIterator<T>::operator++(int) {
  auto old = *this;
  this->operator++();
  return old;
}
template <typename T> T &ObjectFile::DataIterator<T>::operator*() {
  if (index * sizeof(T) >= data->d_size)
    throw std::runtime_error("Unexpectedly out of range");
  if (data == nullptr)
    throw std::out_of_range("Dereferenced a null data");
  return reinterpret_cast<T *>(data->d_buf)[index];
}
template <typename T> T &ObjectFile::DataIterator<T>::operator*() const {
  if (index * sizeof(T) >= data->d_size)
    throw std::runtime_error("Unexpectedly out of range");
  if (data == nullptr)
    throw std::out_of_range("Dereferenced a null data");
  return reinterpret_cast<const T *>(data->d_buf)[index];
}
template <typename T>
ObjectFile::DataIterator<T> ObjectFile::DataRange<T>::begin() {
  CHECK_DECL(auto data = elf_getdata(scn, nullptr), !data);
  return DataIterator<T>(data, scn);
}

template <typename T>
ObjectFile::DataIterator<const T> ObjectFile::DataRange<T>::cbegin() const {
  CHECK_DECL(auto data = elf_getdata(scn, nullptr), !data);
  return DataIterator<const T>(data, scn);
}

#include "undef_macros.hpp"