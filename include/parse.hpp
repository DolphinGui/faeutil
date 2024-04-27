#pragma once

#include "avr_reloc.hpp"
#include "consume.hpp"
#include "subprojects/range-v3-0.12.0/test/test_iterators.hpp"

#include <algorithm>
#include <concepts>
#include <cstdint>
#include <elf.h>
#include <external/generator.hpp>
#include <functional>
#include <libelf.h>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <vector>

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
  uint32_t find_index(std::string_view name);
  uint32_t make_section(Elf32_Shdr);
  uint32_t get_section_number();
  tl::generator<Elf_Scn *> iterate_sections();
};

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

template <Elf_Type type = ELF_T_BYTE, std::ranges::range Input,
          size_t alignment = alignof(std::ranges::range_value_t<Input>)>
size_t write_section(Elf_Scn *section, Input input, size_t length) {
  auto offset = get_scn_size(section);
  auto data = elf_newdata(section);
  data->d_type = type;
  data->d_size = length * sizeof(std::ranges::range_value_t<Input>);
  data->d_buf = calloc(length, sizeof(std::ranges::range_value_t<Input>));
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
  auto section = elf_getscn(o.elf, index);
  return write_section<type, Input, alignment>(section, input, input.size());
}

template <typename T, size_t alignment = alignof(T)>
size_t write_section(ObjectFile &o, size_t index,
                     std::regular_invocable auto copy, size_t bytes) {
  auto section = elf_getscn(o.elf, index);
  auto offset = get_scn_size(section);
  auto data = elf_newdata(section);
  data->d_size = bytes;
  data->d_buf = calloc(data->d_size, sizeof(T));
  data->d_align = alignment;
  data->d_off = offset;
  copy(data->d_buf);
  return offset;
}

struct relocatable_t {
  uint32_t symbol_index{};
  avr::reloc_type type{};
  uint32_t default_value{};
  int32_t addend{};
  uint32_t offset{};

  static relocatable_t *make(const uint8_t **ptr, uint8_t encoding,
                             const uint8_t *const begin) {
    auto offset = *ptr - begin;
    // yes this leaks memory
    // no I literally do not care. this program is expected to be very short
    // lived
    return new relocatable_t(consume_ptr(ptr, encoding).val, offset);
  }

  static std::reference_wrapper<relocatable_t>
  make(uint32_t symbol, uint32_t value, uint32_t offset, avr::reloc_type type) {
    auto result = std::ref(*(new relocatable_t(value, offset)));
    result.get().symbol_index = symbol;
    result.get().type = type;
    result.get().offset = offset;
    return result;
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

struct frame {
  std::optional<relocatable_t *> begin, range, lsda;
  unwind_info frame;
};

unwind_info parse_cfi(std::span<const uint8_t> cfi_initial,
                      std::span<const uint8_t> fde_cfi);

std::vector<frame> parse_object(ObjectFile &);

void write_fae(ObjectFile &, std::span<frame>, std::string_view filename);
