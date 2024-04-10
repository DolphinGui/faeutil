#pragma once

#include <cstdint>
#include <libelf.h>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

struct state2 {
  std::string function_name;
  size_t stack_usage{};
  std::unordered_map<int, int> register_offsets;
  uint16_t landing_pad_offset;
};

struct state {
  std::string function_name;
  size_t cfa_offset;
  size_t cfa_register;
  std::unordered_map<size_t, size_t> registers;
  uint8_t personality_encoding;
  std::string personality_section;
  uint8_t lsda_encoding;
  std::string lsda_section;
};

struct buffer {
  std::basic_string<uint8_t> b;
};

struct ObjectFile {
  // takes ownership of file
  ObjectFile(int file_desc);
  ObjectFile(ObjectFile &&o) : file_desc(o.file_desc), elf(o.elf) {
    o.file_desc = 0;
    o.elf = nullptr;
  }
  ObjectFile(ObjectFile const &) = delete;
  ~ObjectFile();

  Elf_Kind kind() const { return elf_kind(elf); }

  int file_desc{};
  Elf *elf{};
  size_t strtab_index{};
  size_t symtab_index{};

  std::string_view get_str(uint32_t offset);
  Elf32_Sym &get_sym(uint32_t index);

private:
  struct GlobalInitializer {
    static GlobalInitializer &init();
    Elf *open_elf(int file_desc);

  private:
    GlobalInitializer();
  };
};

struct unwind_info {
  std::unordered_map<uint32_t, int64_t> register_offsets;
  int32_t cfa_offset{};
};

unwind_info parse_cfi(std::span<const uint8_t> cfi_initial,
                        std::span<const uint8_t> fde_cfi);
void parse_object(ObjectFile &);
