#ifndef ELF_STUFF_H
#define ELF_STUFF_H

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

bool valid_elf_magic(Elf64_Ehdr elf_header);
Elf64_Ehdr read_elf_header(int fd);

Elf64_Shdr read_section_header(int fd, Elf64_Ehdr elf_header);
char* get_section_names(int fd, Elf64_Shdr section_header);
unsigned char* read_section_data(int fd, Elf64_Shdr section_header);
void print_section_header(char* section_names, Elf64_Shdr section_header);

bool section_program_and_executable(Elf64_Shdr section_header);
bool section_program_and_writable(Elf64_Shdr section_header);
bool section_program_and_read_only(Elf64_Shdr section_header);

#endif // ELF_STUFF_H