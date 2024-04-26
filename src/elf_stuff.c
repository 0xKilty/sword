#include "elf_stuff.h"

bool valid_elf_magic(Elf64_Ehdr elf_header) {
    return elf_header.e_ident[EI_MAG0] == ELFMAG0 &&
        elf_header.e_ident[EI_MAG1] == ELFMAG1 &&
        elf_header.e_ident[EI_MAG2] == ELFMAG2 &&
        elf_header.e_ident[EI_MAG3] == ELFMAG3;
}

Elf64_Ehdr read_elf_header(int fd) {
    Elf64_Ehdr elf_header;
    size_t bytesRead = read(fd, &elf_header, sizeof(Elf64_Ehdr));
    if (bytesRead != sizeof(Elf64_Ehdr)) {
        perror("read");
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (!valid_elf_magic(elf_header)) {
        fprintf(stderr, "Not an ELF file\n");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return elf_header;
}

Elf64_Shdr read_section_header(int fd, Elf64_Ehdr elf_header) {
    Elf64_Shdr section_header;
    lseek(fd, elf_header.e_shoff + elf_header.e_shstrndx * elf_header.e_shentsize, SEEK_SET);
    read(fd, &section_header, sizeof(section_header));
    return section_header;
}

char* get_section_names(int fd, Elf64_Shdr section_header) {
    char* section_names = malloc(section_header.sh_size);
    lseek(fd, section_header.sh_offset, SEEK_SET);
    read(fd, section_names, section_header.sh_size);
    return section_names;
}

unsigned char* read_section_data(int fd, Elf64_Shdr section_header) {
    unsigned char* section_data = (unsigned char*)malloc(section_header.sh_size);
    if (section_data == NULL) {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);
    }
    lseek(fd, section_header.sh_offset, SEEK_SET);
    read(fd, section_data, section_header.sh_size);

    return section_data;
}

void get_section_flags_string(char* flags_string, Elf64_Shdr section_header) {
    if (section_header.sh_flags & SHF_WRITE)
        flags_string[0] = 'w';
    if (section_header.sh_flags & SHF_ALLOC)
        flags_string[1] = 'a';
    if (section_header.sh_flags & SHF_EXECINSTR)
        flags_string[2] = 'x';
}


void print_section_header(char* section_names, Elf64_Shdr section_header) {
    printf("\n\x1b[1;32m%s\x1b[0m ", section_names + section_header.sh_name);
    char flags_string[4] = "---";
    get_section_flags_string(flags_string, section_header);
    printf("\x1b[1m%s\x1b[0m ", flags_string);
    printf("0x%lx ", (unsigned long)section_header.sh_addr);
    printf("Size: %ld\n\n", (unsigned long)section_header.sh_size);
}

void print_section_raw(Elf64_Shdr section_header, unsigned char* section_data) {
    /*
    for (int i = 0; i < section_header.sh_size; i++) {
        printf("0x%lx: ", (unsigned long)section_header.sh_addr + (i * 8));
        for (int j = 0; j < 8; j++) {
            printf("%02x ", section_data[i * j]);
        }
        printf("\n");
    }
    */
    for (int i = 0; i < section_header.sh_size; i++) {
        printf("%c", section_data[i]);
    }
}

void print_section_data(Elf64_Shdr section_header, unsigned char* section_data) {
    for (int i = 0; i < section_header.sh_size; i += 16) {
        printf("\n0x%08lx: ", (unsigned long)section_header.sh_addr + i);

        for (int j = 0; j < 16 && i + j < section_header.sh_size; j++) {
            printf("%02x ", section_data[i + j]);
        }

        for (int j = 0; j < 16 - (section_header.sh_size - i < 16 ? section_header.sh_size - i : 16); j++) {
            printf("   ");
        }

        printf("|");
        for (int j = 0; j < 16 && i + j < section_header.sh_size; j++) {
            char c = section_data[i + j];
            if (isprint(c)) {
                printf("%c", c);
            } else {
                printf(".");
            }
        }
        printf("|");
    }
    printf("\n");
}

bool section_program_and_executable(Elf64_Shdr section_header) {
    return section_header.sh_type == SHT_PROGBITS && section_header.sh_flags & SHF_EXECINSTR;
}

bool section_program_and_writable(Elf64_Shdr section_header) {
    return section_header.sh_type == SHT_PROGBITS && section_header.sh_flags & SHF_WRITE;
}

bool section_program_and_read_only(Elf64_Shdr section_header) {
    return section_header.sh_type == SHT_PROGBITS && !(section_header.sh_flags & SHF_WRITE);
}