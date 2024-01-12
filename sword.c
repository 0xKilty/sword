#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

Elf32_Ehdr read_elf_file(int file) {
    Elf32_Ehdr elf_header;
    ssize_t bytesRead = read(file, &elf_header, sizeof(Elf32_Ehdr));
    if (bytesRead != sizeof(Elf32_Ehdr)) {
        perror("read");
        close(file);
        exit(EXIT_FAILURE);
    }

    // Check magic
    if (elf_header.e_ident[EI_MAG0] != ELFMAG0 ||
        elf_header.e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header.e_ident[EI_MAG2] != ELFMAG2 ||
        elf_header.e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "Not an ELF file\n");
        close(file);
        exit(EXIT_FAILURE);
    }

    return elf_header;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <elf_executable>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *filename = argv[1];
    int file = open(filename, O_RDONLY);

    if (file < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    //Elf32_Ehdr elf_header = read_elf_file(file);
    Elf32_Ehdr elf_header;
    ssize_t bytesRead = read(file, &elf_header, sizeof(Elf32_Ehdr));
    if (bytesRead != sizeof(Elf32_Ehdr)) {
        perror("read");
        close(file);
        exit(EXIT_FAILURE);
    }

    // Check magic
    if (elf_header.e_ident[EI_MAG0] != ELFMAG0 ||
        elf_header.e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header.e_ident[EI_MAG2] != ELFMAG2 ||
        elf_header.e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "Not an ELF file\n");
        close(file);
        exit(EXIT_FAILURE);
    }

    // Print the values for debugging
    printf("Elf Header Size: %lu\n", sizeof(Elf32_Ehdr));
    printf("e_shoff: %u\n", elf_header.e_shoff);
    printf("e_shnum: %u\n", elf_header.e_shnum);
    printf("e_shentsize: %u\n", elf_header.e_shentsize);

    // Check if e_shnum is non-zero
    if (elf_header.e_shnum == 0) {
        fprintf(stderr, "No sections found\n");
        close(file);
        exit(EXIT_FAILURE);
    }

    // Move to the start of the section headers
    lseek(file, elf_header.e_shoff, SEEK_SET);

    Elf32_Shdr section_header;
    for (int i = 0; i < elf_header.e_shnum; ++i) {
        ssize_t bytesRead = read(file, &section_header, sizeof(Elf32_Shdr));
        if (bytesRead != sizeof(Elf32_Shdr)) {
            perror("read");
            close(file);
            exit(EXIT_FAILURE);
        }

        // Get the name of the section
        char section_name[256]; // Assuming a maximum section name length of 255

        // Use section_header.sh_offset instead of elf_header.e_shoff
        lseek(file, section_header.sh_offset + section_header.sh_name, SEEK_SET);

        bytesRead = read(file, section_name, sizeof(section_name));
        if (bytesRead != sizeof(section_name)) {
            perror("read");
            close(file);
            exit(EXIT_FAILURE);
        }

        // Print the section name
        printf("Section Name: %s\n", section_name);
    }

    close(file);
    return 0;
}
