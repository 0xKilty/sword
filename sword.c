#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

Elf64_Ehdr read_elf_file(int fd) {
    Elf64_Ehdr elf_header;
    ssize_t bytesRead = read(fd, &elf_header, sizeof(Elf64_Ehdr));
    if (bytesRead != sizeof(Elf64_Ehdr)) {
        perror("read");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Check magic
    if (elf_header.e_ident[EI_MAG0] != ELFMAG0 ||
        elf_header.e_ident[EI_MAG1] != ELFMAG1 ||
        elf_header.e_ident[EI_MAG2] != ELFMAG2 ||
        elf_header.e_ident[EI_MAG3] != ELFMAG3) {
        fprintf(stderr, "Not an ELF file\n");
        close(fd);
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
    int fd = open(filename, O_RDONLY);

    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    Elf64_Ehdr elf_header = read_elf_file(fd);

    printf("entry point %lx\n", elf_header.e_entry);

    // Read section header
    Elf64_Shdr section_header;
    lseek(fd, elf_header.e_shoff + elf_header.e_shstrndx * elf_header.e_shentsize, SEEK_SET);
    read(fd, &section_header, sizeof(section_header));

    // Read section names
    char* section_names = malloc(section_header.sh_size);
    lseek(fd, section_header.sh_offset, SEEK_SET);
    read(fd, section_names, section_header.sh_size);
    
    // Print section names
    for (int i = 0; i < elf_header.e_shnum; i++){
        lseek(fd, elf_header.e_shoff + i * sizeof(section_header), SEEK_SET);
        read(fd, &section_header, sizeof(section_header));

        // Check if section is the .text section
        if (section_header.sh_type == SHT_PROGBITS && section_header.sh_flags & SHF_EXECINSTR) {
            printf("%s 0x%lx\n", section_names + section_header.sh_name, (unsigned long)section_header.sh_addr);
            unsigned char* text_section_data = (unsigned char*)malloc(section_header.sh_size);
            if (text_section_data == NULL) {
                perror("Memory allocation error");
                exit(EXIT_FAILURE);
            }
            lseek(fd, section_header.sh_offset, SEEK_SET);
            read(fd, text_section_data, section_header.sh_size);

            free(text_section_data);
        }
    }

    free(section_names);
    close(fd);
    return 0;
}
