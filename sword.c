/*
                                ,-.
                               ("O_)
                              / `-/
                             /-. /
                            /   )
                           /   /  
              _           /-. /
             (_)"-._     /   )
               "-._ "-'""( )/    
                   "-/"-._" `. 
                    /     "-.'._
                   /\       /-._"-._
    _,---...__    /  ) _,-"/    "-(_)
___<__(|) _   ""-/  / /   /
 '  `----' ""-.   \/ /   /
               )  ] /   /
       ____..-'   //   /                       )
   ,-""      __.,'/   /   ___                 /,
  /    ,--""/  / /   /,-""   """-.          ,'/
 [    (    /  / /   /  ,.---,_   `._   _,-','
  \    `-./  / /   /  /       `-._  """ ,-'
   `-._  /  / /   /_,'            ""--"
       "/  / /   /"         
       /  / /   /
      /  / /   /
     /  |,'   /  
    :   /    /
    [  /   ,'
    | /  ,'
    |/,-'
    P'
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <capstone/capstone.h>

bool valid_elf_magic(Elf64_Ehdr elf_header) {
    return elf_header.e_ident[EI_MAG0] == ELFMAG0 &&
        elf_header.e_ident[EI_MAG1] == ELFMAG1 &&
        elf_header.e_ident[EI_MAG2] == ELFMAG2 &&
        elf_header.e_ident[EI_MAG3] == ELFMAG3;
}

Elf64_Ehdr read_elf_header(int fd) {
    Elf64_Ehdr elf_header;
    ssize_t bytesRead = read(fd, &elf_header, sizeof(Elf64_Ehdr));
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

bool section_program_and_executable(Elf64_Shdr section_header) {
    return section_header.sh_type == SHT_PROGBITS && section_header.sh_flags & SHF_EXECINSTR;
}

bool section_program_and_writable(Elf64_Shdr section_header) {
    return section_header.sh_type == SHT_PROGBITS && section_header.sh_flags & SHF_WRITE;
}

bool section_program_and_read_only(Elf64_Shdr section_header) {
    return section_header.sh_type == SHT_PROGBITS && !(section_header.sh_flags & SHF_WRITE);
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

void print_disassembly(unsigned char* section_data, size_t size, unsigned long addr) {
    csh capstone_handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK) {
        fprintf(stderr, "Error initializing disassembler\n");
        exit(EXIT_FAILURE);
    }

    cs_insn *insn;
    size_t count = cs_disasm(capstone_handle, section_data, size, addr, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            printf("0x%" PRIx64 ": %s %s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        fprintf(stderr, "Error disassembling code\n");
        exit(EXIT_FAILURE);
    }

    cs_close(&capstone_handle);
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

    Elf64_Ehdr elf_header = read_elf_header(fd);
    Elf64_Shdr section_header = read_section_header(fd, elf_header);
    char* section_names = get_section_names(fd, section_header);
    
    for (int i = 0; i < elf_header.e_shnum; i++){
        lseek(fd, elf_header.e_shoff + i * sizeof(section_header), SEEK_SET);
        read(fd, &section_header, sizeof(section_header));

        unsigned char* section_data = read_section_data(fd, section_header);
        if (section_header.sh_type == SHT_PROGBITS && (section_header.sh_flags & SHF_EXECINSTR || !(section_header.sh_flags & SHF_WRITE))) {
            printf("\n%s 0x%lx\n\n", section_names + section_header.sh_name, (unsigned long)section_header.sh_addr);
        }
        if (section_program_and_executable(section_header)) {
            print_disassembly(section_data, section_header.sh_size, section_header.sh_addr);
        } else if (section_program_and_read_only(section_header)) {
            for (int j = 0; j < section_header.sh_size; j++) {
                printf("%c", section_data[j]);
            }
        }
        free(section_data);
    }
    printf("\n");
    free(section_names);
    close(fd);
    return 0;
}
