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

/*
TODO (Maybe):
- Add support for portable executables
- Entropy graph
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <capstone/capstone.h>
#include "elf_stuff.h"

void bytes_to_hex_string(char* hex_string, unsigned char* bytes) {
    for (int i = 0; bytes[i] != '\0'; i++)
        sprintf(hex_string + 3 * i, "%02x ", bytes[i]);
}

void print_disassembly_line(cs_insn insn) {
    char hex_string[3 * (sizeof(insn.bytes) / sizeof(insn.bytes[0])) + 1];
    bytes_to_hex_string(hex_string, insn.bytes);
    if (strcmp(insn.mnemonic, "call") == 0) {
        printf("0x%" PRIx64 ": %-20s %s %s -> %s\n", insn.address, hex_string, insn.mnemonic, insn.op_str, insn.op_str);
    } else {
        printf("0x%" PRIx64 ": %-20s %s %s\n", insn.address, hex_string, insn.mnemonic, insn.op_str);
    }
}

void print_section_disassembly(unsigned char* section_data, size_t size, unsigned long addr) {
    csh capstone_handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK) {
        fprintf(stderr, "Error initializing disassembler\n");
        exit(EXIT_FAILURE);
    }

    cs_insn *insn;
    size_t count = cs_disasm(capstone_handle, section_data, size, addr, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++)
           print_disassembly_line(insn[i]);
        cs_free(insn, count);
    } else {
        fprintf(stderr, "Error disassembling code\n");
        exit(EXIT_FAILURE);
    }

    cs_close(&capstone_handle);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "%s: Usage: %s <elf_executable>\n", argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }

    int fd = open(argv[1], O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "%s: Can not open file %s\n", argv[0], argv[1]);
        exit(EXIT_FAILURE);
    }

    Elf64_Ehdr elf_header = read_elf_header(fd);

    printf("Entry point address: 0x%lx\n", (unsigned long)elf_header.e_entry);

    Elf64_Shdr section_header = read_section_header(fd, elf_header);
    char* section_names = get_section_names(fd, section_header);
    
    for (int i = 0; i < elf_header.e_shnum; i++) {
        lseek(fd, elf_header.e_shoff + i * sizeof(section_header), SEEK_SET);
        read(fd, &section_header, sizeof(section_header));
        unsigned char* section_data = read_section_data(fd, section_header);
        
        if (section_program_and_executable(section_header)) {
            print_section_header(section_names, section_header);
            print_section_disassembly(section_data, section_header.sh_size, section_header.sh_addr);
        } else if (section_program_and_read_only(section_header)) {
            print_section_header(section_names, section_header);
            print_section_data(section_header, section_data);
        }
        free(section_data);
    }
    printf("\n");
    free(section_names);
    close(fd);
    return 0;
}
