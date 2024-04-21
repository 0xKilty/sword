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
*/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <math.h>
#include <capstone/capstone.h>
#include "elf_stuff.h"

#define ENTROPY_BUFFER_SIZE 256

void bytes_to_hex_string(char* hex_string, unsigned char* bytes) {
    for (int i = 0; bytes[i] != '\0'; i++)
        sprintf(hex_string + 3 * i, "%02x ", bytes[i]);
}

void print_disassembly_line(cs_insn insn, int place) {
    char hex_string[3 * (sizeof(insn.bytes) / sizeof(insn.bytes[0])) + 1];
    bytes_to_hex_string(hex_string, insn.bytes);
    printf("%ld 0x%" PRIx64 ": %-20s %s %s\n", insn.address, insn.address, hex_string, insn.mnemonic, insn.op_str);
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
           print_disassembly_line(insn[i], i);
        cs_free(insn, count);
    } else {
        fprintf(stderr, "Error disassembling code\n");
        exit(EXIT_FAILURE);
    }

    cs_close(&capstone_handle);
}

float calculate_entropy(int* occurrences, int total_count) {
    float entropy = 0;
    for (int i = 0; i < ENTROPY_BUFFER_SIZE; i++) {
        float probability = (float)occurrences[i] / total_count;
        if (probability > 0)
            entropy += probability * log2f(probability);
    }

    return -entropy;
}

float calculate_fd_entropy(int fd) {
    char byte;
    int occurrences[ENTROPY_BUFFER_SIZE] = {0};
    int total_count = 0;
    ssize_t bytesRead;

    lseek(fd, 0, SEEK_SET);
    while ((bytesRead = read(fd, &byte, 1)) > 0) {
        occurrences[(unsigned char)byte]++;
        total_count++;
    }

    return calculate_entropy(occurrences, total_count);
}

void print_logo() {
    const char* figlet = 
        "   ______       ______  ____  ____ \n"
        "  / ___/ |     / / __ \\/ __ \\/ __ \\\n"
        "  \\__ \\| | /| / / / / / /_/ / / / /\n"
        " ___/ /| |/ |/ / /_/ / _, _/ /_/ / \n"
        "/____/ |__/|__/\\____/_/ |_/_____/  \n";
    printf("%s\n", figlet);
}

extern char *optarg;

int main(int argc, char *argv[]) {
    int opt;
    char entropy_flag = 0;

    while ((opt = getopt(argc, argv, "lse")) != -1) {
        switch (opt) {
            case 'l':
                print_logo();
                break;
            case 'e':
                entropy_flag = 1;
                break;
            case 's':
                printf("Option 's'\n");
                break;
            case '?':
                fprintf(stderr, "Usage: %s -a <value> -b <value>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    /*
    if (argc != 2) {
        fprintf(stderr, "%s: Usage: %s <elf_executable>\n", argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }
    */

    int fd = open(argv[argc - 1], O_RDONLY);

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
        print_section_header(section_names, section_header);

        if (section_program_and_executable(section_header)) {
            print_section_disassembly(section_data, section_header.sh_size, section_header.sh_addr);
        } else if (section_program_and_read_only(section_header)) {
            print_section_data(section_header, section_data);
        } else {
            print_section_data(section_header, section_data);
        }
        free(section_data);
    }
    printf("\n");
    free(section_names);

    if (entropy_flag) {
        float entropy = calculate_fd_entropy(fd);
        printf("\nEntropy: %f bits per byte\n", entropy);
    }

    close(fd);
    return 0;
}
