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
#include <capstone/capstone.h>
#include "elf_stuff.h"
#include "entropy.h"

#define ENTROPY_BUFFER_SIZE 256

const char *program_name;

int open_file(char* filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: Can not open file %s\n", program_name, filename);
        exit(EXIT_FAILURE);
    }
    return fd;
}

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

    int flavor = CS_OPT_SYNTAX_ATT;
    cs_option(capstone_handle, CS_OPT_SYNTAX, flavor);

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

void print_disassembly(int fd, int disassembly_flavor) {
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
        }
        
        free(section_data);
    }
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
    char disassembly_flag = 0;
    int disassembly_flavor = "intel";

    while ((opt = getopt(argc, argv, "lef:dsh")) != -1) {
        switch (opt) {
            case 'l':
                print_logo();
                break;
            case 'e':
                entropy_flag = 1;
                break;
            case 'd':
                disassembly_flag = 1;
                break;
            case 'f':
                if (strcmp(optarg, "intel") != 0) {
                    disassembly_flavor = CS_OPT_SYNTAX_INTEL;
                } else if (strcmp(optarg, "att") != 0) {
                    disassembly_flavor = CS_OPT_SYNTAX_ATT;
                } else {
                    fprintf(stderr, "%s: %s is not a valid disassembly flavor (intel|att)\n", argv[0], optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 's':
                printf("Option 's'\n");
                break;
            case 'h':
            case '?':
                fprintf(stderr, "%s Usage:\n", argv[0]);
                fprintf(stderr, "\t-h Print the help message\n");
                fprintf(stderr, "\t-e Print the file entropy\n");
                fprintf(stderr, "\t-d Print disassembly\n");
                fprintf(stderr, "\t-l Print logo\n");
                fprintf(stderr, "\t-s <section> Print section data\n");
                exit(EXIT_FAILURE);
        }
    }

    program_name = argv[0];
    int fd = open_file(argv[argc - 1]);

    if (disassembly_flag) {
        print_disassembly(fd, disassembly_flavor);
    } 
    
    if (entropy_flag) {
        float entropy = calculate_fd_entropy(fd);
        printf("\nEntropy: %f bits per byte\n", entropy);
    } else if (1 == 2) {
        Elf64_Ehdr elf_header = read_elf_header(fd);
        printf("Entry point address: 0x%lx\n", (unsigned long)elf_header.e_entry);

        Elf64_Shdr section_header = read_section_header(fd, elf_header);
        char* section_names = get_section_names(fd, section_header);
        
        for (int i = 0; i < elf_header.e_shnum; i++) {
            lseek(fd, elf_header.e_shoff + i * sizeof(section_header), SEEK_SET);
            read(fd, &section_header, sizeof(section_header));

            unsigned char* section_data = read_section_data(fd, section_header);
            char* name = section_names + section_header.sh_name;

            if (strcmp(name, ".dynsym") == 0 && 1 == 2) {
                unsigned char* section_data = read_section_data(fd, section_header);

                int num_symbols = section_header.sh_size / sizeof(Elf64_Sym);

                Elf64_Sym* symbols = (Elf64_Sym*)section_data;

                for (int j = 0; j < num_symbols; j++) {
                    printf("Symbol %d:\n", j);
                    printf("Name Offset: 0x%x\n", symbols[j].st_name);
                    printf("Value: 0x%lx\n", symbols[j].st_value);
                    printf("Size: %lu\n", symbols[j].st_size);
                    printf("Binding: %d\n", ELF64_ST_BIND(symbols[j].st_info));
                    printf("Type: %d\n", ELF64_ST_TYPE(symbols[j].st_info));
                    printf("\n");
                }
            } else {
                print_section_header(section_names, section_header);
                print_section_data(section_header, section_data);
            }

            
            free(section_data);
        }

        printf("\n");
        free(section_names);
    }

    close(fd);
    return 0;
}
