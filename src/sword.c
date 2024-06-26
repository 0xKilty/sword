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
- Make a file compressor in here

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
#include "user_interaction.h"
#include "compression.h"

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
    printf("%ld 0x%" PRIx64 ": %-20s", insn.address, insn.address, hex_string);
    printf("%s %s\n", insn.mnemonic, insn.op_str);
}

void print_section_disassembly(unsigned char* section_data, size_t size, unsigned long addr, int flavor) {
    csh capstone_handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK) {
        fprintf(stderr, "Error initializing disassembler\n");
        exit(EXIT_FAILURE);
    }

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

struct dynamic_data {
    char* dynstr_data;
    Elf64_Shdr dynsym_header;
    Elf64_Sym* dynsym_symbols;
    int num_dynsym_symbols;
};

struct dynamic_data *get_dynamic_data(int fd, Elf64_Ehdr elf_header, Elf64_Shdr section_header, char* section_names) {
    struct dynamic_data *dyn_data = malloc(sizeof(struct dynamic_data));
    for (int i = 0; i < elf_header.e_shnum; i++) {
        lseek(fd, elf_header.e_shoff + i * sizeof(section_header), SEEK_SET);
        read(fd, &section_header, sizeof(section_header));
        unsigned char* section_data = read_section_data(fd, section_header);

        if (strcmp(&section_names[section_header.sh_name], ".dynstr") == 0) {
            dyn_data->dynstr_data = malloc(section_header.sh_size);
            memcpy(dyn_data->dynstr_data, section_data, section_header.sh_size);
        } else if (strcmp(&section_names[section_header.sh_name], ".dynsym") == 0) {
            dyn_data->dynsym_header = section_header;
            dyn_data->num_dynsym_symbols = section_header.sh_size / sizeof(Elf64_Sym);
            dyn_data->dynsym_symbols = malloc(section_header.sh_size);
            memcpy(dyn_data->dynsym_symbols, section_data, section_header.sh_size);
        }
        
        free(section_data);
    }
    return dyn_data;
}

void print_dynamic_data(struct dynamic_data *dyn_data) {
    for (int j = 0; j < dyn_data->num_dynsym_symbols; j++) {
        printf("Symbol %d:\n", j);
        printf("Name: %s\n", dyn_data->dynstr_data + dyn_data->dynsym_symbols[j].st_name);
        printf("Value: 0x%lx = %ld\n", dyn_data->dynsym_symbols[j].st_value, dyn_data->dynsym_symbols[j].st_value);
        printf("Size: %lu\n",  dyn_data->dynsym_symbols[j].st_size);
        printf("Binding: %d\n", ELF64_ST_BIND(dyn_data->dynsym_symbols[j].st_info));
        printf("Type: %d\n", ELF64_ST_TYPE(dyn_data->dynsym_symbols[j].st_info));
        printf("\n");
    }
}

void print_disassembly(int fd, int disassembly_flavor) {
    Elf64_Ehdr elf_header = read_elf_header(fd);
    printf("Entry point address: 0x%lx\n", (unsigned long)elf_header.e_entry);
    Elf64_Shdr section_header = read_section_header(fd, elf_header);
    char* section_names = get_section_names(fd, section_header);

    struct dynamic_data *dyn_data = get_dynamic_data(fd, elf_header, section_header, section_names);
    if (dyn_data->dynsym_symbols != NULL && dyn_data->dynstr_data != NULL) {
        printf(".dynsym Data:\n");
        print_dynamic_data(dyn_data);
    }

    csh capstone_handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handle) != CS_ERR_OK) {
        fprintf(stderr, "Error initializing disassembler\n");
        exit(EXIT_FAILURE);
    }

    cs_option(capstone_handle, CS_OPT_SYNTAX, disassembly_flavor);
    cs_option(capstone_handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn;
    
    for (int i = 0; i < elf_header.e_shnum; i++) {
        lseek(fd, elf_header.e_shoff + i * sizeof(section_header), SEEK_SET);
        read(fd, &section_header, sizeof(section_header));

        unsigned char* section_data = read_section_data(fd, section_header);

        if (section_program_and_executable(section_header)) {
            print_section_header(section_names, section_header);
            size_t count = cs_disasm(capstone_handle, section_data, section_header.sh_size, section_header.sh_addr, 0, &insn);
            if (count > 0) {
                for (size_t i = 0; i < count; i++)
                    print_disassembly_line(insn[i], i);
                cs_free(insn, count);
            } else {
                fprintf(stderr, "Error disassembling code\n");
                exit(EXIT_FAILURE);
            }
        }
        
        free(section_data);
    }
    free(dyn_data->dynstr_data);
    free(dyn_data->dynsym_symbols);
    free(dyn_data);
    cs_close(&capstone_handle);
}

void print_all_data(int fd, int disassembly_flavor) {
    Elf64_Ehdr elf_header = read_elf_header(fd);
    printf("Entry point address: 0x%lx\n", (unsigned long)elf_header.e_entry);

    Elf64_Shdr section_header = read_section_header(fd, elf_header);
    char* section_names = get_section_names(fd, section_header);
    
    for (int i = 0; i < elf_header.e_shnum; i++) {
        lseek(fd, elf_header.e_shoff + i * sizeof(section_header), SEEK_SET);
        read(fd, &section_header, sizeof(section_header));

        unsigned char* section_data = read_section_data(fd, section_header);
        char* name = section_names + section_header.sh_name;

        print_section_header(section_names, section_header);
        if (section_program_and_executable(section_header)) {
            print_section_disassembly(section_data, section_header.sh_size, section_header.sh_addr, disassembly_flavor);
        } else {
            print_section_data(section_header, section_data);
        }
              
        free(section_data);
    }

    printf("\n");
    free(section_names);
}


int main(int argc, char *argv[]) {
    struct program_flags *flags = get_flags(argc, argv);
    program_name = argv[0];
    int fd = open_file(argv[argc - 1]);
    
    if (flags->disassembly_flag) {
        print_disassembly(fd, flags->disassembly_flavor);
    }

    if (flags->all_flag) {
        print_all_data(fd, flags->disassembly_flavor);
    }

    if (flags->compression_flag == 1) {
        inflate(fd);
    } else if (flags->compression_flag == 2) {
        compress(fd);
    }
    
    if (flags->entropy_flag) {
        float entropy = calculate_fd_entropy(fd);
        printf("\nEntropy: %f bits per byte\n", entropy);
    } 

    free(flags);
    close(fd);
    return 0;
}
