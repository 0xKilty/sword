#ifndef USER_INTERACTION_H
#define USER_INTERACTION_H

void print_logo();

struct program_flags {
    char entropy_flag;
    char disassembly_flag;
    char all_flag;
    int disassembly_flavor;
    char compression_flag;
    char* output_file;
};

struct program_flags *get_flags(int argc, char *argv[]);

#endif /* USER_INTERACTION_H */
