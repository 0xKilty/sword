#ifndef ENTROPY
#define ENTROPY

#include <unistd.h>
#include <math.h>

#define ENTROPY_BUFFER_SIZE 256

float calculate_entropy(int* occurrences, int total_count);
float calculate_fd_entropy(int fd);

#endif /* ENTROPY */