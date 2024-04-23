#include "entropy.h"

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
    lseek(fd, 0, SEEK_SET);
    return calculate_entropy(occurrences, total_count);
}