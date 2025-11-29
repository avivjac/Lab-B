#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define HEXA_BUFFER_SIZE 16

static void PrintHex(const unsigned char *buffer, size_t length, bool *is_first)
{
    for (size_t i = 0; i < length; ++i)
    {
        if (!(*is_first))
            printf(" ");
        printf("%02X", buffer[i]);
        *is_first = false;
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s FILE\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *file_name = argv[1];
    FILE *file = fopen(file_name, "rb");
    if (!file)
    {
        perror("fopen");
        return EXIT_FAILURE;
    }

    unsigned char buffer[HEXA_BUFFER_SIZE];
    size_t bytes_read;
    bool is_first = true;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        PrintHex(buffer, bytes_read, &is_first);
    }

    if (ferror(file))
    {
        perror("fread");
        fclose(file);
        return EXIT_FAILURE;
    }

    fclose(file);
    if (!is_first)
        printf("\n");

    return EXIT_SUCCESS;
}

