#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MENU_BUFFER_SIZE 256
#define VIRUS_HEADER_SIZE 18

typedef struct virus
{
    unsigned short SigSize;
    char virusName[16];
    unsigned char *sig;
} virus;

typedef struct link link;
struct link
{
    link *nextVirus;
    virus *vir;
};

static link *SignaturesList = NULL;
static int SignatureFileIsLittleEndian = 1;
static void virus_free(virus *vir);
static void neutralize_virus(char *fileName, int signatureOffset);

static unsigned short read_u16(const unsigned char *buffer)
{
    if (SignatureFileIsLittleEndian)
        return (unsigned short)(buffer[0] | (buffer[1] << 8));
    return (unsigned short)((buffer[0] << 8) | buffer[1]);
}

static virus *readSignature(FILE *file)
{
    unsigned char header[VIRUS_HEADER_SIZE];
    size_t bytes_read = fread(header, 1, sizeof(header), file);
    if (bytes_read == 0)
        return NULL;
    if (bytes_read < sizeof(header))
    {
        fprintf(stderr, "Incomplete virus header\n");
        return NULL;
    }

    virus *v = (virus *)calloc(1, sizeof(*v));
    if (!v)
    {
        perror("calloc");
        return NULL;
    }

    v->SigSize = read_u16(header);
    memcpy(v->virusName, header + 2, sizeof(v->virusName));
    v->virusName[sizeof(v->virusName) - 1] = '\0';

    if (v->SigSize > 0)
    {
        v->sig = (unsigned char *)malloc(v->SigSize);
        if (!v->sig)
        {
            perror("malloc");
            free(v);
            return NULL;
        }

        if (fread(v->sig, 1, v->SigSize, file) != v->SigSize)
        {
            fprintf(stderr, "Failed to read full virus signature\n");
            free(v->sig);
            free(v);
            return NULL;
        }
    }
    else
    {
        v->sig = NULL;
    }

    return v;
}

static void printSignature(const virus *virus, FILE *output)
{
    if (!virus || !output)
        return;

    fprintf(output, "Virus name: %s\n", virus->virusName);
    fprintf(output, "Virus size: %u\n", virus->SigSize);
    fprintf(output, "Signature:");
    for (unsigned short i = 0; i < virus->SigSize; ++i)
        fprintf(output, " %02X", virus->sig ? virus->sig[i] : 0);
    fprintf(output, "\n\n");
}

static void print_menu(void)
{
    printf("1) Load signatures\n");
    printf("2) Print signatures\n");
    printf("3) Detect viruses\n");
    printf("4) Fix file\n");
    printf("5) AI analysis of file\n");
    printf("6) Quit\n");
    printf("Select one of the above options:\n");
}

static void print_not_implemented(void)
{
    printf("Not implemented yet\n");
}

static link *list_append(link *virus_list, virus *data)
{
    link *new_link = (link *)malloc(sizeof(*new_link));
    if (!new_link)
    {
        perror("malloc");
        virus_free(data);
        return virus_list;
    }

    new_link->vir = data;
    new_link->nextVirus = NULL;

    if (!virus_list)
        return new_link;

    link *current = virus_list;
    while (current->nextVirus)
        current = current->nextVirus;
    current->nextVirus = new_link;
    return virus_list;
}

static void list_print(link *virus_list, FILE *output)
{
    if (!virus_list)
    {
        fprintf(output, "No signatures\n");
        return;
    }

    for (link *current = virus_list; current != NULL; current = current->nextVirus)
        printSignature(current->vir, output);
}

static void detect_virus(const unsigned char *buffer, size_t buffer_size, link *virus_list)
{
    if (!buffer || !virus_list)
        return;

    for (size_t i = 0; i < buffer_size; ++i)
    {
        for (link *current = virus_list; current != NULL; current = current->nextVirus)
        {
            virus *v = current->vir;
            if (!v || !v->sig || v->SigSize == 0)
                continue;
            if (i + v->SigSize > buffer_size)
                continue;
            if (memcmp(buffer + i, v->sig, v->SigSize) == 0)
            {
                printf("Virus detected!\n");
                printf("Starting byte location: %zu\n", i);
                printf("Virus name: %s\n", v->virusName);
                printf("Virus size: %u\n\n", v->SigSize);
            }
        }
    }
}

static void detect_viruses(void)
{
    if (!SignaturesList)
    {
        printf("No signatures\n");
        return;
    }

    char path[MENU_BUFFER_SIZE];
    printf("Enter suspected file name:\n");
    if (!fgets(path, sizeof(path), stdin))
    {
        printf("Failed to read file name\n");
        return;
    }
    path[strcspn(path, "\n")] = '\0';

    FILE *file = fopen(path, "rb");
    if (!file)
    {
        perror("fopen");
        return;
    }

    unsigned char buffer[10240];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
    if (ferror(file))
    {
        perror("fread");
        fclose(file);
        return;
    }

    detect_virus(buffer, bytes_read, SignaturesList);
    fclose(file);
}

static void fix_file(void)
{
    if (!SignaturesList)
    {
        printf("No signatures\n");
        return;
    }

    char path[MENU_BUFFER_SIZE];
    printf("Enter suspected file name:\n");
    if (!fgets(path, sizeof(path), stdin))
    {
        printf("Failed to read file name\n");
        return;
    }
    path[strcspn(path, "\n")] = '\0';

    FILE *file = fopen(path, "rb");
    if (!file)
    {
        perror("fopen");
        return;
    }

    unsigned char buffer[10240];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
    if (ferror(file))
    {
        perror("fread");
        fclose(file);
        return;
    }
    fclose(file);

    int neutralized = 0;

    for (size_t i = 0; i < bytes_read; ++i)
    {
        for (link *current = SignaturesList; current != NULL; current = current->nextVirus)
        {
            virus *v = current->vir;
            if (!v || !v->sig || v->SigSize == 0)
                continue;
            if (i + v->SigSize > bytes_read)
                continue;
            if (memcmp(buffer + i, v->sig, v->SigSize) == 0)
            {
                if (i > INT_MAX)
                    continue;
                neutralize_virus(path, (int)i);
                printf("Neutralized virus %s at offset %zu\n", v->virusName, i);
                ++neutralized;
            }
        }
    }

    if (neutralized == 0)
        printf("No viruses neutralized\n");
}

static void ai_analysis(void)
{
    print_not_implemented();
}

static void neutralize_virus(char *fileName, int signatureOffset)
{
    FILE *file = fopen(fileName, "rb+");
    if (!file)
    {
        perror("fopen");
        return;
    }

    if (fseek(file, (long)signatureOffset, SEEK_SET) != 0)
    {
        perror("fseek");
        fclose(file);
        return;
    }

    unsigned char ret_opcode = 0xC3;
    if (fwrite(&ret_opcode, 1, 1, file) != 1)
        perror("fwrite");

    fclose(file);
}

static void virus_free(virus *vir)
{
    if (!vir)
        return;
    free(vir->sig);
    free(vir);
}

static void list_free(link *virus_list)
{
    while (virus_list)
    {
        link *next = virus_list->nextVirus;
        virus_free(virus_list->vir);
        free(virus_list);
        virus_list = next;
    }
}

static int read_magic_number(FILE *file)
{
    unsigned char magic[4];
    if (fread(magic, 1, sizeof(magic), file) != sizeof(magic))
    {
        fprintf(stderr, "Failed to read magic number\n");
        return 0;
    }

    if (memcmp(magic, "VIRL", 4) == 0)
    {
        SignatureFileIsLittleEndian = 1;
        return 1;
    }
    if (memcmp(magic, "VIRB", 4) == 0)
    {
        SignatureFileIsLittleEndian = 0;
        return 1;
    }

    fprintf(stderr, "Invalid magic number\n");
    return 0;
}

static void load_signatures(void)
{
    char path[MENU_BUFFER_SIZE];
    printf("Enter signatures file name:\n");
    if (!fgets(path, sizeof(path), stdin))
    {
        printf("Failed to read file name\n");
        return;
    }

    path[strcspn(path, "\n")] = '\0';
    FILE *file = fopen(path, "rb");
    if (!file)
    {
        perror("fopen");
        return;
    }

    list_free(SignaturesList);
    SignaturesList = NULL;

    if (!read_magic_number(file))
    {
        fclose(file);
        return;
    }

    while (1)
    {
        virus *v = readSignature(file);
        if (!v)
            break;
        SignaturesList = list_append(SignaturesList, v);
    }

    fclose(file);
}

static void print_signatures(void)
{
    list_print(SignaturesList, stdout);
}

static void run_menu(void)
{
    char input[MENU_BUFFER_SIZE];
    int option;

    while (1)
    {
        print_menu();
        if (!fgets(input, sizeof(input), stdin))
        {
            printf("Failed to read input. Exiting.\n");
            break;
        }

        if (sscanf(input, "%d", &option) != 1)
        {
            printf("Invalid option\n");
            continue;
        }

        switch (option)
        {
        case 1:
            load_signatures();
            break;
        case 2:
            print_signatures();
            break;
        case 3:
            detect_viruses();
            break;
        case 4:
            fix_file();
            break;
        case 5:
            ai_analysis();
            break;
        case 6:
            list_free(SignaturesList);
            return;
        default:
            printf("Invalid option\n");
            break;
        }
    }
}

int main(void)
{
    run_menu();
    return EXIT_SUCCESS;
}

