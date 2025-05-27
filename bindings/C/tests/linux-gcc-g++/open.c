#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <string.h>
#ifdef __cplusplus
#include "mla.hpp"
#define MLA_STATUS(x) MLAStatus::x
#else
#include "mla.h"
#define MLA_STATUS(x) (x)
#endif

static int32_t read_cb(uint8_t *buffer, uint32_t buffer_len, void *context, uint32_t *bytes_read)
{
    FILE *f = (FILE *)context;
    *bytes_read = fread(buffer, 1, buffer_len, f);
    return 0;
}

static int32_t seek_cb(int64_t offset, int32_t whence, void *context, uint64_t *new_pos)
{
    FILE *f = (FILE *)context;
    if (!fseek(f, offset, whence))
    {
        *new_pos = ftell(f);
        return 0;
    }

    return errno;
}

static int32_t write_cb(const uint8_t *pBuffer, uint32_t length, void *context, uint32_t *pBytesWritten)
{
    FILE *f = (FILE *)context;
    size_t res = fwrite(pBuffer, 1, length, f);
    *pBytesWritten = (uint32_t)res;
    if (ferror(context))
    {
        return errno;
    }
    return 0;
}

static int32_t flush_cb(void *context)
{
    FILE *f = (FILE *)context;
    if (fflush(f) != 0)
    {
        return errno;
    }
    return 0;
}

static int32_t file_cb(void *context, const uint8_t *filename, uintptr_t filename_len, struct FileWriter *file_writer)
{
    (void)(context);
    // Copy filename to a zero terminated buffer
    char *szFilename = (char *)calloc(1, filename_len + 1);
    if (!szFilename)
        return -1;
    memcpy(szFilename, filename, filename_len);
    // !!! in real-world code, do security checks on filenames !!!
    char *szOutput = malloc(strlen(szFilename) + 11); // len("extracted/") + 1
    sprintf(szOutput, "extracted/%s", szFilename);

    free(szFilename);

    FILE *ofile = fopen(szOutput, "w");
    if (!ofile)
        return -2;

    free(szOutput);

    file_writer->context = ofile;
    file_writer->write_callback = write_cb;
    file_writer->flush_callback = flush_cb;

    return 0;
}

int main()
{
    FILE *kf = fopen("../../../../samples/test_mlakey_archive_v2.der", "r");
    if (kf == NULL)
    {
        fprintf(stderr, " [!] Could not open private key file\n");
        return errno;
    }
    if (fseek(kf, 0, SEEK_END))
    {
        fprintf(stderr, " [!] Could not open private key file\n");
        fclose(kf);
        return errno;
    }

    mkdir("extracted", S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

    long keySize = ftell(kf);
    if (keySize <= 0) {
        fprintf(stderr, " [!] Invalid key file size\n");
        fclose(kf);
        return 1;
    }

    rewind(kf);

    uint8_t *keyData = malloc((size_t)keySize);
    if (!keyData) {
        fprintf(stderr, " [!] Memory allocation failed\n");
        fclose(kf);
        return ENOMEM;
    }

    if (keySize != (long)fread(keyData, sizeof *keyData, keySize, kf))
    {
        fprintf(stderr, " [!] Could not read private key file\n");
        free(keyData);
        return ferror(kf);
    }

    fclose(kf);

    MLAConfigHandle hConfig = NULL;
    MLAStatus status = mla_reader_config_new(&hConfig);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Config creation failed with code %" PRIX64 "\n", (uint64_t)status);
        free(keyData);
        return (int)status;
    }

    status = mla_reader_config_add_private_key_der(hConfig, keyData, (size_t)keySize);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Private key set failed with code %" PRIX64 "\n", (uint64_t)status);
        free(keyData);
        return (int)status;
    }

    FILE *f = fopen("../../../../samples/archive_v2.mla", "r");
    if (!f)
    {
        fprintf(stderr, " [!] Cannot open file: %d\n", errno);
        free(keyData);
        return 1;
    }

    status = mla_roarchive_extract(&hConfig, read_cb, seek_cb, file_cb, f);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Archive read failed with code %" PRIX64 "\n", (uint64_t)status);
        fclose(f);
        free(keyData);
        return (int)status;
    }

    free(keyData);
    fclose(f);

    printf("SUCCESS\n");
    return 0;
}
