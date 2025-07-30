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

// from samples/test_mlakey_archive_v2_receiver.mlapriv
const char * const szDecryptionPrivkey = "REPLACE WITH PRIVATE ARCHIVE V2 RECEIVER PRIVATE KEY FROM SAMPLE";
// from samples/test_mlakey_archive_v2_sender.mlapub
const char * const szSignatureVerificationPublickey = "REPLACE WITH PRIVATE ARCHIVE V2 SENDER PUBLIC KEY FROM SAMPLE";

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
    mkdir("extracted", S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

    MLAReaderConfigHandle hConfig = NULL;
    const char *const decryption_keys[] = {(const char *const) szDecryptionPrivkey};
    const char *const signature_verification_keys[] = {(const char *const) szSignatureVerificationPublickey};
    MLAStatus status = create_mla_reader_config_with_encryption_with_signature_verification(&hConfig, decryption_keys, 1, signature_verification_keys, 1);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Private key set failed with code %" PRIX64 "\n", (uint64_t)status);
        return (int)status;
    }

    FILE *f = fopen("../../../../samples/archive_v2.mla", "r");
    if (!f)
    {
        fprintf(stderr, " [!] Cannot open file: %d\n", errno);
        return 1;
    }

    uint32_t number_of_keys_with_valid_signature = 0;
    status = mla_roarchive_extract(&hConfig, read_cb, seek_cb, file_cb, f, 0, &number_of_keys_with_valid_signature);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Archive read failed with code %" PRIX64 "\n", (uint64_t)status);
        fclose(f);
        return (int)status;
    }

    // just to check, if it was not at least one, we would have received an error
    if (number_of_keys_with_valid_signature != 1) {
        fprintf(stderr, " [!] wrong number of keys with valid signature \n");
        fclose(f);
        return 2;
    }

    fclose(f);

    printf("SUCCESS\n");
    return 0;
}
