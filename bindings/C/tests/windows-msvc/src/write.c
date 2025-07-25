#include <Windows.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>

#ifdef __cplusplus
#include "mla.hpp"
#define MLA_STATUS(x) MLAStatus::x
#else
#include "mla.h"
#define MLA_STATUS(x) (x)
#endif

static int32_t callback_write(const uint8_t* pBuffer, uint32_t length, void* context, uint32_t* pBytesWritten)
{
    HANDLE hOutFile = (HANDLE)context;

    if (!WriteFile(hOutFile, pBuffer, length, (PDWORD)pBytesWritten, NULL))
    {
        int32_t err = GetLastError();
        fprintf(stderr, " [!] Could not write to output file: error %lu\n", err);
        return err;
    }
    return 0;
}

static int32_t callback_flush(void* context)
{
    HANDLE hOutFile = (HANDLE)context;
    if (!FlushFileBuffers(hOutFile))
    {
        int32_t err = GetLastError();
        fprintf(stderr, " [!] Could not flush to output file: error %lu\n", err);
        return err;
    }
    return 0;
}

int test_writer()
{
    FILE *kf = NULL;
    char *keyData = NULL;
    const char *keys[1] = { NULL };

    HANDLE hOutFile = INVALID_HANDLE_VALUE;
    MLAStatus status = MLA_STATUS(MLA_STATUS_SUCCESS);
    MLAWriterConfigHandle hConfig = NULL;
    MLAArchiveHandle hArchive = NULL;
    MLAArchiveFileHandle hFile = NULL;
    long keySize = 0;
    size_t bytesRead = 0;
    const char *message = NULL;

    if (fopen_s(&kf, "../../../../samples/test_mlakey.mlapub", "r") != 0)
    {
        fprintf(stderr, " [!] Could not open public key file\n");
        return errno;
    }

    if (fseek(kf, 0, SEEK_END) != 0)
    {
        fprintf(stderr, " [!] Could not seek in public key file\n");
        status = (MLAStatus)errno;
        goto cleanup;
    }

    keySize = ftell(kf);
    if (keySize <= 0)
    {
        fprintf(stderr, " [!] Invalid key file size\n");
        status = (MLAStatus)1;
        goto cleanup;
    }

    // Allocate space +1 for null terminator
    keyData = (char *)malloc((size_t)keySize + 1);
    if (!keyData)
    {
        fprintf(stderr, " [!] Memory allocation failed\n");
        status = (MLAStatus)ENOMEM;
        goto cleanup;
    }

    rewind(kf);

    bytesRead = fread(keyData, 1, keySize, kf);
    if (bytesRead != (size_t)keySize)
    {
        fprintf(stderr, " [!] Could not read public key file\n");
        status = (MLAStatus)ferror(kf);
        goto cleanup;
    }

    keyData[bytesRead] = '\0';  // Null terminate for string safety

    keys[0] = (const char *)keyData;

    hOutFile = CreateFileA("test.mla", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hOutFile == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, " [!] Could not create output file: error %lu\n", GetLastError());
        status = (MLAStatus)1;
        goto cleanup;
    }

    status = create_mla_writer_config_with_public_keys(&hConfig, keys, 1);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Public key set failed with code %" PRIX64 "\n", (uint64_t)status);
        goto cleanup;
    }

    status = mla_archive_new(&hConfig, &callback_write, &callback_flush, (void*)hOutFile, &hArchive);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Archive creation failed with code %" PRIX64 "\n", (uint64_t)status);
        goto cleanup;
    }

    status = mla_archive_start_entry_with_path_as_name(hArchive, "test.txt", &hFile);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] File creation failed with code %" PRIX64 "\n", (uint64_t)status);
        goto cleanup;
    }

    message = "Hello, World!\n";
    status = mla_archive_file_append(hArchive, hFile, (const uint8_t*)message, (uint32_t)strlen(message));
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] File write failed with code %" PRIX64 "\n", (uint64_t)status);
        goto cleanup;
    }

    status = mla_archive_file_close(hArchive, &hFile);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] File close failed with code %" PRIX64 "\n", (uint64_t)status);
        goto cleanup;
    }

    status = mla_archive_close(&hArchive);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Archive close failed with code %" PRIX64 "\n", (uint64_t)status);
        goto cleanup;
    }

    printf("SUCCESS\n");

cleanup:
    if (keyData) free(keyData);
    if (kf) fclose(kf);
    if (hOutFile != INVALID_HANDLE_VALUE) CloseHandle(hOutFile);
    return (int)status;
}
