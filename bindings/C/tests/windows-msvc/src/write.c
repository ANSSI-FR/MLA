#include <Windows.h>
#include <stdio.h>
#include <inttypes.h>
#ifdef __cplusplus
#include "mla.hpp"
#define MLA_STATUS(x) MLAStatus::x
#else
#include "mla.h"
#define MLA_STATUS(x) (x)
#endif

// From samples/test_ed25519_pub.pem
PCSTR szPubkey = "-----BEGIN PUBLIC KEY-----\n"
"MCowBQYDK2VwAyEA9md4yIIFx+ftwe0c1p2YsJFrobXWKxan54Bs+/jFagE=\n"
"-----END PUBLIC KEY-----\n";

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
    HANDLE hOutFile = INVALID_HANDLE_VALUE;

    hOutFile = CreateFileA("test.mla", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hOutFile == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, " [!] Could not create output file: error %lu\n", GetLastError());
        return 1;
    }

    MLAStatus status;
    MLAConfigHandle hConfig = NULL;
    status = mla_config_default_new(&hConfig);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Config creation failed with code %" PRIX64 "\n", (uint64_t)status);
        return (int)status;
    }

    status = mla_config_add_public_keys(hConfig, szPubkey);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Public key set failed with code %" PRIX64 "\n", (uint64_t)status);
        return (int)status;
    }

    MLAArchiveHandle hArchive = NULL;
    status = mla_archive_new(&hConfig, &callback_write, &callback_flush, (void*)hOutFile, &hArchive);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Archive creation failed with code %" PRIX64 "\n", (uint64_t)status);
        return (int)status;
    }

    MLAArchiveFileHandle hFile = NULL;
    status = mla_archive_file_new(hArchive, "test.txt", &hFile);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] File creation failed with code %" PRIX64 "\n", (uint64_t)status);
        return 1;
    }

    status = mla_archive_file_append(hArchive, hFile, (const uint8_t*)"Hello, World!\n", (uint32_t)strlen("Hello, World!\n"));
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] File write failed with code %" PRIX64 "\n", (uint64_t)status);
        return 1;
    }

    status = mla_archive_file_close(hArchive, &hFile);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] File close failed with code %" PRIX64 "\n", (uint64_t)status);
        return 1;
    }

    status = mla_archive_close(&hArchive);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Archive close failed with code %" PRIX64 "\n", (uint64_t)status);
        return 1;
    }

    CloseHandle(hOutFile);
    return 0;
}
