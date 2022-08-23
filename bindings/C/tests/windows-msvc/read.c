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

static const char* callback_read(void* context, const char* szFilename)
{
    context = context; //ignore
    if (szFilename == NULL)
        return NULL;
    char* szOutput = malloc(strlen(szFilename) + 11); // len("extracted/") + 1
    sprintf_s(szOutput, strlen(szFilename) + 11, "extracted/%s", szFilename);
    // The pointer leak is assumed for this test
    return szOutput;
}

int test_reader_info()
{
    MLAStatus status;

    ArchiveInfo archive_info;
    HANDLE hFile = CreateFile(TEXT("../../../../samples/archive_v1.mla"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, " [!] Cannot open file: %d\n", GetLastError());
        return 1;
    }

    status = mla_roarchive_info(hFile, &archive_info);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Archive info failed with code %" PRIX64 "\n", (uint64_t)status);
        CloseHandle(hFile);
        return (int)status;
    }
    if (archive_info.version != 1)
    {
        fprintf(stderr, " [!] Invalid MLA archive version %x\n", archive_info.version);
        CloseHandle(hFile);
        return 1;
    }

    if (archive_info.layers != 3)
    {
        fprintf(stderr, " [!] Unexpected layers %x\n", archive_info.layers);
        CloseHandle(hFile);
        return 2;
    }

    printf("SUCCESS\n");
    CloseHandle(hFile);
    return 0;
}

int test_reader_extract()
{
    FILE* f;
    
    if (fopen_s(&f, "../../../../samples/test_ed25519.pem", "r") != 0)
    {
        fprintf(stderr, " [!] Could not open private key file\n");
        return errno;
    }
    if (fseek(f, 0, SEEK_END))
    {
        fprintf(stderr, " [!] Could not open private key file\n");
        return errno;
    }

    _mkdir("extracted");

    long keySize = ftell(f);
    char* szPrivateKey = malloc((size_t)keySize);
    rewind(f);
    if (keySize != (long)fread(szPrivateKey, sizeof * szPrivateKey, keySize, f))
    {
        fprintf(stderr, " [!] Could not read private key file\n");
        return ferror(f);
    }

    MLAStatus status;
    MLAConfigHandle hConfig = NULL;
    status = mla_reader_config_new(&hConfig);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Config creation failed with code %" PRIX64 "\n", (uint64_t)status);
        return (int)status;
    }

    status = mla_reader_config_add_private_key(hConfig, szPrivateKey);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Public key set failed with code %" PRIX64 "\n", (uint64_t)status);
        return (int)status;
    }

    HANDLE hFile = CreateFile(TEXT("../../../../samples/archive_v1.mla"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, " [!] Cannot open file: %d\n", GetLastError());
        return 1;
    }

    status = mla_roarchive_walk(&hConfig, hFile, callback_read, NULL);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Archive read failed with code %" PRIX64 "\n", (uint64_t)status);
        CloseHandle(hFile);
        return (int)status;
    }

    fclose(f);
    free(szPrivateKey);
    CloseHandle(hFile);

    printf("SUCCESS\n");
    return 0;
}
