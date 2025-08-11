#include <Windows.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#ifdef __cplusplus
#include "mla.hpp"
#define MLA_STATUS(x) MLAStatus::x
#else
#include "mla.h"
#define MLA_STATUS(x) (x)
#endif

// Callback for reading from a Windows HANDLE (e.g., file handle)
static int32_t read_cb_win(uint8_t *buffer, uint32_t buffer_len, void *context, uint32_t *bytes_read)
{
    HANDLE hFile = (HANDLE)context;
    if (ReadFile(hFile, buffer, buffer_len, (LPDWORD)bytes_read, NULL))
        return 0;
    return GetLastError();
}

// Callback for reading from a standard C FILE*
static int32_t read_cb(uint8_t *buffer, uint32_t buffer_len, void *context, uint32_t *bytes_read)
{
    FILE *f = (FILE *)context;
    *bytes_read = (uint32_t)fread(buffer, 1, buffer_len, f);
    return 0;
}

// Callback for seeking within a standard C FILE*
static int32_t seek_cb(int64_t offset, int32_t whence, void *context, uint64_t *new_pos)
{
    FILE *f = (FILE *)context;
    if (!_fseeki64(f, offset, whence) == 0)
    {
        *new_pos = (uint64_t)_ftelli64(f);
        return 0;
    }
    return errno;
}

// Callback for writing to a standard C FILE*
static int32_t write_cb(const uint8_t *pBuffer, uint32_t length, void *context, uint32_t *pBytesWritten)
{
    FILE *f = (FILE *)context;
    size_t res = fwrite(pBuffer, 1, length, f);
    *pBytesWritten = (uint32_t)res;
    if (ferror(f))
    {
        return errno;
    }
    return 0;
}

// Callback to flush a standard C FILE*
static int32_t flush_cb(void *context)
{
    FILE *f = (FILE *)context;
    if (fflush(f) != 0)
    {
        return errno;
    }
    return 0;
}

// Callback to create and open an output file for extraction
// This is called during archive extraction when a new file needs to be written
static int32_t file_cb(void *context, const uint8_t *filename, uintptr_t filename_len, struct FileWriter *file_writer)
{
    (void)(context);

    // Copy filename to a null-terminated string
    char *szFilename = (char *)calloc(1, filename_len + 1);
    if (!szFilename)
        return -1;

    memcpy(szFilename, filename, filename_len);

    // Construct output path: "extracted/<filename>"
    char *szOutput = (char *)malloc(strlen(szFilename) + 11); // "extracted/" + null
    sprintf_s(szOutput, strlen(szFilename) + 11, "extracted/%s", szFilename);

    free(szFilename);

    // Open output file
    FILE *ofile;
    if (fopen_s(&ofile, szOutput, "wb") != 0)
    {
        free(szOutput);
        return -2;
    }

    free(szOutput);

    // Populate FileWriter structure with callbacks
    file_writer->context = ofile;
    file_writer->write_callback = write_cb;
    file_writer->flush_callback = flush_cb;

    return 0;
}

// Test function to read archive metadata (version, encryption)
int test_reader_info()
{
    MLAStatus status;
    ArchiveInfo archive_info;

    // Open MLA archive using Windows API
    HANDLE hFile = CreateFile(TEXT("../../../../samples/archive_v2.mla"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, " [!] Cannot open file: %lu\n", GetLastError());
        return 1;
    }

    // Retrieve archive information
    status = mla_roarchive_info(read_cb_win, hFile, &archive_info);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Archive info failed with code %" PRIX64 "\n", (uint64_t)status);
        CloseHandle(hFile);
        return (int)status;
    }

    // Validate archive version
    if (archive_info.version != 2)
    {
        fprintf(stderr, " [!] Invalid MLA archive version %x\n", archive_info.version);
        CloseHandle(hFile);
        return 1;
    }

    // Validate encryption flag
    if (archive_info.is_encryption_enabled != 1)
    {
        fprintf(stderr, " [!] Encryption should be enabled\n");
        CloseHandle(hFile);
        return 2;
    }

    printf("SUCCESS\n");
    CloseHandle(hFile);
    return 0;
}

// Test function to extract encrypted MLA archive using a private key
int test_reader_extract()
{
    FILE *kf = NULL;

    // Open private key file
    if (fopen_s(&kf, "../../../../samples/test_mlakey_archive_v2_receiver.mlapriv", "r") != 0)
    {
        fprintf(stderr, " [!] Could not open private key file\n");
        return errno;
    }

    // Determine file size
    if (fseek(kf, 0, SEEK_END) != 0)
    {
        fprintf(stderr, " [!] Could not seek private key file\n");
        fclose(kf);
        return errno;
    }

    long keySize = ftell(kf);
    if (keySize <= 0)
    {
        fprintf(stderr, " [!] Invalid key file size\n");
        fclose(kf);
        return 1;
    }

    rewind(kf);

    // Allocate buffer for key (with null terminator)
    char *keyData = (char *)malloc((size_t)keySize + 1);
    if (!keyData)
    {
        fprintf(stderr, " [!] Memory allocation failed\n");
        fclose(kf);
        return ENOMEM;
    }

    // Read key data
    size_t readLen = fread(keyData, 1, keySize, kf);
    if (readLen != (size_t)keySize)
    {
        fprintf(stderr, " [!] Could not read private key file\n");
        free(keyData);
        fclose(kf);
        return ferror(kf);
    }

    keyData[keySize] = '\0'; // Null terminate

    fclose(kf);

    // Create MLA reader config with encryption (no signature verification)
    MLAReaderConfigHandle hConfig = NULL;
    const char *const keys[] = {(const char *const)keyData};
    MLAStatus status = create_mla_reader_config_with_encryption_without_signature_verification(&hConfig, keys, 1);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Private key set failed with code %" PRIX64 "\n", (uint64_t)status);
        free(keyData);
        return (int)status;
    }

    // Open MLA archive file
    FILE *f = NULL;
    if (fopen_s(&f, "../../../../samples/archive_v2.mla", "rb") != 0)
    {
        fprintf(stderr, " [!] Cannot open archive file: %d\n", errno);
        free(keyData);
        return 1;
    }

    // Ensure extraction output directory exists
    CreateDirectory(TEXT("extracted"), NULL);

    // Extract files from archive
    uint32_t number_of_keys_with_valid_signature = 0;
    status = mla_roarchive_extract(&hConfig, read_cb, seek_cb, file_cb, f, 0, &number_of_keys_with_valid_signature);
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
