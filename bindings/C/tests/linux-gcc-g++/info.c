#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
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

int main()
{
    MLAStatus status;

    ArchiveInfo archive_info;
    FILE *f = fopen("../../../../samples/archive_v2.mla", "r");
    if (!f)
    {
        fprintf(stderr, " [!] Cannot open file: %d\n", errno);
        return 1;
    }

    status = mla_roarchive_info(read_cb, f, &archive_info);
    if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
    {
        fprintf(stderr, " [!] Archive info failed with code %" PRIX64 "\n", (uint64_t)status);
        fclose(f);
        return (int)status;
    }
    if (archive_info.version != 2)
    {
        fprintf(stderr, " [!] Invalid MLA archive version %x\n", archive_info.version);
        fclose(f);
        return 1;
    }

    if (archive_info.is_encryption_enabled != 1)
    {
        fprintf(stderr, " [!] Encryption should be enabled\n");
        fclose(f);
        return 2;
    }

    if (archive_info.is_signature_enabled != 1)
    {
        fprintf(stderr, " [!] Signature should be enabled\n");
        fclose(f);
        return 2;
    }

    fclose(f);
    printf("SUCCESS\n");
    return 0;
}
