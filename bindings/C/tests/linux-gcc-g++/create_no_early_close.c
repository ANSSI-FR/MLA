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

// From samples/test_ed25519_pub.pem
const char *szPubkey = "-----BEGIN PUBLIC KEY-----\n"
   "MCowBQYDK2VwAyEA9md4yIIFx+ftwe0c1p2YsJFrobXWKxan54Bs+/jFagE=\n"
   "-----END PUBLIC KEY-----\n";

static int32_t callback_write(const uint8_t* pBuffer, uintptr_t length, void *context)
{
   fwrite(pBuffer, length, 1, (FILE*)context);
   return 0;
}

static int32_t callback_flush(void *context)
{
   fflush((FILE*)context);
   return 0;
}

int main()
{
   FILE* f = fopen("test.mla", "w");
   if (f == NULL)
   {
      fprintf(stderr, " [!] Could not create output file\n");
      return errno;
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
   status = mla_archive_new(&hConfig, &callback_write, &callback_flush, f, &hArchive);
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
      return (int)status;
   }

   status = mla_archive_close(&hArchive);
   if (status != MLA_STATUS(MLA_STATUS_WRONG_WRITER_STATE))
   {
      fprintf(stderr, " [!] Archive close did not fail as expected, code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   fclose(f);

   return 0;
}
