#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "mla.h"

// From samples/test_ed25519.pem
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

   MLAStatus status = 0;
   MLAConfigHandle hConfig = NULL;
   status = mla_config_default_new(&hConfig);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] Config creation failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   status = mla_config_add_public_keys(hConfig, szPubkey);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] Public key set failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   MLAArchiveHandle hArchive = NULL;
   status = mla_archive_new(&hConfig, &callback_write, &callback_flush, f, &hArchive);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] Archive creation failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   MLAArchiveFileHandle hFile1 = NULL;
   status = mla_archive_file_new(hArchive, "test1.txt", &hFile1);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File creation failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }
   
   MLAArchiveFileHandle hFile2 = NULL;
   status = mla_archive_file_new(hArchive, "test2.txt", &hFile2);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File creation failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   status = mla_archive_file_append(hArchive, hFile1, (const uint8_t*)"Hello,", (uint32_t)strlen("Hello,"));
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File write failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   status = mla_archive_flush(hArchive);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] Archive flush failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }
   
   status = mla_archive_file_append(hArchive, hFile2, (const uint8_t*)"Hell", (uint32_t)strlen("Hell"));
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File write failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }
   
   status = mla_archive_file_append(hArchive, hFile1, (const uint8_t*)" World!\n", (uint32_t)strlen(" World!\n"));
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File write failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }
   
   status = mla_archive_file_append(hArchive, hFile2, (const uint8_t*)"o, World!\n", (uint32_t)strlen("o, World!\n"));
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File write failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   status = mla_archive_file_close(hArchive, &hFile1);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File close failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }
   
   status = mla_archive_file_close(hArchive, &hFile2);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File close failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   status = mla_archive_close(&hArchive);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] Archive close failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   fclose(f);

   return 0;
}
