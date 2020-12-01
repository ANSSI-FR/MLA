#include <Windows.h>
#include <stdio.h>
#include <inttypes.h>

#pragma comment(lib, "mla.lib")
#include "mla.h"

// From samples/test_ed25519_pub.pem
PCSTR szPubkey = "-----BEGIN PUBLIC KEY-----\n"
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
   FILE* f = NULL;
   if (fopen_s(&f, "test.mla", "w") != 0)
   {
      fprintf(stderr, " [!] Could not create output file\n");
      return 1;
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

   status = mla_config_set_compression_level(hConfig, 10);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] Compression level set failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   MLAArchiveHandle hArchive = NULL;
   status = mla_archive_new(&hConfig, &callback_write, &callback_flush, f, &hArchive);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] Archive creation failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   MLAArchiveFileHandle hFile = NULL;
   status = mla_archive_file_new(hArchive, "test.txt", &hFile);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File creation failed with code %" PRIX64 "\n", (uint64_t)status);
      return 1;
   }

   status = mla_archive_file_append(hArchive, hFile, "Hello, World!\n", (uint32_t)strlen("Hello, World!\n"));
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File write failed with code %" PRIX64 "\n", (uint64_t)status);
      return 1;
   }

   status = mla_archive_file_close(hArchive, &hFile);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] File close failed with code %" PRIX64 "\n", (uint64_t)status);
      return 1;
   }

   status = mla_archive_close(&hArchive);
   if (status != MLA_STATUS_SUCCESS)
   {
      fprintf(stderr, " [!] Archive close failed with code %" PRIX64 "\n", (uint64_t)status);
      return 1;
   }

   fclose(f);
   return 0;
}
