#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "mla.h"

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

   MLAArchiveHandle hArchive = NULL;
   status = mla_archive_new(&hConfig, &callback_write, &callback_flush, f, &hArchive);
   if (status != MLA_STATUS_CONFIG_ERROR_ENCRYPTION_KEY_IS_MISSING)
   {
      fprintf(stderr, " [!] Archive creation did not fail, status %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   fclose(f);
   return 0;
}
