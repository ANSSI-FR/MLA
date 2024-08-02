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

static int32_t callback_write(const uint8_t* pBuffer, uint32_t length, void *context, uint32_t *pBytesWritten)
{
   size_t res = fwrite(pBuffer, 1, length, (FILE*)context);
   *pBytesWritten = (uint32_t)res;
   if (ferror(context))
   {
       return errno;
   }
   return 0;
}

static int32_t callback_flush(void *context)
{
   if (fflush((FILE*)context) != 0)
   {
       return errno;
   }
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

   MLAArchiveHandle hArchive = NULL;
   status = mla_archive_new(&hConfig, &callback_write, &callback_flush, f, &hArchive);
   if (status != MLA_STATUS(MLA_STATUS_CONFIG_ERROR_NO_RECIPIENTS))
   {
      fprintf(stderr, " [!] Archive creation did not fail, status %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   fclose(f);
   return 0;
}
