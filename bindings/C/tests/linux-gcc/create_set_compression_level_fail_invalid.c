#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "mla.h"

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

   status = mla_config_set_compression_level(hConfig, 42);
   if (status != MLA_STATUS_CONFIG_ERROR_COMPRESSION_LEVEL_OUT_OF_RANGE)
   {
      fprintf(stderr, " [!] Compression level set failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   fclose(f);
   return 0;
}
