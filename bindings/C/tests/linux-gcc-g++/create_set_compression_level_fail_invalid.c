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

int main()
{
   FILE* f = fopen("test.mla", "w");
   if (f == NULL)
   {
      fprintf(stderr, " [!] Could not create output file\n");
      return errno;
   }

   MLAStatus status;
   MLAWriterConfigHandle hConfig = NULL;
   status = create_mla_writer_config_without_encryption_without_signature(&hConfig);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] Config creation failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   status = mla_writer_config_with_compression_level(&hConfig, 42);
   if (status != MLA_STATUS(MLA_STATUS_CONFIG_ERROR_COMPRESSION_LEVEL_OUT_OF_RANGE))
   {
      fprintf(stderr, " [!] Compression level set failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   fclose(f);
   return 0;
}
