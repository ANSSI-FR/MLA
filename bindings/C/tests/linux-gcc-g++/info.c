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
   MLAStatus status;

   ArchiveInfo archive_info;
   status = mla_roarchive_info("../../../../samples/archive_v1.mla", &archive_info);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] Archive info failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }
   if (archive_info.version != 1)
   {
      fprintf(stderr, " [!] Invalid MLA archive version %x\n", archive_info.version);
      return 1;
   }

   if (archive_info.layers != 3)
   {
      fprintf(stderr, " [!] Unexpected layers %x\n", archive_info.layers);
      return 2;
   }

   return 0;
}
