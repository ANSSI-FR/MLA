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

int main()
{
   MLAStatus status;

   ArchiveInfo archive_info;
   int fd = open("../../../../samples/archive_v1.mla", O_RDONLY);
   if (fd == -1)
   {
      fprintf(stderr, " [!] Cannot open file: %d\n", errno);
      return 1;
   }

   status = mla_roarchive_info(fd, &archive_info);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] Archive info failed with code %" PRIX64 "\n", (uint64_t)status);
      close(fd);
      return (int)status;
   }
   if (archive_info.version != 1)
   {
      fprintf(stderr, " [!] Invalid MLA archive version %x\n", archive_info.version);
      close(fd);
      return 1;
   }

   if (archive_info.layers != 3)
   {
      fprintf(stderr, " [!] Unexpected layers %x\n", archive_info.layers);
      close(fd);
      return 2;
   }

   close(fd);
   printf("SUCCESS\n");
   return 0;
}
