#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <string.h>
#ifdef __cplusplus
#include "mla.hpp"
#define MLA_STATUS(x) MLAStatus::x
#else
#include "mla.h"
#define MLA_STATUS(x) (x)
#endif

static const char *callback_read(void *context, const char *szFilename)
{
   context = context; //ignore
   if (szFilename == NULL)
      return NULL;
   char *szOutput = malloc(strlen(szFilename) + 11); // len("extracted/") + 1
   sprintf(szOutput, "extracted/%s", szFilename);
   // The pointer leak is assumed for this test
   return szOutput;
}

int main()
{
   FILE* f = fopen("../../../../samples/test_ed25519.pem", "r");
   if (f == NULL)
   {
      fprintf(stderr, " [!] Could not open private key file\n");
      return errno;
   }
   if (fseek(f, 0, SEEK_END))
   {
      fprintf(stderr, " [!] Could not open private key file\n");
      return errno;
   }

   mkdir("extracted", S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

   long keySize = ftell(f);
   char* szPrivateKey = malloc((size_t)keySize);  
   rewind(f);
   if (keySize != (long)fread(szPrivateKey, sizeof *szPrivateKey, keySize, f))
   {
      fprintf(stderr, " [!] Could not read private key file\n");
      return ferror(f);
   }

   MLAStatus status;
   MLAConfigHandle hConfig = NULL;
   status = mla_reader_config_new(&hConfig);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] Config creation failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   status = mla_reader_config_add_private_key(hConfig, szPrivateKey);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] Public key set failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }
   
   status = mla_roarchive_walk(&hConfig, "../../../../samples/archive_v1.mla", callback_read, NULL);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] Archive read failed with code %" PRIX64 "\n", (uint64_t)status);
      return (int)status;
   }

   fclose(f);
   free(szPrivateKey);

   return 0;
}
