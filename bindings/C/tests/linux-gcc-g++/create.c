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

// Public key from samples/test_mlakey.mlapub (replaced in Makefile via sed)
const char *szPubkey = "REPLACE WITH PUBLIC KEY FROM SAMPLE";

// Callback for writing data to file
static int32_t callback_write(const uint8_t* pBuffer, uint32_t length, void *context, uint32_t *pBytesWritten)
{
   size_t res = fwrite(pBuffer, 1, length, (FILE*)context);
   *pBytesWritten = (uint32_t)res;
   if (ferror((FILE*)context))
   {
       return errno; // Return the error code if write fails
   }
   return 0;
}

// Callback for flushing data to file
static int32_t callback_flush(void *context)
{
   if (fflush((FILE*)context) != 0)
   {
       return errno; // Return the error code if flush fails
   }
   return 0;
}

int main()
{
   // Open file for writing
   FILE* f = fopen("test.mla", "w");
   if (f == NULL)
   {
      fprintf(stderr, " [!] Could not create output file\n");
      return errno;
   }

   MLAStatus status;
   MLAWriterConfigHandle hConfig = NULL;

   // Create writer config with encryption, no signature, using public key
   const char *const keys[] = {szPubkey};
   status = create_mla_writer_config_with_encryption_without_signature(&hConfig, keys, 1);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] Public key set failed with code %" PRIX64 "\n", (uint64_t)status);
      fclose(f);
      return (int)status;
   }
   
   // Create new MLA archive with callbacks for writing and flushing
   MLAArchiveHandle hArchive = NULL;
   status = mla_archive_new(&hConfig, &callback_write, &callback_flush, f, &hArchive);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] Archive creation failed with code %" PRIX64 "\n", (uint64_t)status);
      fclose(f);
      return (int)status;
   }

   // Start new archive entry (file) named "test.txt"
   MLAArchiveEntryHandle hFile = NULL;
   status = mla_archive_start_entry_with_path_as_name(hArchive, "test.txt", &hFile);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] File creation failed with code %" PRIX64 "\n", (uint64_t)status);
      mla_archive_close(&hArchive);
      fclose(f);
      return (int)status;
   }

   // Write data into the archive file entry
   const char *data = "Hello, World!\n";
   status = mla_archive_file_append(hArchive, hFile, (const uint8_t*)data, (uint32_t)strlen(data));
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] File write failed with code %" PRIX64 "\n", (uint64_t)status);
      mla_archive_file_close(hArchive, &hFile);
      mla_archive_close(&hArchive);
      fclose(f);
      return (int)status;
   }

   // Close the archive file entry
   status = mla_archive_file_close(hArchive, &hFile);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] File close failed with code %" PRIX64 "\n", (uint64_t)status);
      mla_archive_close(&hArchive);
      fclose(f);
      return (int)status;
   }

   // Close the MLA archive
   status = mla_archive_close(&hArchive);
   if (status != MLA_STATUS(MLA_STATUS_SUCCESS))
   {
      fprintf(stderr, " [!] Archive close failed with code %" PRIX64 "\n", (uint64_t)status);
      fclose(f);
      return (int)status;
   }

   fclose(f);

   printf("Archive created successfully.\n");

   return 0;
}