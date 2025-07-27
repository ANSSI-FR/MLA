/* Automatically generated with cbindgen --config cbindgen_c.toml (do not modify) */

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

enum MLAStatus {
  MLA_STATUS_SUCCESS = 0,
  MLA_STATUS_IO_ERROR = 65536,
  MLA_STATUS_WRONG_MAGIC = 131072,
  MLA_STATUS_UNSUPPORTED_VERSION = 196608,
  MLA_STATUS_INVALID_KEY_FORMAT = 262144,
  MLA_STATUS_WRONG_BLOCK_SUB_FILE_TYPE = 327680,
  MLA_STATUS_UTF8_CONVERSION_ERROR = 393216,
  MLA_STATUS_FILENAME_TOO_LONG = 458752,
  MLA_STATUS_WRONG_ARCHIVE_WRITER_STATE = 524288,
  MLA_STATUS_ASSERTION_ERROR = 589824,
  MLA_STATUS_WRONG_READER_STATE = 655360,
  MLA_STATUS_WRONG_WRITER_STATE = 720896,
  MLA_STATUS_RAND_ERROR = 851968,
  MLA_STATUS_PRIVATE_KEY_NEEDED = 917504,
  MLA_STATUS_DESERIALIZATION_ERROR = 983040,
  MLA_STATUS_SERIALIZATION_ERROR = 1048576,
  MLA_STATUS_MISSING_METADATA = 1114112,
  MLA_STATUS_BAD_API_ARGUMENT = 1179648,
  MLA_STATUS_END_OF_STREAM = 1245184,
  MLA_STATUS_CONFIG_ERROR_INCOHERENT_PERSISTENT_CONFIG = 1310721,
  MLA_STATUS_CONFIG_ERROR_COMPRESSION_LEVEL_OUT_OF_RANGE = 1310722,
  MLA_STATUS_CONFIG_ERROR_ENCRYPTION_KEY_IS_MISSING = 1310723,
  MLA_STATUS_CONFIG_ERROR_PRIVATE_KEY_NOT_SET = 1310724,
  MLA_STATUS_CONFIG_ERROR_PRIVATE_KEY_NOT_FOUND = 1310725,
  MLA_STATUS_CONFIG_ERROR_DHKEM_COMPUTATION_ERROR = 1310726,
  MLA_STATUS_CONFIG_ERROR_KEY_COMMITMENT_COMPUTATION_ERROR = 1310727,
  MLA_STATUS_CONFIG_ERROR_KEY_COMMITMENT_CHECKING_ERROR = 1310728,
  MLA_STATUS_CONFIG_ERROR_NO_RECIPIENTS = 1310729,
  MLA_STATUS_CONFIG_ERROR_MLKEM_COMPUTATION_ERROR = 1310730,
  MLA_STATUS_CONFIG_ERROR_KEY_WRAPPING_COMPUTATION_ERROR = 1310731,
  MLA_STATUS_DUPLICATE_FILENAME = 1376256,
  MLA_STATUS_AUTHENTICATED_DECRYPTION_WRONG_TAG = 1441792,
  MLA_STATUS_HKDF_INVALID_KEY_LENGTH = 1507328,
  MLA_STATUS_HPKE_ERROR = 98304,
  MLA_STATUS_INVALID_LAST_TAG = 102400,
  MLA_STATUS_ENCRYPTION_ASKED_BUT_NOT_MARKED_PRESENT = 1572864,
  MLA_STATUS_WRONG_END_MAGIC = 1638400,
  MLA_STATUS_NO_VALID_SIGNATURE_FOUND = 2097152,
  MLA_STATUS_SIGNATURE_VERIFICATION_ASKED_BUT_NO_SIGNATURE_LAYER_FOUND = 2162688,
  MLA_STATUS_MLA_KEY_PARSER_ERROR = 15859712,
};
typedef uint64_t MLAStatus;

typedef void *MLAWriterConfigHandle;

typedef void *MLAReaderConfigHandle;

/**
 * Implemented by the developper. Takes a buffer of a certain number of bytes of MLA
 * file, and does whatever it wants with it (e.g. write it to a file, to a HTTP stream, etc.)
 * If successful, returns 0 and sets the number of bytes actually written to its last
 * parameter. Otherwise, returns an error code on failure.
 */
typedef int32_t (*MLAWriteCallback)(const uint8_t *buffer,
                                    uint32_t buffer_len,
                                    void *context,
                                    uint32_t *bytes_written);

/**
 * Implemented by the developper. Should ask the underlying medium (file buffering, HTTP
 * buffering, etc.) to flush any internal buffer.
 */
typedef int32_t (*MLAFlushCallback)(void *context);

typedef void *MLAArchiveHandle;

typedef void *MLAArchiveFileHandle;

/**
 * Implemented by the developper. Read between 0 and buffer_len into buffer.
 * If successful, returns 0 and sets the number of bytes actually read to its last
 * parameter. Otherwise, returns an error code on failure.
 */
typedef int32_t (*MlaReadCallback)(uint8_t *buffer,
                                   uint32_t buffer_len,
                                   void *context,
                                   uint32_t *bytes_read);

/**
 * Implemented by the developper. Seek in the source data.
 * If successful, returns 0 and sets the new position to its last
 * parameter. Otherwise, returns an error code on failure.
 */
typedef int32_t (*MlaSeekCallback)(int64_t offset, int32_t whence, void *context, uint64_t *new_pos);

typedef struct FileWriter {
  MLAWriteCallback write_callback;
  MLAFlushCallback flush_callback;
  void *context;
} FileWriter;

/**
 * Implemented by the developper
 * Return the desired `FileWriter` which is expected to be writable.
 * WARNING, The callback developper is responsible all security checks and parent path creation.
 * See `mla_roarchive_extract` documentation for how to interpret `entry_name`.
 */
typedef int32_t (*MLAFileCallBack)(void *context,
                                   const uint8_t *entry_name,
                                   uintptr_t entry_name_len,
                                   struct FileWriter *file_writer);

/**
 * Structure for MLA archive info
 */
typedef struct ArchiveInfo {
  uint32_t version;
  uint8_t is_encryption_enabled;
} ArchiveInfo;

/**
 * Create a new configuration with encryption and signature and
 * return a handle to it.
 *
 * See rust doc for `ArchiveWriterConfig::with_encryption_with_signature` for more info.
 *
 * `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
 *
 * `public_keys_pointers` is an array of pointers to public keys null terminated strings in MLA key format.
 */
MLAStatus create_mla_writer_config_with_encryption_with_signature(MLAWriterConfigHandle *handle_out,
                                                                  const char *const *private_keys_pointers,
                                                                  uintptr_t number_of_private_keys,
                                                                  const char *const *public_keys_pointers,
                                                                  uintptr_t number_of_public_keys);

/**
 * WARNING: Will NOT sign content !
 *
 * Create a new configuration with encryption AND WITHOUT SIGNATURE and
 * return a handle to it.
 *
 * See rust doc for `ArchiveWriterConfig::with_encryption_without_signature` for more info.
 *
 * `public_keys_pointers` is an array of pointers to public keys null terminated strings in MLA key format.
 */
MLAStatus create_mla_writer_config_with_encryption_without_signature(MLAWriterConfigHandle *handle_out,
                                                                     const char *const *public_keys_pointers,
                                                                     uintptr_t number_of_public_keys);

/**
 * WARNING: Will NOT encrypt content !
 *
 * Create a new configuration with signature AND WITHOUT ENCRYPTION and
 * return a handle to it.
 *
 * See rust doc for `ArchiveWriterConfig::without_encryption_with_signature` for more info.
 *
 * `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
 */
MLAStatus create_mla_writer_config_without_encryption_with_signature(MLAWriterConfigHandle *handle_out,
                                                                     const char *const *private_keys_pointers,
                                                                     uintptr_t number_of_private_keys);

/**
 * WARNING: Will NOT encrypt content and will NOT sign content !
 *
 * Create a new configuration WITHOUT ENCRYPTION and WITHOUT SIGNATURE and
 * return a handle to it.
 *
 * See rust doc for `ArchiveWriterConfig::without_encryption_without_signature_verification` for more info.
 */
MLAStatus create_mla_writer_config_without_encryption_without_signature(MLAWriterConfigHandle *handle_out);

/**
 * Change handle to same config with given compression level
 * Currently this level can only be an integer N with 0 <= N <= 11,
 * and bigger values cause denser but slower compression.
 * Previous handle value becomes invalid after this call.
 */
MLAStatus mla_writer_config_with_compression_level(MLAWriterConfigHandle *handle_inout,
                                                   uint32_t level);

/**
 * Change handle to same config without compression.
 * Previous handle value becomes invalid after this call.
 */
MLAStatus mla_writer_config_without_compression(MLAWriterConfigHandle *handle_inout);

/**
 * Create a new configuration with encryption and signature and
 * return a handle to it.
 *
 * See rust doc for `ArchiveReaderConfig::with_signature` and `IncompleteArchiveReaderConfig::with_encryption` for more info.
 *
 * `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
 *
 * `public_keys_pointers` is an array of pointers to public keys null terminated strings in MLA key format.
 */
MLAStatus create_mla_reader_config_with_encryption_with_signature_verification(MLAReaderConfigHandle *handle_out,
                                                                               const char *const *private_keys_pointers,
                                                                               uintptr_t number_of_private_keys,
                                                                               const char *const *public_keys_pointers,
                                                                               uintptr_t number_of_public_keys);

/**
 * WARNING: This will accept reading unencrypted archives !
 *
 * Create a new configuration with signature and EVENTUALLY encryption and
 * return a handle to it.
 *
 * See rust doc for `ArchiveReaderConfig::with_signature` and `IncompleteArchiveReaderConfig::with_encryption_accept_unencrypted` for more info.
 *
 * `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
 *
 * `public_keys_pointers` is an array of pointers to public keys null terminated strings in MLA key format.
 */
MLAStatus create_mla_reader_config_with_encryption_accept_unencrypted_with_signature_verification(MLAReaderConfigHandle *handle_out,
                                                                                                  const char *const *private_keys_pointers,
                                                                                                  uintptr_t number_of_private_keys,
                                                                                                  const char *const *public_keys_pointers,
                                                                                                  uintptr_t number_of_public_keys);

/**
 * Create a new configuration with encryption but SKIPPING signature checking and
 * return a handle to it.
 *
 * See rust doc for `ArchiveReaderConfig::without_signature_verification` and `IncompleteArchiveReaderConfig::with_encryption` for more info.
 *
 * `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
 */
MLAStatus create_mla_reader_config_with_encryption_without_signature_verification(MLAReaderConfigHandle *handle_out,
                                                                                  const char *const *private_keys_pointers,
                                                                                  uintptr_t number_of_private_keys);

/**
 * WARNING: This will accept reading unencrypted and unsigned archives !
 *
 * Create a new configuration EVENTUALLY with encryption but SKIPPING signature checking and
 * return a handle to it.
 *
 * See rust doc for `ArchiveReaderConfig::without_signature_verification` and `IncompleteArchiveReaderConfig::with_encryption_accept_unencrypted` for more info.
 *
 * `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
 */
MLAStatus create_mla_reader_config_with_encryption_accept_unencrypted_without_signature_verification(MLAReaderConfigHandle *handle_out,
                                                                                                     const char *const *private_keys_pointers,
                                                                                                     uintptr_t number_of_private_keys);

/**
 * Open a new MLA archive using the given configuration, which is consumed and freed
 * (its handle cannot be reused to create another archive). The archive is streamed
 * through the write_callback, and flushed at least at the end when the last byte is
 * written. The context pointer can be used to hold any information, and is passed
 * as an argument when any of the two callbacks are called.
 */
MLAStatus mla_archive_new(MLAWriterConfigHandle *config,
                          MLAWriteCallback write_callback,
                          MLAFlushCallback flush_callback,
                          void *context,
                          MLAArchiveHandle *handle_out);

/**
 * You probably want to use `mla_archive_start_entry_with_path_as_name`.
 *
 * Starts a new entry in the archive identified by the handle returned by
 * mla_archive_new(). The given name must be a non empty array of
 * bytes of `name_size` length.
 * See documentation of rust function `EntryName::from_arbitrary_bytes`.
 * Returns MLA_STATUS_SUCCESS on success, or an error code.
 */
MLAStatus mla_archive_start_entry_with_arbitrary_bytes_name(MLAArchiveHandle archive,
                                                            const uint8_t *entry_name_arbitrary_bytes,
                                                            uintptr_t name_size,
                                                            MLAArchiveFileHandle *handle_out);

/**
 * Starts a new entry in the archive identified by the handle returned by
 * mla_archive_new(). The given name must be a unique non-empty
 * NULL-terminated string.
 * The given `entry_name` is meant to represent a path and must
 * respect rules documented in `doc/ENTRY_NAME.md`.
 * Notably, on Windows, given `entry_name` must be valid slash separated UTF-8.
 * See documentation of rust function `EntryName::from_path`.
 * Returns MLA_STATUS_SUCCESS on success, or an error code.
 */
MLAStatus mla_archive_start_entry_with_path_as_name(MLAArchiveHandle archive,
                                                    const char *entry_name,
                                                    MLAArchiveFileHandle *handle_out);

/**
 * Append data to the end of an already opened file identified by the
 * handle returned by mla_archive_start_entry_with_path_as_name(). Returns MLA_STATUS_SUCCESS on
 * success, or an error code.
 */
MLAStatus mla_archive_file_append(MLAArchiveHandle archive,
                                  MLAArchiveFileHandle file,
                                  const uint8_t *buffer,
                                  uint64_t length);

/**
 * Flush any data to be written buffered in MLA to the write_callback,
 * then calls the flush_callback given during archive initialization.
 * Returns MLA_STATUS_SUCCESS on success, or an error code.
 */
MLAStatus mla_archive_flush(MLAArchiveHandle archive);

/**
 * Close the given file, which queues its End-Of-File marker and integrity
 * checks to be written to the callback. Must be called before closing the
 * archive. The file handle must be passed as a mutable reference so it is
 * cleared and cannot be reused after free by accident. Returns
 * MLA_STATUS_SUCCESS on success, or an error code.
 */
MLAStatus mla_archive_file_close(MLAArchiveHandle archive, MLAArchiveFileHandle *file);

/**
 * Close the given archive (must only be called after all files have been
 * closed), flush the output and free any allocated resource. The archive
 * handle must be passed as a mutable reference so it is cleared and
 * cannot be reused after free by accident. Returns MLA_STATUS_SUCCESS on success,
 * or an error code.
 */
MLAStatus mla_archive_close(MLAArchiveHandle *archive);

/**
 * Open and extract an existing MLA archive, using the given configuration.
 * `read_callback` and `seek_callback` are used to read the archive data.
 * `file_callback` is used to convert each archive entry's name to `FileWriter`s.
 * WARNING, The caller is responsible of all security checks related to callback provided paths.
 * If `give_raw_name_as_arbitrary_bytes_to_file_callback` is true, then entry name's raw content (arbitrary bytes)
 * are given as argument to `file_callback`. This is dangerous, see Rust lib `EntryName::raw_content_as_bytes` documentation.
 * Else, it is given the almost arbitraty bytes (still some dangers) of `EntryName::to_pathbuf` (encoded as UTF-8 on Windows).
 * See Rust lib `EntryName::to_pathbuf` documentation.
 */
MLAStatus mla_roarchive_extract(MLAReaderConfigHandle *config,
                                MlaReadCallback read_callback,
                                MlaSeekCallback seek_callback,
                                MLAFileCallBack file_callback,
                                bool give_raw_name_as_arbitrary_bytes_to_file_callback,
                                void *context);

/**
 * Get info on an existing MLA archive
 */
MLAStatus mla_roarchive_info(MlaReadCallback read_callback,
                             void *context,
                             struct ArchiveInfo *info_out);
