/* Automatically generated with cbindgen --config cbindgen.toml (do not modify) */

#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

enum class MLAStatus : uint64_t {
  MLA_STATUS_SUCCESS = 0,
  MLA_STATUS_IO_ERROR = 65536,
  MLA_STATUS_WRONG_MAGIC = 131072,
  MLA_STATUS_UNSUPPORTED_VERSION = 196608,
  MLA_STATUS_INVALID_ECC_KEY_FORMAT = 262144,
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
  MLA_STATUS_CONFIG_ERROR_ECIES_COMPUTATION_ERROR = 1310726,
  MLA_STATUS_DUPLICATE_FILENAME = 1376256,
  MLA_STATUS_AUTHENTICATED_DECRYPTION_WRONG_TAG = 1441792,
  MLA_STATUS_HKDF_INVALID_KEY_LENGTH = 1507328,
  MLA_STATUS_CURVE25519_PARSER_ERROR = 15794176,
};

using MLAConfigHandle = void*;

/// Implemented by the developper. Takes a buffer of a certain number of bytes of MLA
/// file, and does whatever it wants with it (e.g. write it to a file, to a HTTP stream, etc.)
/// If successful, returns 0 and sets the number of bytes actually written to its last
/// parameter. Otherwise, returns an error code on failure.
using MLAWriteCallback = int32_t(*)(const uint8_t*, uint32_t, void*, uint32_t*);

/// Implemented by the developper. Should ask the underlying medium (file buffering, HTTP
/// buffering, etc.) to flush any internal buffer.
using MLAFlushCallback = int32_t(*)(void*);

using MLAArchiveHandle = void*;

using MLAArchiveFileHandle = void*;

extern "C" {

/// Create a new configuration with default options, and return a handle to it.
MLAStatus mla_config_default_new(MLAConfigHandle *handle_out);

/// Appends the given public key(s) to an existing given configuration
/// (referenced by the handle returned by mla_config_default_new()).
MLAStatus mla_config_add_public_keys(MLAConfigHandle config, const char *public_keys);

/// Sets the compression level in an existing given configuration
/// (referenced by the handle returned by mla_config_default_new()).
/// Currently this level can only be an integer N with 0 <= N <= 11,
/// and bigger values cause denser but slower compression.
MLAStatus mla_config_set_compression_level(MLAConfigHandle config, uint32_t level);

/// Open a new MLA archive using the given configuration, which is consumed and freed
/// (its handle cannot be reused to create another archive). The archive is streamed
/// through the write_callback, and flushed at least at the end when the last byte is
/// written. The context pointer can be used to hold any information, and is passed
/// as an argument when any of the two callbacks are called.
MLAStatus mla_archive_new(MLAConfigHandle *config,
                          MLAWriteCallback write_callback,
                          MLAFlushCallback flush_callback,
                          void *context,
                          MLAArchiveHandle *handle_out);

/// Open a new file in the archive identified by the handle returned by
/// mla_archive_new(). The given name must be a unique NULL-terminated string.
/// Returns MLA_STATUS_SUCCESS on success, or an error code.
MLAStatus mla_archive_file_new(MLAArchiveHandle archive,
                               const char *file_name,
                               MLAArchiveFileHandle *handle_out);

/// Append data to the end of an already opened file identified by the
/// handle returned by mla_archive_file_new(). Returns MLA_STATUS_SUCCESS on
/// success, or an error code.
MLAStatus mla_archive_file_append(MLAArchiveHandle archive,
                                  MLAArchiveFileHandle file,
                                  const uint8_t *buffer,
                                  uint64_t length);

/// Flush any data to be written buffered in MLA to the write_callback,
/// then calls the flush_callback given during archive initialization.
/// Returns MLA_STATUS_SUCCESS on success, or an error code.
MLAStatus mla_archive_flush(MLAArchiveHandle archive);

/// Close the given file, which queues its End-Of-File marker and integrity
/// checks to be written to the callback. Must be called before closing the
/// archive. The file handle must be passed as a mutable reference so it is
/// cleared and cannot be reused after free by accident. Returns
/// MLA_STATUS_SUCCESS on success, or an error code.
MLAStatus mla_archive_file_close(MLAArchiveHandle archive, MLAArchiveFileHandle *file);

/// Close the given archive (must only be called after all files have been
/// closed), flush the output and free any allocated resource. The archive
/// handle must be passed as a mutable reference so it is cleared and
/// cannot be reused after free by accident. Returns MLA_STATUS_SUCCESS on success,
/// or an error code.
MLAStatus mla_archive_close(MLAArchiveHandle *archive);

} // extern "C"
