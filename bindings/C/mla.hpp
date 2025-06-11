/* Automatically generated with cbindgen --config cbindgen_cpp.toml (do not modify) */

#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

constexpr static const uint8_t ENCRYPT = 1;

constexpr static const uint8_t COMPRESS = 2;

enum class MLAStatus : uint64_t {
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
  MLA_STATUS_MLA_KEY_PARSER_ERROR = 15859712,
};

using MLAWriterConfigHandle = void*;

using MLAReaderConfigHandle = void*;

/// Implemented by the developper. Takes a buffer of a certain number of bytes of MLA
/// file, and does whatever it wants with it (e.g. write it to a file, to a HTTP stream, etc.)
/// If successful, returns 0 and sets the number of bytes actually written to its last
/// parameter. Otherwise, returns an error code on failure.
using MLAWriteCallback = int32_t(*)(const uint8_t *buffer,
                                    uint32_t buffer_len,
                                    void *context,
                                    uint32_t *bytes_written);

/// Implemented by the developper. Should ask the underlying medium (file buffering, HTTP
/// buffering, etc.) to flush any internal buffer.
using MLAFlushCallback = int32_t(*)(void *context);

using MLAArchiveHandle = void*;

using MLAArchiveFileHandle = void*;

/// Implemented by the developper. Read between 0 and buffer_len into buffer.
/// If successful, returns 0 and sets the number of bytes actually read to its last
/// parameter. Otherwise, returns an error code on failure.
using MlaReadCallback = int32_t(*)(uint8_t *buffer,
                                   uint32_t buffer_len,
                                   void *context,
                                   uint32_t *bytes_read);

/// Implemented by the developper. Seek in the source data.
/// If successful, returns 0 and sets the new position to its last
/// parameter. Otherwise, returns an error code on failure.
using MlaSeekCallback = int32_t(*)(int64_t offset, int32_t whence, void *context, uint64_t *new_pos);

struct FileWriter {
  MLAWriteCallback write_callback;
  MLAFlushCallback flush_callback;
  void *context;
};

/// Implemented by the developper
/// Return the desired output path which is expected to be writable.
/// The callback developper is responsible all security checks and parent path creation.
using MLAFileCallBack = int32_t(*)(void *context,
                                   const uint8_t *filename,
                                   uintptr_t filename_len,
                                   FileWriter *file_writer);

/// Structure for MLA archive info
struct ArchiveInfo {
  uint32_t version;
  uint8_t layers;
};

extern "C" {

/// Create a new configuration with the given public key(s) in DER format and
/// return a handle to it
/// `public_keys_pointers` is an array of pointers to public keys in DER format
MLAStatus create_mla_writer_config_with_public_keys_der(MLAWriterConfigHandle *handle_out,
                                                        const uint8_t *const *public_keys_pointers,
                                                        uintptr_t number_of_public_keys);

/// Create a new configuration with the given public key(s) in PEM format and
/// return a handle to it
/// `public_keys` is a C string containing concatenated PEM public keys
MLAStatus create_mla_writer_config_with_public_keys_pem(MLAWriterConfigHandle *handle_out,
                                                        const char *public_keys);

/// Create a new configuration without encryption and return a handle to it
MLAStatus create_mla_writer_config_without_encryption(MLAWriterConfigHandle *handle_out);

/// Change handle to same config with given compression level
/// Currently this level can only be an integer N with 0 <= N <= 11,
/// and bigger values cause denser but slower compression.
/// Previous handle value becomes invalid after this call.
MLAStatus mla_writer_config_with_compression_level(MLAWriterConfigHandle *handle_inout,
                                                   uint32_t level);

/// Change handle to same config without compression.
/// Previous handle value becomes invalid after this call.
MLAStatus mla_writer_config_without_compression(MLAWriterConfigHandle *handle_inout);

MLAStatus create_mla_reader_config_without_encryption(MLAReaderConfigHandle *handle_out);

/// Appends the given private key in DER format to an existing given configuration
/// (referenced by the handle returned by mla_reader_config_new()).
MLAStatus create_mla_reader_config_with_private_keys_der(MLAReaderConfigHandle *handle_out,
                                                         const uint8_t *const *private_keys_pointers,
                                                         uintptr_t number_of_private_keys);

/// Appends the given private key in DER format to an existing given configuration
/// (referenced by the handle returned by mla_reader_config_new()).
MLAStatus create_mla_reader_config_with_private_keys_der_accept_unencrypted(MLAReaderConfigHandle *handle_out,
                                                                            const uint8_t *const *private_keys_pointers,
                                                                            uintptr_t number_of_private_keys);

/// Appends the given private key in PEM format to an existing given configuration
/// (referenced by the handle returned by mla_reader_config_new()).
MLAStatus create_mla_reader_config_with_private_key_pem_many(MLAReaderConfigHandle *handle_out,
                                                             const char *private_key_pem);

MLAStatus create_mla_reader_config_with_private_key_pem_many_accept_unencrypted(MLAReaderConfigHandle *handle_out,
                                                                                const char *private_key_pem);

/// Open a new MLA archive using the given configuration, which is consumed and freed
/// (its handle cannot be reused to create another archive). The archive is streamed
/// through the write_callback, and flushed at least at the end when the last byte is
/// written. The context pointer can be used to hold any information, and is passed
/// as an argument when any of the two callbacks are called.
MLAStatus mla_archive_new(MLAWriterConfigHandle *config,
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

/// Open and extract an existing MLA archive, using the given configuration.
/// read_callback and seek_callback are used to read the archive data
/// file_callback is used to convert each archive file's name to pathes where extract the data
/// The caller is responsible of all security checks related to callback provided paths
MLAStatus mla_roarchive_extract(MLAReaderConfigHandle *config,
                                MlaReadCallback read_callback,
                                MlaSeekCallback seek_callback,
                                MLAFileCallBack file_callback,
                                void *context);

/// Get info on an existing MLA archive
MLAStatus mla_roarchive_info(MlaReadCallback read_callback, void *context, ArchiveInfo *info_out);

}  // extern "C"
