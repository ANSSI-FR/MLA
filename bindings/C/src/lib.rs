#![allow(clippy::not_unsafe_ptr_arg_deref)]
use curve25519_parser::parse_openssl_25519_privkey;
use curve25519_parser::parse_openssl_25519_pubkeys_pem_many;
use mla::config::ArchiveReaderConfig;
use mla::config::ArchiveWriterConfig;
use mla::errors::ConfigError;
use mla::errors::Error as MLAError;
use mla::helpers::linear_extract;
use mla::ArchiveHeader;
use mla::ArchiveReader;
use mla::ArchiveWriter;
use mla::{ArchiveFileID, Layers};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::{c_void, CStr};
use std::io::{Read, Seek, Write};
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::ptr::null_mut;

// Types the caller must understand for error handling and I/O

#[repr(u64)]
pub enum MLAStatus {
    Success = 0,
    IOError = 0x010000,
    WrongMagic = 0x020000,
    UnsupportedVersion = 0x030000,
    InvalidKeyFormat = 0x040000,
    WrongBlockSubFileType = 0x050000,
    UTF8ConversionError = 0x060000,
    FilenameTooLong = 0x070000,
    WrongArchiveWriterState = 0x080000,
    AssertionError = 0x090000,
    WrongReaderState = 0x0A0000,
    WrongWriterState = 0x0B0000,
    // Keep 0x0C0000 slot, for backward compatibility
    //  InvalidCipherInit = 0x0C0000,
    RandError = 0x0D0000,
    PrivateKeyNeeded = 0x0E0000,
    DeserializationError = 0x0F0000,
    SerializationError = 0x100000,
    MissingMetadata = 0x110000,
    BadAPIArgument = 0x120000,
    EndOfStream = 0x130000,
    ConfigErrorIncoherentPersistentConfig = 0x140001,
    ConfigErrorCompressionLevelOutOfRange = 0x140002,
    ConfigErrorEncryptionKeyIsMissing = 0x140003,
    ConfigErrorPrivateKeyNotSet = 0x140004,
    ConfigErrorPrivateKeyNotFound = 0x140005,
    ConfigErrorECIESComputationError = 0x140006,
    ConfigErrorKeyCommitmentComputationError = 0x140007,
    ConfigErrorKeyCommitmentCheckingError = 0x140008,
    ConfigErrorNoRecipients = 0x140009,
    DuplicateFilename = 0x150000,
    AuthenticatedDecryptionWrongTag = 0x160000,
    HKDFInvalidKeyLength = 0x170000,
    Curve25519ParserError = 0xF10000,
}
/// Implemented by the developper. Takes a buffer of a certain number of bytes of MLA
/// file, and does whatever it wants with it (e.g. write it to a file, to a HTTP stream, etc.)
/// If successful, returns 0 and sets the number of bytes actually written to its last
/// parameter. Otherwise, returns an error code on failure.
type MLAWriteCallback = Option<
    extern "C" fn(
        buffer: *const u8,
        buffer_len: u32,
        context: *mut c_void,
        bytes_written: *mut u32,
    ) -> i32,
>;
// bindgen workaround, as Option<typedef> is gen as an opaque type
type MLAWriteCallbackRaw = extern "C" fn(
    buffer: *const u8,
    buffer_len: u32,
    context: *mut c_void,
    bytes_written: *mut u32,
) -> i32;
/// Implemented by the developper. Should ask the underlying medium (file buffering, HTTP
/// buffering, etc.) to flush any internal buffer.
pub type MLAFlushCallback = Option<extern "C" fn(context: *mut c_void) -> i32>;
// bindgen workaround, as Option<typedef> is gen as an opaque type
type MLAFlushCallbackRaw = extern "C" fn(context: *mut c_void) -> i32;

#[repr(C)]
pub struct FileWriter {
    write_callback: MLAWriteCallback,
    flush_callback: MLAFlushCallback,
    context: *mut c_void,
}
/// Implemented by the developper
/// Return the desired output path which is expected to be writable.
/// The callback developper is responsible all security checks and parent path creation.
pub type MlaFileCalback = Option<
    extern "C" fn(
        context: *mut c_void,
        filename: *const u8,
        filename_len: usize,
        file_writer: *mut FileWriter,
    ) -> i32,
>;
// bindgen workaround, as Option<typedef> is gen as an opaque type
type MlaFileCalbackRaw = extern "C" fn(
    context: *mut c_void,
    filename: *const u8,
    filename_len: usize,
    file_writer: *mut FileWriter,
) -> i32;
/// Implemented by the developper. Read between 0 and buffer_len into buffer.
/// If successful, returns 0 and sets the number of bytes actually read to its last
/// parameter. Otherwise, returns an error code on failure.
pub type MlaReadCallback = Option<
    extern "C" fn(
        buffer: *mut u8,
        buffer_len: u32,
        context: *mut c_void,
        bytes_read: *mut u32,
    ) -> i32,
>;
// bindgen workaround, as Option<typedef> is gen as an opaque type
type MlaReadCallbackRaw = extern "C" fn(
    buffer: *mut u8,
    buffer_len: u32,
    context: *mut c_void,
    bytes_read: *mut u32,
) -> i32;
/// Implemented by the developper. Seek in the source data.
/// If successful, returns 0 and sets the new position to its last
/// parameter. Otherwise, returns an error code on failure.
pub type MlaSeekCallback =
    Option<extern "C" fn(offset: i64, whence: i32, context: *mut c_void, new_pos: *mut u64) -> i32>;
// bindgen workaround, as Option<typedef> is gen as an opaque type
pub type MlaSeekCallbackRaw =
    extern "C" fn(offset: i64, whence: i32, context: *mut c_void, new_pos: *mut u64) -> i32;

impl From<MLAError> for MLAStatus {
    fn from(err: MLAError) -> Self {
        match err {
            MLAError::IOError(_) => MLAStatus::IOError,
            MLAError::WrongMagic => MLAStatus::WrongMagic,
            MLAError::UnsupportedVersion => MLAStatus::UnsupportedVersion,
            MLAError::InvalidKeyFormat => MLAStatus::InvalidKeyFormat,
            MLAError::WrongBlockSubFileType => MLAStatus::WrongBlockSubFileType,
            MLAError::UTF8ConversionError(_) => MLAStatus::UTF8ConversionError,
            MLAError::FilenameTooLong => MLAStatus::FilenameTooLong,
            MLAError::WrongArchiveWriterState {
                current_state: _,
                expected_state: _,
            } => MLAStatus::WrongArchiveWriterState,
            MLAError::AssertionError(_) => MLAStatus::AssertionError,
            MLAError::WrongReaderState(_) => MLAStatus::WrongReaderState,
            MLAError::WrongWriterState(_) => MLAStatus::WrongWriterState,
            MLAError::RandError(_) => MLAStatus::RandError,
            MLAError::PrivateKeyNeeded => MLAStatus::PrivateKeyNeeded,
            MLAError::DeserializationError => MLAStatus::DeserializationError,
            MLAError::SerializationError => MLAStatus::SerializationError,
            MLAError::MissingMetadata => MLAStatus::MissingMetadata,
            MLAError::BadAPIArgument(_) => MLAStatus::BadAPIArgument,
            MLAError::EndOfStream => MLAStatus::EndOfStream,
            MLAError::ConfigError(ConfigError::IncoherentPersistentConfig) => {
                MLAStatus::ConfigErrorIncoherentPersistentConfig
            }
            MLAError::ConfigError(ConfigError::CompressionLevelOutOfRange) => {
                MLAStatus::ConfigErrorCompressionLevelOutOfRange
            }
            MLAError::ConfigError(ConfigError::NoRecipients) => {
                MLAStatus::ConfigErrorNoRecipients
            }
            MLAError::ConfigError(ConfigError::EncryptionKeyIsMissing) => {
                MLAStatus::ConfigErrorEncryptionKeyIsMissing
            }
            MLAError::ConfigError(ConfigError::PrivateKeyNotSet) => {
                MLAStatus::ConfigErrorPrivateKeyNotSet
            }
            MLAError::ConfigError(ConfigError::PrivateKeyNotFound) => {
                MLAStatus::ConfigErrorPrivateKeyNotFound
            }
            MLAError::ConfigError(ConfigError::ECIESComputationError) => {
                MLAStatus::ConfigErrorECIESComputationError
            }
            MLAError::ConfigError(ConfigError::KeyCommitmentComputationError) => {
                MLAStatus::ConfigErrorKeyCommitmentComputationError
            }
            MLAError::ConfigError(ConfigError::KeyCommitmentCheckingError) => {
                MLAStatus::ConfigErrorKeyCommitmentCheckingError
            }
            MLAError::DuplicateFilename => MLAStatus::DuplicateFilename,
            MLAError::AuthenticatedDecryptionWrongTag => MLAStatus::AuthenticatedDecryptionWrongTag,
            MLAError::HKDFInvalidKeyLength => MLAStatus::HKDFInvalidKeyLength,
        }
    }
}

// Opaque types exposed to C callers (not *mut c_void because of
// file IDs being represented as u64, even on 32-bit systems)

pub type MLAConfigHandle = *mut c_void;
pub type MLAArchiveHandle = *mut c_void;
pub type MLAArchiveFileHandle = *mut c_void;

// Internal struct definition to create a Write-able from function pointers

struct CallbackOutput {
    write_callback: MLAWriteCallbackRaw,
    flush_callback: MLAFlushCallbackRaw,
    context: *mut c_void,
}

impl Write for CallbackOutput {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let len = match u32::try_from(buf.len()) {
            Ok(n) => n,
            _ => u32::MAX - 1, // only write the first 4GB, the callback will get called multiple times
        };
        let mut len_written: u32 = 0;
        match (self.write_callback)(
            buf.as_ptr(),
            len,
            self.context,
            &mut len_written as *mut u32,
        ) {
            0 => Ok(len_written as usize),
            e => Err(std::io::Error::from_raw_os_error(e)),
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        match (self.flush_callback)(self.context) {
            0 => Ok(()),
            e => Err(std::io::Error::from_raw_os_error(e)),
        }
    }
}

// The actual C API exposed to external callers

/// Create a new configuration with default options, and return a handle to it.
#[no_mangle]
pub extern "C" fn mla_config_default_new(handle_out: *mut MLAConfigHandle) -> MLAStatus {
    if handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let mut config = ArchiveWriterConfig::new();
    config.set_layers(Layers::DEFAULT);

    let ptr = Box::into_raw(Box::new(config));
    unsafe {
        *handle_out = ptr as MLAConfigHandle;
    }
    MLAStatus::Success
}

/// Appends the given public key(s) to an existing given configuration
/// (referenced by the handle returned by mla_config_default_new()).
#[no_mangle]
pub extern "C" fn mla_config_add_public_keys(
    config: MLAConfigHandle,
    public_keys: *const c_char,
) -> MLAStatus {
    if config.is_null() || public_keys.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let mut config = unsafe { Box::from_raw(config as *mut ArchiveWriterConfig) };

    // Create a slice from the NULL-terminated string
    let public_keys = unsafe { CStr::from_ptr(public_keys) }.to_bytes();
    // Parse as OpenSSL Ed25519 public key(s)
    let res = match parse_openssl_25519_pubkeys_pem_many(public_keys) {
        Ok(v) if !v.is_empty() => {
            config.add_public_keys(&v);
            MLAStatus::Success
        }
        _ => MLAStatus::Curve25519ParserError,
    };

    Box::leak(config);
    res
}

/// Sets the compression level in an existing given configuration
/// (referenced by the handle returned by mla_config_default_new()).
/// Currently this level can only be an integer N with 0 <= N <= 11,
/// and bigger values cause denser but slower compression.
#[no_mangle]
pub extern "C" fn mla_config_set_compression_level(
    config: MLAConfigHandle,
    level: u32,
) -> MLAStatus {
    if config.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let mut config = unsafe { Box::from_raw(config as *mut ArchiveWriterConfig) };

    let res = match config.with_compression_level(level) {
        Ok(_) => MLAStatus::Success,
        Err(e) => MLAStatus::from(MLAError::ConfigError(e)),
    };

    Box::leak(config);
    res
}

/// Create an empty ReaderConfig
#[no_mangle]
pub extern "C" fn mla_reader_config_new(handle_out: *mut MLAConfigHandle) -> MLAStatus {
    if handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let config = ArchiveReaderConfig::new();

    let ptr = Box::into_raw(Box::new(config));
    unsafe {
        *handle_out = ptr as MLAConfigHandle;
    }
    MLAStatus::Success
}

/// Appends the given private key to an existing given configuration
/// (referenced by the handle returned by mla_reader_config_new()).
#[no_mangle]
pub extern "C" fn mla_reader_config_add_private_key(
    config: MLAConfigHandle,
    private_key: *const c_char,
) -> MLAStatus {
    if config.is_null() || private_key.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let mut config = unsafe { Box::from_raw(config as *mut ArchiveReaderConfig) };
    let mut private_keys = Vec::new();

    // Create a slice from the NULL-terminated string
    let private_key = unsafe { CStr::from_ptr(private_key) }.to_bytes();
    // Parse as OpenSSL Ed25519 private key(s)
    let res = match parse_openssl_25519_privkey(private_key) {
        Ok(v) => {
            private_keys.push(v);
            config.add_private_keys(&private_keys);
            MLAStatus::Success
        }
        _ => MLAStatus::Curve25519ParserError,
    };

    Box::leak(config);
    res
}

/// Open a new MLA archive using the given configuration, which is consumed and freed
/// (its handle cannot be reused to create another archive). The archive is streamed
/// through the write_callback, and flushed at least at the end when the last byte is
/// written. The context pointer can be used to hold any information, and is passed
/// as an argument when any of the two callbacks are called.
#[no_mangle]
pub extern "C" fn mla_archive_new(
    config: *mut MLAConfigHandle,
    write_callback: MLAWriteCallback,
    flush_callback: MLAFlushCallback,
    context: *mut c_void,
    handle_out: *mut MLAArchiveHandle,
) -> MLAStatus {
    if config.is_null() || handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let write_callback = match write_callback {
        None => return MLAStatus::BadAPIArgument,
        Some(x) => x,
    };
    let flush_callback = match flush_callback {
        None => return MLAStatus::BadAPIArgument,
        Some(x) => x,
    };

    let config_ptr = unsafe { *(config as *mut *mut ArchiveWriterConfig) };
    // Avoid any use-after-free of this handle by the caller
    unsafe {
        *config = null_mut();
    }
    let config = unsafe { Box::from_raw(config_ptr) };

    let output = CallbackOutput {
        write_callback,
        flush_callback,
        context,
    };

    let mla: ArchiveWriter<CallbackOutput> = match ArchiveWriter::from_config(output, *config) {
        Ok(mla) => mla,
        Err(e) => {
            return MLAStatus::from(e);
        }
    };

    let ptr = Box::into_raw(Box::new(mla));
    unsafe {
        *handle_out = ptr as MLAArchiveHandle;
    }
    MLAStatus::Success
}

/// Open a new file in the archive identified by the handle returned by
/// mla_archive_new(). The given name must be a unique NULL-terminated string.
/// Returns MLA_STATUS_SUCCESS on success, or an error code.
#[no_mangle]
pub extern "C" fn mla_archive_file_new(
    archive: MLAArchiveHandle,
    file_name: *const c_char,
    handle_out: *mut MLAArchiveFileHandle,
) -> MLAStatus {
    if archive.is_null() || file_name.is_null() || handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }
    let file_name = unsafe { CStr::from_ptr(file_name) }.to_string_lossy();

    let mut archive = unsafe { Box::from_raw(archive as *mut ArchiveWriter<CallbackOutput>) };
    let res = match archive.start_file(&file_name) {
        Ok(fileid) => {
            let ptr = Box::into_raw(Box::new(fileid));
            unsafe {
                *handle_out = ptr as MLAArchiveFileHandle;
            }
            MLAStatus::Success
        }
        Err(e) => MLAStatus::from(e),
    };
    Box::leak(archive);
    res
}

/// Append data to the end of an already opened file identified by the
/// handle returned by mla_archive_file_new(). Returns MLA_STATUS_SUCCESS on
/// success, or an error code.
#[no_mangle]
pub extern "C" fn mla_archive_file_append(
    archive: MLAArchiveHandle,
    file: MLAArchiveFileHandle,
    buffer: *const u8,
    length: u64,
) -> MLAStatus {
    if archive.is_null() || file.is_null() || buffer.is_null() {
        return MLAStatus::BadAPIArgument;
    }
    let length_usize = match usize::try_from(length) {
        Ok(n) => n,
        Err(_) => return MLAStatus::BadAPIArgument,
    };
    let slice = unsafe { std::slice::from_raw_parts(buffer, length_usize) };

    let mut archive = unsafe { Box::from_raw(archive as *mut ArchiveWriter<CallbackOutput>) };
    let file = unsafe { Box::from_raw(file as *mut ArchiveFileID) };
    let res = match archive.append_file_content(*file, length, slice) {
        Ok(_) => MLAStatus::Success,
        Err(e) => MLAStatus::from(e),
    };
    Box::leak(archive);
    Box::leak(file);
    res
}

/// Flush any data to be written buffered in MLA to the write_callback,
/// then calls the flush_callback given during archive initialization.
/// Returns MLA_STATUS_SUCCESS on success, or an error code.
#[no_mangle]
pub extern "C" fn mla_archive_flush(archive: MLAArchiveHandle) -> MLAStatus {
    if archive.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let mut archive = unsafe { Box::from_raw(archive as *mut ArchiveWriter<CallbackOutput>) };
    let res = match archive.flush() {
        Ok(_) => MLAStatus::Success,
        Err(e) => MLAStatus::from(MLAError::IOError(e)),
    };
    Box::leak(archive);
    res
}

/// Close the given file, which queues its End-Of-File marker and integrity
/// checks to be written to the callback. Must be called before closing the
/// archive. The file handle must be passed as a mutable reference so it is
/// cleared and cannot be reused after free by accident. Returns
/// MLA_STATUS_SUCCESS on success, or an error code.
#[no_mangle]
pub extern "C" fn mla_archive_file_close(
    archive: MLAArchiveHandle,
    file: *mut MLAArchiveFileHandle,
) -> MLAStatus {
    if archive.is_null() || file.is_null() {
        return MLAStatus::BadAPIArgument;
    }
    let handle = unsafe { *file };
    if handle.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    // Avoid any use-after-free of this handle by the caller
    unsafe {
        *file = null_mut();
    }

    let mut archive = unsafe { Box::from_raw(archive as *mut ArchiveWriter<CallbackOutput>) };
    let file = unsafe { Box::from_raw(handle as *mut ArchiveFileID) };

    let res = match archive.end_file(*file) {
        Ok(_) => MLAStatus::Success,
        Err(e) => MLAStatus::from(e),
    };
    Box::leak(archive);
    res
}

/// Close the given archive (must only be called after all files have been
/// closed), flush the output and free any allocated resource. The archive
/// handle must be passed as a mutable reference so it is cleared and
/// cannot be reused after free by accident. Returns MLA_STATUS_SUCCESS on success,
/// or an error code.
#[no_mangle]
pub extern "C" fn mla_archive_close(archive: *mut MLAArchiveHandle) -> MLAStatus {
    if archive.is_null() {
        return MLAStatus::BadAPIArgument;
    }
    let handle = unsafe { *archive };
    if handle.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    // Avoid any use-after-free of this handle by the caller
    unsafe {
        *archive = null_mut();
    }

    let mut archive = unsafe { Box::from_raw(handle as *mut ArchiveWriter<CallbackOutput>) };
    match archive.finalize() {
        Ok(_) => MLAStatus::Success,
        Err(e) => MLAStatus::from(e),
    }
}

struct CallbackInputRead {
    read_callback: MlaReadCallbackRaw,
    seek_callback: Option<MlaSeekCallbackRaw>,
    context: *mut c_void,
}

impl Read for CallbackInputRead {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let len = match u32::try_from(buf.len()) {
            Ok(n) => n,
            _ => u32::MAX - 1, // only read the first 4GB, the callback will get called multiple times
        };
        let mut len_read: u32 = 0;
        match (self.read_callback)(
            buf.as_mut_ptr(),
            len,
            self.context,
            &mut len_read as *mut u32,
        ) {
            0 => Ok(len_read as usize),
            e => Err(std::io::Error::from_raw_os_error(e)),
        }
    }
}

impl Seek for CallbackInputRead {
    fn seek(&mut self, style: std::io::SeekFrom) -> Result<u64, std::io::Error> {
        let mut new_pos: u64 = 0;
        let (whence, offset) = match style {
            std::io::SeekFrom::Start(n) => (0, n as i64), // SEEK_SET
            std::io::SeekFrom::Current(n) => (1, n),      // SEEK_CUR
            std::io::SeekFrom::End(n) => (2, n),          // SEEK_END
        };
        match (self.seek_callback.unwrap())(offset, whence, self.context, &mut new_pos as *mut u64)
        {
            0 => Ok(new_pos),
            e => Err(std::io::Error::from_raw_os_error(e)),
        }
    }
}

/// Open and extract an existing MLA archive, using the given configuration.
/// read_callback and seek_callback are used to read the archive data
/// file_callback is used to convert each archive file's name to pathes where extract the data
/// The caller is responsible of all security checks related to callback provided paths
#[no_mangle]
pub extern "C" fn mla_roarchive_extract(
    config: *mut MLAConfigHandle,
    read_callback: MlaReadCallback,
    seek_callback: MlaSeekCallback,
    file_callback: MlaFileCalback,
    context: *mut c_void,
) -> MLAStatus {
    if config.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let read_callback = match read_callback {
        None => return MLAStatus::BadAPIArgument,
        Some(x) => x,
    };
    let seek_callback = match seek_callback {
        None => return MLAStatus::BadAPIArgument,
        Some(x) => x,
    };
    let file_callback = match file_callback {
        None => return MLAStatus::BadAPIArgument,
        Some(x) => x,
    };

    let reader = CallbackInputRead {
        read_callback,
        seek_callback: Some(seek_callback),
        context,
    };
    _mla_roarchive_extract(config, reader, file_callback, context)
}

#[allow(clippy::extra_unused_lifetimes)]
fn _mla_roarchive_extract<'a, R: Read + Seek + 'a>(
    config: *mut MLAConfigHandle,
    src: R,
    file_callback: MlaFileCalbackRaw,
    context: *mut c_void,
) -> MLAStatus {
    let config_ptr = unsafe { *(config as *mut *mut ArchiveReaderConfig) };
    // Avoid any use-after-free of this handle by the caller
    unsafe {
        *config = null_mut();
    }
    let config = unsafe { Box::from_raw(config_ptr) };

    let mut mla: ArchiveReader<'a, R> = match ArchiveReader::from_config(src, *config) {
        Ok(mla) => mla,
        Err(e) => {
            return MLAStatus::from(e);
        }
    };

    let mut iter: Vec<String> = match mla.list_files() {
        Ok(v) => v.cloned().collect(),
        Err(_) => return MLAStatus::BadAPIArgument,
    };
    iter.sort();

    let mut export: HashMap<&String, CallbackOutput> = HashMap::new();
    for fname in &iter {
        let mut file_writer: MaybeUninit<FileWriter> = MaybeUninit::uninit();
        match (file_callback)(
            context,
            fname.as_ptr(),
            fname.len(),
            file_writer.as_mut_ptr(),
        ) {
            0 => {
                let file_writer = unsafe { file_writer.assume_init() };
                export.insert(
                    fname,
                    CallbackOutput {
                        write_callback: match file_writer.write_callback {
                            // Rust FFI garantees Option<x> as equal to x
                            Some(x) => x,
                            None => return MLAStatus::BadAPIArgument,
                        },
                        flush_callback: match file_writer.flush_callback {
                            // Rust FFI garantees Option<x> as equal to x
                            Some(x) => x,
                            None => return MLAStatus::BadAPIArgument,
                        },
                        context: file_writer.context,
                    },
                );
            }
            _ => continue,
        };
    }
    match linear_extract(&mut mla, &mut export) {
        Ok(()) => MLAStatus::Success,
        Err(e) => MLAStatus::from(e),
    }
}

/// Structure for MLA archive info
#[repr(C)]
pub struct ArchiveInfo {
    version: u32,
    layers: u8,
}

/// Get info on an existing MLA archive
#[no_mangle]
pub extern "C" fn mla_roarchive_info(
    read_callback: MlaReadCallback,
    context: *mut c_void,
    info_out: *mut ArchiveInfo,
) -> MLAStatus {
    if info_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }
    let read_callback = match read_callback {
        None => return MLAStatus::BadAPIArgument,
        Some(x) => x,
    };

    let mut reader = CallbackInputRead {
        read_callback,
        seek_callback: None,
        context,
    };
    _mla_roarchive_info(&mut reader, info_out)
}

fn _mla_roarchive_info<R: Read>(src: &mut R, info_out: *mut ArchiveInfo) -> MLAStatus {
    let header = match ArchiveHeader::from(src) {
        Ok(header) => header,
        Err(e) => return MLAStatus::from(e),
    };
    let layers = header.config.layers_enabled;

    unsafe {
        (*info_out).version = header.format_version;
        (*info_out).layers = layers.bits();
    }
    MLAStatus::Success
}
