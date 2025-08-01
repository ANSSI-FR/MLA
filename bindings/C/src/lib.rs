#![allow(clippy::not_unsafe_ptr_arg_deref)]
use mla::config::ArchiveReaderConfig;
use mla::config::ArchiveWriterConfig;
use mla::config::IncompleteArchiveReaderConfig;
use mla::crypto::mlakey::MLADecryptionPrivateKey;
use mla::crypto::mlakey::MLAEncryptionPublicKey;
use mla::crypto::mlakey::MLAPrivateKey;
use mla::crypto::mlakey::MLAPublicKey;
use mla::crypto::mlakey::MLASignatureVerificationPublicKey;
use mla::crypto::mlakey::MLASigningPrivateKey;
use mla::entry::ArchiveEntryId;
use mla::entry::EntryName;
use mla::errors::ConfigError;
use mla::errors::Error as MLAError;
use mla::helpers::linear_extract;
use mla::ArchiveReader;
use mla::ArchiveWriter;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::ffi::{c_void, CStr};
use std::io::{Read, Seek, Write};
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::path::Path;
use std::ptr::null_mut;
use std::slice;

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
    // Keep 0x0C0000 slot for backward compatibility
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
    ConfigErrorDHKEMComputationError = 0x140006,
    ConfigErrorKeyCommitmentComputationError = 0x140007,
    ConfigErrorKeyCommitmentCheckingError = 0x140008,
    ConfigErrorNoRecipients = 0x140009,
    ConfigErrorMLKEMComputationError = 0x14000A,
    ConfigErrorKeyWrappingComputationError = 0x14000B,
    DuplicateFilename = 0x150000,
    AuthenticatedDecryptionWrongTag = 0x160000,
    HKDFInvalidKeyLength = 0x170000,
    HPKEError = 0x18000,
    InvalidLastTag = 0x19000,
    EncryptionAskedButNotMarkedPresent = 0x180000,
    WrongEndMagic = 0x190000,
    NoValidSignatureFound = 0x200000,
    SignatureVerificationAskedButNoSignatureLayerFound = 0x210000,
    MissingEndOfEncryptedInnerLayerMagic = 0x220000,
    TruncatedTag = 0x230000,
    UnknownTagPosition = 0x240000,
    // Keep 0xF10000 slot for backward compatibility
    // Curve25519ParserError = 0xF10000,
    MlaKeyParserError = 0xF20000,
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
/// Return the desired `FileWriter` which is expected to be writable.
/// WARNING, The callback developper is responsible all security checks and parent path creation.
/// See `mla_roarchive_extract` documentation for how to interpret `entry_name`.
pub type MLAFileCallBack = Option<
    extern "C" fn(
        context: *mut c_void,
        entry_name: *const u8,
        entry_name_len: usize,
        file_writer: *mut FileWriter,
    ) -> i32,
>;
// bindgen workaround, as Option<typedef> is gen as an opaque type
type MLAFileCallBackRaw = extern "C" fn(
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
            MLAError::RandError => MLAStatus::RandError,
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
            MLAError::ConfigError(ConfigError::NoRecipients) => MLAStatus::ConfigErrorNoRecipients,
            MLAError::ConfigError(ConfigError::EncryptionKeyIsMissing) => {
                MLAStatus::ConfigErrorEncryptionKeyIsMissing
            }
            MLAError::ConfigError(ConfigError::PrivateKeyNotSet) => {
                MLAStatus::ConfigErrorPrivateKeyNotSet
            }
            MLAError::ConfigError(ConfigError::PrivateKeyNotFound) => {
                MLAStatus::ConfigErrorPrivateKeyNotFound
            }
            MLAError::ConfigError(ConfigError::DHKEMComputationError) => {
                MLAStatus::ConfigErrorDHKEMComputationError
            }
            MLAError::ConfigError(ConfigError::KeyCommitmentComputationError) => {
                MLAStatus::ConfigErrorKeyCommitmentComputationError
            }
            MLAError::ConfigError(ConfigError::KeyCommitmentCheckingError) => {
                MLAStatus::ConfigErrorKeyCommitmentCheckingError
            }
            MLAError::ConfigError(ConfigError::MLKEMComputationError) => {
                MLAStatus::ConfigErrorMLKEMComputationError
            }
            MLAError::ConfigError(ConfigError::KeyWrappingComputationError) => {
                MLAStatus::ConfigErrorKeyWrappingComputationError
            }
            MLAError::DuplicateFilename => MLAStatus::DuplicateFilename,
            MLAError::AuthenticatedDecryptionWrongTag => MLAStatus::AuthenticatedDecryptionWrongTag,
            MLAError::HKDFInvalidKeyLength => MLAStatus::HKDFInvalidKeyLength,
            MLAError::HPKEError => MLAStatus::HPKEError,
            MLAError::InvalidLastTag => MLAStatus::InvalidLastTag,
            MLAError::EncryptionAskedButNotMarkedPresent => {
                MLAStatus::EncryptionAskedButNotMarkedPresent
            }
            MLAError::WrongEndMagic => MLAStatus::WrongEndMagic,
            MLAError::NoValidSignatureFound => MLAStatus::NoValidSignatureFound,
            MLAError::SignatureVerificationAskedButNoSignatureLayerFound => {
                MLAStatus::SignatureVerificationAskedButNoSignatureLayerFound
            }
            MLAError::MissingEndOfEncryptedInnerLayerMagic => {
                MLAStatus::MissingEndOfEncryptedInnerLayerMagic
            }
            MLAError::TruncatedTag => MLAStatus::TruncatedTag,
            MLAError::UnknownTagPosition => MLAStatus::UnknownTagPosition,
        }
    }
}

// Opaque types exposed to C callers (not *mut c_void because of
// file IDs being represented as u64, even on 32-bit systems)

pub type MLAWriterConfigHandle = *mut c_void;
pub type MLAReaderConfigHandle = *mut c_void;
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

trait Key {
    type TYPE1;
    type TYPE2;
    fn deserialize_key(src: impl Read) -> Result<Self, MLAError>
    where
        Self: std::marker::Sized;
    fn get_keys(self) -> (Self::TYPE1, Self::TYPE2);
}

impl Key for MLAPrivateKey {
    type TYPE1 = MLADecryptionPrivateKey;
    type TYPE2 = MLASigningPrivateKey;

    fn deserialize_key(src: impl Read) -> Result<Self, MLAError> {
        Self::deserialize_private_key(src)
    }

    fn get_keys(self) -> (Self::TYPE1, Self::TYPE2) {
        self.get_private_keys()
    }
}

impl Key for MLAPublicKey {
    type TYPE1 = MLAEncryptionPublicKey;
    type TYPE2 = MLASignatureVerificationPublicKey;
    fn deserialize_key(src: impl Read) -> Result<Self, MLAError> {
        Self::deserialize_public_key(src)
    }

    fn get_keys(self) -> (Self::TYPE1, Self::TYPE2) {
        self.get_public_keys()
    }
}

#[allow(clippy::type_complexity)]
unsafe fn keys_from_pointers<K>(
    keys_pointers: *const *const c_char,
    number_of_keys: usize,
) -> Result<(Vec<K::TYPE1>, Vec<K::TYPE2>), MLAStatus>
where
    K: Key,
{
    if keys_pointers.is_null() || number_of_keys == 0 {
        return Err(MLAStatus::BadAPIArgument);
    }

    let keys_pointers = unsafe { std::slice::from_raw_parts(keys_pointers, number_of_keys) };

    let keys = keys_pointers
        .iter()
        .map(|pointer| {
            if pointer.is_null() {
                Err(MLAStatus::BadAPIArgument)
            } else {
                let key_bytes = unsafe { CStr::from_ptr(*pointer) }.to_bytes();
                K::deserialize_key(key_bytes).map_err(|_| MLAStatus::MlaKeyParserError)
            }
        })
        .collect::<Result<Vec<_>, MLAStatus>>()?;
    Ok(keys.into_iter().map(|k| k.get_keys()).unzip())
}

// The actual C API exposed to external callers

/// Create a new configuration with encryption and signature and
/// return a handle to it.
///
/// See rust doc for `ArchiveWriterConfig::with_encryption_with_signature` for more info.
///
/// `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
///
/// `public_keys_pointers` is an array of pointers to public keys null terminated strings in MLA key format.
#[no_mangle]
pub extern "C" fn create_mla_writer_config_with_encryption_with_signature(
    handle_out: *mut MLAWriterConfigHandle,
    private_keys_pointers: *const *const c_char,
    number_of_private_keys: usize,
    public_keys_pointers: *const *const c_char,
    number_of_public_keys: usize,
) -> MLAStatus {
    if handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let (_private_decryption_keys, private_signing_keys) = match unsafe {
        keys_from_pointers::<MLAPrivateKey>(private_keys_pointers, number_of_private_keys)
    } {
        Ok(private_key_pair) => private_key_pair,
        Err(e) => return e,
    };

    let (public_encryption_keys, _public_signature_verification_keys) = match unsafe {
        keys_from_pointers::<MLAPublicKey>(public_keys_pointers, number_of_public_keys)
    } {
        Ok(public_key_pair) => public_key_pair,
        Err(e) => return e,
    };

    let config = ArchiveWriterConfig::with_encryption_with_signature(
        &public_encryption_keys,
        &private_signing_keys,
    );

    let ptr = Box::into_raw(Box::new(config));
    unsafe {
        *handle_out = ptr as MLAWriterConfigHandle;
    }
    MLAStatus::Success
}

/// WARNING: Will NOT sign content !
///
/// Create a new configuration with encryption AND WITHOUT SIGNATURE and
/// return a handle to it.
///
/// See rust doc for `ArchiveWriterConfig::with_encryption_without_signature` for more info.
///
/// `public_keys_pointers` is an array of pointers to public keys null terminated strings in MLA key format.
#[no_mangle]
pub extern "C" fn create_mla_writer_config_with_encryption_without_signature(
    handle_out: *mut MLAWriterConfigHandle,
    public_keys_pointers: *const *const c_char,
    number_of_public_keys: usize,
) -> MLAStatus {
    if handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let (public_encryption_keys, _public_signature_verification_keys) = match unsafe {
        keys_from_pointers::<MLAPublicKey>(public_keys_pointers, number_of_public_keys)
    } {
        Ok(public_key_pair) => public_key_pair,
        Err(e) => return e,
    };

    let config = ArchiveWriterConfig::with_encryption_without_signature(&public_encryption_keys);

    let ptr = Box::into_raw(Box::new(config));
    unsafe {
        *handle_out = ptr as MLAWriterConfigHandle;
    }
    MLAStatus::Success
}

/// WARNING: Will NOT encrypt content !
///
/// Create a new configuration with signature AND WITHOUT ENCRYPTION and
/// return a handle to it.
///
/// See rust doc for `ArchiveWriterConfig::without_encryption_with_signature` for more info.
///
/// `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
#[no_mangle]
pub extern "C" fn create_mla_writer_config_without_encryption_with_signature(
    handle_out: *mut MLAWriterConfigHandle,
    private_keys_pointers: *const *const c_char,
    number_of_private_keys: usize,
) -> MLAStatus {
    if handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let (_private_decryption_keys, private_signing_keys) = match unsafe {
        keys_from_pointers::<MLAPrivateKey>(private_keys_pointers, number_of_private_keys)
    } {
        Ok(private_key_pair) => private_key_pair,
        Err(e) => return e,
    };

    let config = ArchiveWriterConfig::without_encryption_with_signature(&private_signing_keys);

    let ptr = Box::into_raw(Box::new(config));
    unsafe {
        *handle_out = ptr as MLAWriterConfigHandle;
    }
    MLAStatus::Success
}

/// WARNING: Will NOT encrypt content and will NOT sign content !
///
/// Create a new configuration WITHOUT ENCRYPTION and WITHOUT SIGNATURE and
/// return a handle to it.
///
/// See rust doc for `ArchiveWriterConfig::without_encryption_without_signature_verification` for more info.
#[no_mangle]
pub extern "C" fn create_mla_writer_config_without_encryption_without_signature(
    handle_out: *mut MLAWriterConfigHandle,
) -> MLAStatus {
    if handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let config = ArchiveWriterConfig::without_encryption_without_signature();

    let ptr = Box::into_raw(Box::new(config));
    unsafe {
        *handle_out = ptr as MLAWriterConfigHandle;
    }
    MLAStatus::Success
}

/// Change handle to same config with given compression level
/// Currently this level can only be an integer N with 0 <= N <= 11,
/// and bigger values cause denser but slower compression.
/// Previous handle value becomes invalid after this call.
#[no_mangle]
pub extern "C" fn mla_writer_config_with_compression_level(
    handle_inout: *mut MLAWriterConfigHandle,
    level: u32,
) -> MLAStatus {
    if handle_inout.is_null() {
        return MLAStatus::BadAPIArgument;
    }
    let handle_in_ptr = unsafe { *(handle_inout as *mut *mut ArchiveWriterConfig) };
    // Avoid any use-after-free of this handle by the caller if with_compression_level fails
    unsafe {
        *handle_inout = null_mut();
    }
    let in_config = unsafe { Box::from_raw(handle_in_ptr) };
    match in_config.with_compression_level(level) {
        Ok(out_config) => {
            let ptr = Box::into_raw(Box::new(out_config));
            unsafe {
                *handle_inout = ptr as MLAWriterConfigHandle;
            }
            MLAStatus::Success
        }
        Err(e) => MLAStatus::from(MLAError::ConfigError(e)),
    }
}

/// Change handle to same config without compression.
/// Previous handle value becomes invalid after this call.
#[no_mangle]
pub extern "C" fn mla_writer_config_without_compression(
    handle_inout: *mut MLAWriterConfigHandle,
) -> MLAStatus {
    if handle_inout.is_null() {
        return MLAStatus::BadAPIArgument;
    }
    let handle_in_ptr = unsafe { *(handle_inout as *mut *mut ArchiveWriterConfig) };
    let in_config = unsafe { Box::from_raw(handle_in_ptr) };
    let out_config = in_config.without_compression();

    let ptr = Box::into_raw(Box::new(out_config));
    unsafe {
        *handle_inout = ptr as MLAWriterConfigHandle;
    }
    MLAStatus::Success
}

/// Create a new configuration with encryption and signature and
/// return a handle to it.
///
/// See rust doc for `ArchiveReaderConfig::with_signature` and `IncompleteArchiveReaderConfig::with_encryption` for more info.
///
/// `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
///
/// `public_keys_pointers` is an array of pointers to public keys null terminated strings in MLA key format.
#[no_mangle]
pub extern "C" fn create_mla_reader_config_with_encryption_with_signature_verification(
    handle_out: *mut MLAReaderConfigHandle,
    private_keys_pointers: *const *const c_char,
    number_of_private_keys: usize,
    public_keys_pointers: *const *const c_char,
    number_of_public_keys: usize,
) -> MLAStatus {
    create_mla_reader_config_with_encryption_generic_with_signature_verification(
        handle_out,
        private_keys_pointers,
        number_of_private_keys,
        public_keys_pointers,
        number_of_public_keys,
        IncompleteArchiveReaderConfig::with_encryption,
    )
}

/// WARNING: This will accept reading unencrypted archives !
///
/// Create a new configuration with signature and EVENTUALLY encryption and
/// return a handle to it.
///
/// See rust doc for `ArchiveReaderConfig::with_signature` and `IncompleteArchiveReaderConfig::with_encryption_accept_unencrypted` for more info.
///
/// `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
///
/// `public_keys_pointers` is an array of pointers to public keys null terminated strings in MLA key format.
#[no_mangle]
pub extern "C" fn create_mla_reader_config_with_encryption_accept_unencrypted_with_signature_verification(
    handle_out: *mut MLAReaderConfigHandle,
    private_keys_pointers: *const *const c_char,
    number_of_private_keys: usize,
    public_keys_pointers: *const *const c_char,
    number_of_public_keys: usize,
) -> MLAStatus {
    create_mla_reader_config_with_encryption_generic_with_signature_verification(
        handle_out,
        private_keys_pointers,
        number_of_private_keys,
        public_keys_pointers,
        number_of_public_keys,
        IncompleteArchiveReaderConfig::with_encryption_accept_unencrypted,
    )
}

fn create_mla_reader_config_with_encryption_generic_with_signature_verification<F>(
    handle_out: *mut MLAReaderConfigHandle,
    private_keys_pointers: *const *const c_char,
    number_of_private_keys: usize,
    public_keys_pointers: *const *const c_char,
    number_of_public_keys: usize,
    f: F,
) -> MLAStatus
where
    F: FnOnce(IncompleteArchiveReaderConfig, &[MLADecryptionPrivateKey]) -> ArchiveReaderConfig,
{
    if handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let (_public_encryption_keys, public_signature_verification_keys) = match unsafe {
        keys_from_pointers::<MLAPublicKey>(public_keys_pointers, number_of_public_keys)
    } {
        Ok(public_key_pair) => public_key_pair,
        Err(e) => return e,
    };

    let incomplete_config =
        ArchiveReaderConfig::with_signature_verification(&public_signature_verification_keys);

    let (private_decryption_keys, _private_signing_keys) = match unsafe {
        keys_from_pointers::<MLAPrivateKey>(private_keys_pointers, number_of_private_keys)
    } {
        Ok(private_key_pair) => private_key_pair,
        Err(e) => return e,
    };

    let config = f(incomplete_config, &private_decryption_keys);

    let ptr = Box::into_raw(Box::new(config));
    unsafe {
        *handle_out = ptr as MLAReaderConfigHandle;
    }
    MLAStatus::Success
}

/// Create a new configuration with encryption but SKIPPING signature checking and
/// return a handle to it.
///
/// See rust doc for `ArchiveReaderConfig::without_signature_verification` and `IncompleteArchiveReaderConfig::with_encryption` for more info.
///
/// `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
#[no_mangle]
pub extern "C" fn create_mla_reader_config_with_encryption_without_signature_verification(
    handle_out: *mut MLAReaderConfigHandle,
    private_keys_pointers: *const *const c_char,
    number_of_private_keys: usize,
) -> MLAStatus {
    create_mla_reader_config_with_encryption_generic_without_signature_verification(
        handle_out,
        private_keys_pointers,
        number_of_private_keys,
        IncompleteArchiveReaderConfig::with_encryption,
    )
}

/// WARNING: This will accept reading unencrypted and unsigned archives !
///
/// Create a new configuration EVENTUALLY with encryption but SKIPPING signature checking and
/// return a handle to it.
///
/// See rust doc for `ArchiveReaderConfig::without_signature_verification` and `IncompleteArchiveReaderConfig::with_encryption_accept_unencrypted` for more info.
///
/// `private_keys_pointers` is an array of pointers to private keys null terminated strings in MLA key format.
#[no_mangle]
pub extern "C" fn create_mla_reader_config_with_encryption_accept_unencrypted_without_signature_verification(
    handle_out: *mut MLAReaderConfigHandle,
    private_keys_pointers: *const *const c_char,
    number_of_private_keys: usize,
) -> MLAStatus {
    create_mla_reader_config_with_encryption_generic_without_signature_verification(
        handle_out,
        private_keys_pointers,
        number_of_private_keys,
        IncompleteArchiveReaderConfig::with_encryption_accept_unencrypted,
    )
}

fn create_mla_reader_config_with_encryption_generic_without_signature_verification<F>(
    handle_out: *mut MLAReaderConfigHandle,
    private_keys_pointers: *const *const c_char,
    number_of_private_keys: usize,
    f: F,
) -> MLAStatus
where
    F: FnOnce(IncompleteArchiveReaderConfig, &[MLADecryptionPrivateKey]) -> ArchiveReaderConfig,
{
    if handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let incomplete_config = ArchiveReaderConfig::without_signature_verification();

    let (private_decryption_keys, _private_signing_keys) = match unsafe {
        keys_from_pointers::<MLAPrivateKey>(private_keys_pointers, number_of_private_keys)
    } {
        Ok(private_key_pair) => private_key_pair,
        Err(e) => return e,
    };

    let config = f(incomplete_config, &private_decryption_keys);

    let ptr = Box::into_raw(Box::new(config));
    unsafe {
        *handle_out = ptr as MLAReaderConfigHandle;
    }
    MLAStatus::Success
}

/// Will NOT accept encrypted archives.
///
/// Create a new configuration WITHOUT encryption and with signature and
/// return a handle to it.
///
/// See rust doc for `ArchiveReaderConfig::with_signature_verification` and `IncompleteArchiveReaderConfig::without_encryption` for more info.
///
/// `pubc_keys_pointers` is an array of pointers to public keys null terminated strings in MLA key format.
pub fn create_mla_reader_config_without_encryption_with_signature_verification(
    handle_out: *mut MLAReaderConfigHandle,
    public_keys_pointers: *const *const c_char,
    number_of_public_keys: usize,
) -> MLAStatus {
    if handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let (_public_encryption_keys, public_signature_verification_keys) = match unsafe {
        keys_from_pointers::<MLAPublicKey>(public_keys_pointers, number_of_public_keys)
    } {
        Ok(public_key_pair) => public_key_pair,
        Err(e) => return e,
    };

    let incomplete_config =
        ArchiveReaderConfig::with_signature_verification(&public_signature_verification_keys);

    let config = incomplete_config.without_encryption();

    let ptr = Box::into_raw(Box::new(config));
    unsafe {
        *handle_out = ptr as MLAReaderConfigHandle;
    }
    MLAStatus::Success
}

/// Will NOT accept encrypted archives and will SKIP verification.
///
/// Create a new configuration WITHOUT encryption and SKIP signature checking and
/// return a handle to it.
///
/// See rust doc for `ArchiveReaderConfig::without_signature_verification` and `IncompleteArchiveReaderConfig::without_encryption` for more info.
pub fn create_mla_reader_config_without_encryption_without_signature_verification(
    handle_out: *mut MLAReaderConfigHandle,
) -> MLAStatus {
    if handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let config = ArchiveReaderConfig::without_signature_verification().without_encryption();

    let ptr = Box::into_raw(Box::new(config));
    unsafe {
        *handle_out = ptr as MLAReaderConfigHandle;
    }
    MLAStatus::Success
}

/// Open a new MLA archive using the given configuration, which is consumed and freed
/// (its handle cannot be reused to create another archive). The archive is streamed
/// through the write_callback, and flushed at least at the end when the last byte is
/// written. The context pointer can be used to hold any information, and is passed
/// as an argument when any of the two callbacks are called.
#[no_mangle]
pub extern "C" fn mla_archive_new(
    config: *mut MLAWriterConfigHandle,
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

/// You probably want to use `mla_archive_start_entry_with_path_as_name`.
///
/// Starts a new entry in the archive identified by the handle returned by
/// mla_archive_new(). The given name must be a non empty array of
/// bytes of `name_size` length.
/// See documentation of rust function `EntryName::from_arbitrary_bytes`.
/// Returns MLA_STATUS_SUCCESS on success, or an error code.
#[no_mangle]
pub extern "C" fn mla_archive_start_entry_with_arbitrary_bytes_name(
    archive: MLAArchiveHandle,
    entry_name_arbitrary_bytes: *const u8,
    name_size: usize,
    handle_out: *mut MLAArchiveFileHandle,
) -> MLAStatus {
    if archive.is_null()
        || entry_name_arbitrary_bytes.is_null()
        || name_size < 1
        || handle_out.is_null()
    {
        return MLAStatus::BadAPIArgument;
    }
    let name_bytes: &[u8] = unsafe { slice::from_raw_parts(entry_name_arbitrary_bytes, name_size) };
    let entry_name = match EntryName::from_arbitrary_bytes(name_bytes) {
        Ok(entry_name) => entry_name,
        Err(_) => return MLAStatus::BadAPIArgument,
    };

    start_entry(archive, entry_name, handle_out)
}

fn start_entry(
    archive: MLAArchiveHandle,
    entry_name: EntryName,
    handle_out: *mut MLAArchiveFileHandle,
) -> MLAStatus {
    let mut archive = unsafe { Box::from_raw(archive as *mut ArchiveWriter<CallbackOutput>) };
    let res = match archive.start_entry(entry_name) {
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

/// Starts a new entry in the archive identified by the handle returned by
/// mla_archive_new(). The given name must be a unique non-empty
/// NULL-terminated string.
/// The given `entry_name` is meant to represent a path and must
/// respect rules documented in `doc/ENTRY_NAME.md`.
/// Notably, on Windows, given `entry_name` must be valid slash separated UTF-8.
/// See documentation of rust function `EntryName::from_path`.
/// Returns MLA_STATUS_SUCCESS on success, or an error code.
#[no_mangle]
pub extern "C" fn mla_archive_start_entry_with_path_as_name(
    archive: MLAArchiveHandle,
    entry_name: *const c_char,
    handle_out: *mut MLAArchiveFileHandle,
) -> MLAStatus {
    if archive.is_null() || entry_name.is_null() || handle_out.is_null() {
        return MLAStatus::BadAPIArgument;
    }

    let name_cstr = unsafe { CStr::from_ptr(entry_name) };
    let real_entry_name =
        match cstr_to_path_os(name_cstr).and_then(|p| EntryName::from_path(p).ok()) {
            Some(path) => path,
            None => return MLAStatus::BadAPIArgument,
        };
    start_entry(archive, real_entry_name, handle_out)
}

#[cfg(target_family = "unix")]
fn cstr_to_path_os(cstr: &CStr) -> Option<&Path> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    Some(Path::new(OsStr::from_bytes(cstr.to_bytes())))
}

#[cfg(target_family = "windows")]
fn cstr_to_path_os(cstr: &CStr) -> Option<&Path> {
    cstr.to_str().ok().map(Path::new)
}

#[cfg(target_family = "unix")]
fn path_to_bytes_os(p: &Path) -> Option<&[u8]> {
    use std::os::unix::ffi::OsStrExt;

    Some(p.as_os_str().as_bytes())
}

#[cfg(target_family = "windows")]
fn path_to_bytes_os(p: &Path) -> Option<&[u8]> {
    p.to_str().map(str::as_bytes)
}

/// Append data to the end of an already opened file identified by the
/// handle returned by mla_archive_start_entry_with_path_as_name(). Returns MLA_STATUS_SUCCESS on
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
    let file = unsafe { Box::from_raw(file as *mut ArchiveEntryId) };
    let res = match archive.append_entry_content(*file, length, slice) {
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
    let file = unsafe { Box::from_raw(handle as *mut ArchiveEntryId) };

    let res = match archive.end_entry(*file) {
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

    let archive = unsafe { Box::from_raw(handle as *mut ArchiveWriter<CallbackOutput>) };
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
/// `read_callback` and `seek_callback` are used to read the archive data.
/// `file_callback` is used to convert each archive entry's name to `FileWriter`s.
/// WARNING, The caller is responsible of all security checks related to callback provided paths.
/// If `give_raw_name_as_arbitrary_bytes_to_file_callback` is true, then entry name's raw content (arbitrary bytes)
/// are given as argument to `file_callback`. This is dangerous, see Rust lib `EntryName::raw_content_as_bytes` documentation.
/// Else, it is given the almost arbitraty bytes (still some dangers) of `EntryName::to_pathbuf` (encoded as UTF-8 on Windows).
/// See Rust lib `EntryName::to_pathbuf` documentation.
#[no_mangle]
pub extern "C" fn mla_roarchive_extract(
    config: *mut MLAReaderConfigHandle,
    read_callback: MlaReadCallback,
    seek_callback: MlaSeekCallback,
    file_callback: MLAFileCallBack,
    context: *mut c_void,
    give_raw_name_as_arbitrary_bytes_to_file_callback: bool,
    number_of_keys_with_valid_signature: *mut u32,
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
    _mla_roarchive_extract(
        config,
        reader,
        file_callback,
        give_raw_name_as_arbitrary_bytes_to_file_callback,
        context,
        number_of_keys_with_valid_signature,
    )
}

#[allow(clippy::extra_unused_lifetimes)]
fn _mla_roarchive_extract<'a, R: Read + Seek + 'a>(
    config: *mut MLAReaderConfigHandle,
    src: R,
    file_callback: MLAFileCallBackRaw,
    give_raw_name_as_arbitrary_bytes_to_file_callback: bool,
    context: *mut c_void,
    number_of_keys_with_valid_signature: *mut u32,
) -> MLAStatus {
    let config_ptr = unsafe { *(config as *mut *mut ArchiveReaderConfig) };
    // Avoid any use-after-free of this handle by the caller
    unsafe {
        *config = null_mut();
    }
    let config = unsafe { Box::from_raw(config_ptr) };

    let mut mla: ArchiveReader<'a, R> = match ArchiveReader::from_config(src, *config) {
        Ok((mla, keys_with_valid_signature)) => {
            let count = keys_with_valid_signature.len() as u32;
            unsafe {
                *number_of_keys_with_valid_signature = count;
            }
            mla
        }
        Err(e) => {
            return MLAStatus::from(e);
        }
    };

    let mut iter: Vec<EntryName> = match mla.list_entries() {
        Ok(v) => v.cloned().collect(),
        Err(_) => return MLAStatus::BadAPIArgument,
    };
    iter.sort();

    let mut export: HashMap<&EntryName, CallbackOutput> = HashMap::new();
    for entry_name in &iter {
        let mut file_writer: MaybeUninit<FileWriter> = MaybeUninit::uninit();
        let name_for_callback = if give_raw_name_as_arbitrary_bytes_to_file_callback {
            entry_name.as_arbitrary_bytes().to_vec()
        } else {
            let path = entry_name.to_pathbuf();
            match path.ok().as_deref().and_then(path_to_bytes_os) {
                Some(bytes) => bytes.to_vec(),
                None => return MLAStatus::BadAPIArgument,
            }
        };

        match (file_callback)(
            context,
            name_for_callback.as_ptr(),
            name_for_callback.len(),
            file_writer.as_mut_ptr(),
        ) {
            0 => {
                let file_writer = unsafe { file_writer.assume_init() };
                export.insert(
                    entry_name,
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
    is_encryption_enabled: u8,
    is_signature_enabled: u8,
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
    let info = match mla::info::read_info(src) {
        Ok(info) => info,
        Err(e) => return MLAStatus::from(e),
    };
    let version = info.get_format_version();
    let is_encryption_enabled = info.is_encryption_enabled();
    let is_signature_enabled = info.is_signature_enabled();

    unsafe {
        (*info_out).version = version;
        (*info_out).is_encryption_enabled = if is_encryption_enabled { 1 } else { 0 };
        (*info_out).is_signature_enabled = if is_signature_enabled { 1 } else { 0 };
    }
    MLAStatus::Success
}
