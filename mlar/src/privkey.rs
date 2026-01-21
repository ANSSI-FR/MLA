use std::fs::File;
use std::io::Error;
use std::path::Path;

/// Create a file with owner only rw access.
pub fn create_private_key<P: AsRef<Path>>(p: P) -> Result<File, Error> {
    create_private_key_os(p)
}

#[cfg(target_family = "unix")]
fn create_private_key_os<P: AsRef<Path>>(p: P) -> Result<File, Error> {
    unix::create_private_file(p)
}

#[cfg(target_family = "unix")]
mod unix {
    use std::fs::{File, OpenOptions};
    use std::io::Error;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    pub fn create_private_file<P: AsRef<Path>>(p: P) -> Result<File, Error> {
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(p)
    }
}

#[cfg(target_family = "windows")]
fn create_private_key_os<P: AsRef<Path>>(p: P) -> Result<File, Error> {
    windows::create_private_file(p)
}

#[cfg(target_family = "windows")]
mod windows {
    use std::fs::File;
    use std::io::Error;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::path::Path;
    use std::ptr;
    use windows::Win32::Foundation::{GENERIC_WRITE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::PSECURITY_DESCRIPTOR;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
    };
    use windows::core::PCWSTR;

    pub fn create_private_file<P: AsRef<Path>>(p: P) -> Result<File, Error> {
        // Wrap it in a struct ensuring proper free on drop
        struct SDWrapper(PSECURITY_DESCRIPTOR);

        impl Drop for SDWrapper {
            fn drop(&mut self) {
                if !self.0.0.is_null() {
                    // SAFETY: pointer is not null
                    unsafe { LocalFree(Some(HLOCAL(self.0.0.cast()))) };
                }
            }
        }

        let filename_wide: Vec<u16> = p
            .as_ref()
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Create a SDDL disabling inheritance
        let mut sd_ptr: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(ptr::null_mut());
        // SDDL details:
        // D:          - Discretionary ACL
        // P           - Protected (no inheritance)
        // (A;;FA;;;OW) - Allow Full Access to Owner (OW)
        // OW: Owner Rights SID (S-1-3-4) exists since Windows Vista and Windows Server 2008
        create_security_descriptor_from_sddl("D:P(A;;FA;;;OW)", ptr::from_mut(&mut sd_ptr).cast())?;

        // Ensure SD is freed when going out of scope
        let _sd_wrapper = SDWrapper(sd_ptr);

        // Create SA with SDDL
        let sa = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|e| {
                Error::other(format!("Security Attributes size conversion failed: {e}"))
            })?,
            lpSecurityDescriptor: sd_ptr.0.cast(),
            bInheritHandle: false.into(),
        };

        let file = unsafe {
            // Create file with SDDL
            let handle = CreateFileW(
                PCWSTR(filename_wide.as_ptr()), // File name
                GENERIC_WRITE.0,                // Access rights
                FILE_SHARE_NONE,                // Share mode: no sharing
                Some(&raw const sa),            // Security Attributes (The ACL)
                CREATE_NEW,                     // Creation disposition (Fail if exists)
                FILE_ATTRIBUTE_NORMAL,          // Flags
                None,                           // Template file
            )?;

            // No error handling needed like in C because of the ? operator

            // Create file from handle
            File::from_raw_handle(handle.0 as RawHandle)
        };
        // Return file
        Ok(file)
    }

    // Creating a SD from SDDL, modifying sd_ptr in-place
    fn create_security_descriptor_from_sddl(
        sddl: &str,
        sd_ptr: *mut PSECURITY_DESCRIPTOR,
    ) -> Result<(), std::io::Error> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0u16)).collect();

        // SAFETY: sd_ptr points to a pointer for SECURITY_DESCRIPTOR allocation
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                sd_ptr,
                None,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::NamedTempFile;
    use std::fs;

    #[cfg(target_family = "unix")]
    #[test]
    fn create_private_key_creates_file_with_0600() {
        use std::os::unix::fs::PermissionsExt;

        let path = NamedTempFile::new("privkey_unix").unwrap();
        let file = create_private_key(&path).expect("create_private_key failed");
        drop(file);
        let meta = fs::metadata(&path).expect("metadata failed");
        let perm = meta.permissions().mode() & 0o777;
        assert_eq!(perm, 0o600);
        fs::remove_file(&path).ok();
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn create_private_key_windows_success() {
        let path = NamedTempFile::new("privkey_windows").unwrap();
        let file = create_private_key(&path).expect("create_private_key failed");
        drop(file);
        // won't check security descriptor here, just that the file was created
        assert!(path.exists());
        fs::remove_file(&path).ok();
    }
}
