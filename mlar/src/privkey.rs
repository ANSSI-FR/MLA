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
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use windows::Win32::Foundation::GENERIC_WRITE;
    use windows::Win32::Security::SECURITY_ATTRIBUTES;
    use windows::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE,
    };
    use windows::core::PCWSTR;

    pub fn create_private_file<P: AsRef<Path>>(p: P) -> Result<File, Error> {
        // SDDL is a stable function since Windows 2000, hardcoding the Security Descriptor is reasonably safe then
        //
        // SDDL used: D:P(A;;FA;;;OW)
        // Details:
        // D:          - Discretionary ACL
        // P           - Protected (no inheritance)
        // (A;;FA;;;OW) - Allow Full Access to Owner (OW)
        // OW: Owner Rights SID (S-1-3-4) exists since Windows Vista and Windows Server 2008
        //
        // How it was generated with PowerShell:
        // $sddl = "D:P(A;;FA;;;OW)"
        // $sd  = New-Object System.Security.AccessControl.RawSecurityDescriptor $sddl
        // $bytes = New-Object byte[] $sd.BinaryLength
        // $sd.GetBinaryForm($bytes, 0)
        // Rust formatting of the byte array skipped [...]

        // Self-relative SECURITY_DESCRIPTOR for: D:P(A;;FA;;;OW)
        let sd_private_owner_full: &mut [u8; 48] = &mut [
            0x01, 0x00, 0x04, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x14, 0x00, 0xFF, 0x01, 0x1F, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03, 0x04, 0x00, 0x00, 0x00,
        ];

        let filename_wide: Vec<u16> = p
            .as_ref()
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Create SA with SDDL
        let sa = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|e| {
                Error::other(format!("Security Attributes size conversion failed: {e}"))
            })?,
            // mut pointer needed by Windows API but no modifications are done
            lpSecurityDescriptor: sd_private_owner_full.as_mut_ptr().cast(),
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
            File::from_raw_handle(handle.0)
        };
        // Return file
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_fs::NamedTempFile;
    use std::fs;

    #[cfg(target_family = "unix")]
    #[test]
    fn unix_create_private_key_with_rw_owner() {
        use std::os::unix::fs::PermissionsExt;

        let path = NamedTempFile::new("privkey_unix").unwrap();
        create_private_key(&path).expect("create_private_key failed");
        let meta = fs::metadata(&path).expect("metadata failed");
        let perm = meta.permissions().mode() & 0o777;
        assert_eq!(perm, 0o600);
        fs::remove_file(&path).ok();
    }

    #[cfg(target_family = "windows")]
    #[test]
    fn windows_create_private_key_with_rw_owner() {
        use std::fs::OpenOptions;

        let path = NamedTempFile::new("privkey_windows").unwrap();
        let file = create_private_key(&path).expect("create_private_key failed");
        drop(file); // as FILE_SHARE_NONE is used, we need to close the file first
        // tries to open file with open and write access to verify permissions
        let file = OpenOptions::new().read(true).write(true).open(&path);
        assert!(
            file.is_ok(),
            "Private key is not readable or not writable by the current user"
        );
        fs::remove_file(&path).ok();
    }
}
