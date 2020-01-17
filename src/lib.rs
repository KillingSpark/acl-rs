#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

extern crate acl_sys;
extern crate nix;

pub struct AclEntry {
    raw_ptr: acl_sys::acl_entry_t,
}

pub struct AclPerm {
    raw: acl_sys::acl_perm_t,
}
pub struct AclPermSet {
    raw_ptr: acl_sys::acl_permset_t,
}

pub struct AclTag {
    raw: acl_sys::acl_tag_t,
}
pub struct AclType {
    raw: acl_sys::acl_type_t,
}
pub struct Acl {
    raw_ptr: acl_sys::acl_t,
}

#[derive(Clone, Copy, Debug)]
pub enum AclError {
    Errno(nix::errno::Errno),
    UnknownReturn(i32),
}

#[derive(Clone, Copy, Debug)]
pub enum EntryId {
    NextEntry,
    FirstEntry,
}

impl EntryId {
    fn to_raw(&self) -> i32 {
        match self {
            // TODO check if thats the same for bsds
            EntryId::NextEntry => 1,
            EntryId::FirstEntry => 0,
        }
    }
}

impl Acl {
    pub fn init(count: i32) -> Result<Self, AclError> {
        let raw_ptr = unsafe { acl_sys::acl_init(count as i32) };
        if raw_ptr.is_null() {
            let errno = nix::errno::errno();
            Err(AclError::Errno(nix::errno::from_i32(errno)))
        } else {
            Ok(Acl { raw_ptr })
        }
    }

    pub fn from_text(text: &str) -> Result<Self, AclError> {
        let text_i8 = text.bytes().map(|x| x as i8).collect::<Vec<_>>();
        let raw_ptr = unsafe { acl_sys::acl_from_text(text_i8.as_ptr()) };
        if raw_ptr.is_null() {
            let errno = nix::errno::errno();
            Err(AclError::Errno(nix::errno::from_i32(errno)))
        } else {
            Ok(Acl { raw_ptr })
        }
    }

    pub fn for_fd(fd: i32) -> Result<Self, AclError> {
        let raw_ptr = unsafe { acl_sys::acl_get_fd(fd) };
        if raw_ptr.is_null() {
            let errno = nix::errno::errno();
            Err(AclError::Errno(nix::errno::from_i32(errno)))
        } else {
            Ok(Acl { raw_ptr })
        }
    }

    pub fn set_for_fd(&self, fd: i32) -> Result<(), AclError> {
        let result = unsafe { acl_sys::acl_set_fd(fd, self.raw_ptr) };
        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn for_file(file_path: &std::path::PathBuf, typ: AclType) -> Result<Self, AclError> {
        use std::os::unix::ffi::OsStrExt;
        let path_bytes = file_path.as_os_str().as_bytes().to_vec();
        let path_i8 = path_bytes.into_iter().map(|x| x as i8).collect::<Vec<_>>();
        let raw_ptr = unsafe { acl_sys::acl_get_file(path_i8.as_ptr(), typ.raw) };
        if raw_ptr.is_null() {
            let errno = nix::errno::errno();
            Err(AclError::Errno(nix::errno::from_i32(errno)))
        } else {
            Ok(Acl { raw_ptr })
        }
    }

    pub fn set_for_file(&self, file_path: &std::path::PathBuf, typ: &AclType) -> Result<(), AclError> {
        use std::os::unix::ffi::OsStrExt;
        let path_bytes = file_path.as_os_str().as_bytes().to_vec();
        let path_i8 = path_bytes.into_iter().map(|x| x as i8).collect::<Vec<_>>();
        let result = unsafe { acl_sys::acl_set_file(path_i8.as_ptr(), typ.raw, self.raw_ptr) };
        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn get_entry(&self, id: &EntryId) -> Result<Option<AclEntry>, AclError> {
        let mut entry_ptr = std::ptr::null_mut();
        let entry_ptr_ptr = &mut entry_ptr as *mut acl_sys::acl_entry_t;
        let result = unsafe { acl_sys::acl_get_entry(self.raw_ptr, id.to_raw(), entry_ptr_ptr) };

        match result {
            0 => Ok(None),
            1 => Ok(Some(AclEntry { raw_ptr: entry_ptr })),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn create_entry(&mut self) -> Result<AclEntry, AclError> {
        let mut entry_ptr = std::ptr::null_mut();
        let entry_ptr_ptr = &mut entry_ptr as *mut acl_sys::acl_entry_t;
        let result = unsafe { acl_sys::acl_create_entry(&mut self.raw_ptr, entry_ptr_ptr) };

        match result {
            0 => Ok(AclEntry { raw_ptr: entry_ptr }),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    /// consumes the entry but returns it if an error occurs
    pub fn delete_entry(&mut self, entry: AclEntry) -> Result<(), (AclEntry, AclError)> {
        let result = unsafe { acl_sys::acl_delete_entry(self.raw_ptr, entry.raw_ptr) };

        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err((entry, AclError::Errno(nix::errno::from_i32(errno))))
            }
            _ => Err((entry, AclError::UnknownReturn(result))),
        }
    }

    /// Use with care. Acl may not be used after this.
    /// This will also be called when dropped so maybe just let drop handle this
    pub fn free(mut self) -> Result<(), (Self, AclError)> {
        let result = unsafe { acl_sys::acl_free(self.raw_ptr) };
        match result {
            0 => {
                self.raw_ptr = std::ptr::null_mut();
                Ok(())
            }
            -1 => {
                let errno = nix::errno::errno();
                Err((self, AclError::Errno(nix::errno::from_i32(errno))))
            }
            _ => Err((self, AclError::UnknownReturn(result))),
        }
    }

    pub fn calc_mask(&mut self) -> Result<(), AclError> {
        let result = unsafe { acl_sys::acl_calc_mask(&mut self.raw_ptr) };
        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn dup(&self) -> Result<Acl, AclError> {
        let new_acl = unsafe { acl_sys::acl_dup(self.raw_ptr) };

        if new_acl.is_null() {
            let errno = nix::errno::errno();
            Err(AclError::Errno(nix::errno::from_i32(errno)))
        } else {
            Ok(Acl { raw_ptr: new_acl })
        }
    }
}

impl Drop for Acl {
    fn drop(&mut self) {
        unsafe { acl_sys::acl_free(self.raw_ptr) };
        self.raw_ptr = std::ptr::null_mut();
    }
}

impl AclPermSet {
    pub fn add_perm(&mut self, perm: AclPerm) -> Result<(), AclError> {
        let result = unsafe { acl_sys::acl_add_perm(self.raw_ptr, perm.raw) };
        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn delete_perms(&mut self, perm: AclPerm) -> Result<(), AclError> {
        let result = unsafe { acl_sys::acl_delete_perms(self.raw_ptr, perm.raw) };
        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn clear_perms(&mut self) -> Result<(), AclError> {
        let result = unsafe { acl_sys::acl_clear_perms(self.raw_ptr) };
        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }
}

impl AclEntry {
    pub fn copy_to(dest: &mut AclEntry, src: &AclEntry) -> Result<(), AclError> {
        let result = unsafe { acl_sys::acl_copy_entry(dest.raw_ptr, src.raw_ptr) };
        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn get_permset(&self) -> Result<Option<AclPermSet>, AclError> {
        let mut permset_ptr = std::ptr::null_mut();
        let permset_ptr_ptr = &mut permset_ptr as *mut acl_sys::acl_entry_t;
        let result = unsafe { acl_sys::acl_get_permset(self.raw_ptr, permset_ptr_ptr) };

        match result {
            0 => Ok(None),
            1 => Ok(Some(AclPermSet {
                raw_ptr: permset_ptr,
            })),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn get_tag_type(&self) -> Result<AclTag, AclError> {
        let mut raw = 0 as acl_sys::acl_tag_t;
        let raw_ptr = &mut raw as *mut acl_sys::acl_tag_t;
        let result = unsafe { acl_sys::acl_get_tag_type(self.raw_ptr, raw_ptr) };

        match result {
            0 => Ok(AclTag { raw }),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }
}

pub fn delete_def_file(file_path: &std::path::PathBuf) -> Result<(), AclError> {
    use std::os::unix::ffi::OsStrExt;
    let path_bytes = file_path.as_os_str().as_bytes().to_vec();
    let path_i8 = path_bytes.into_iter().map(|x| x as i8).collect::<Vec<_>>();
    let path_ptr = path_i8.as_ptr();

    let result = unsafe { acl_sys::acl_delete_def_file(path_ptr) };
    match result {
        0 => Ok(()),
        -1 => {
            let errno = nix::errno::errno();
            Err(AclError::Errno(nix::errno::from_i32(errno)))
        }
        _ => Err(AclError::UnknownReturn(result)),
    }
}
