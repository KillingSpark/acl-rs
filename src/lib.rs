#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        use crate::*;
        let mut acl = Acl::init(10).unwrap();
        assert_eq!(acl.valid().unwrap(), Some(nix::errno::Errno::EINVAL));

        let mut entry = acl.create_entry().unwrap();
        let tag = AclTag::UserObj;
        entry.set_tag_type(&tag).unwrap();
        let mut permset = entry.get_permset().unwrap();
        permset.add_perm(AclPerm::Read).unwrap();
        assert_eq!(entry.get_tag_type().unwrap(), tag);

        let mut entry = acl.create_entry().unwrap();
        let tag = AclTag::GroupObj;
        entry.set_tag_type(&tag).unwrap();
        let mut permset = entry.get_permset().unwrap();
        permset.add_perm(AclPerm::Write).unwrap();
        assert_eq!(entry.get_tag_type().unwrap(), tag);

        let mut entry = acl.create_entry().unwrap();
        let tag = AclTag::Other;
        entry.set_tag_type(&tag).unwrap();
        let mut permset = entry.get_permset().unwrap();
        permset.add_perm(AclPerm::Execute).unwrap();
        assert_eq!(entry.get_tag_type().unwrap(), tag);

        let mut entry = acl.create_entry().unwrap();
        let tag = AclTag::User;
        entry.set_tag_type(&tag).unwrap();
        entry
            .set_qualifier(&Qualifier::User(nix::unistd::Uid::from_raw(0)))
            .unwrap();
        let mut permset = entry.get_permset().unwrap();
        permset.add_perm(AclPerm::Execute).unwrap();
        permset.add_perm(AclPerm::Read).unwrap();
        permset.add_perm(AclPerm::Write).unwrap();
        assert_eq!(entry.get_tag_type().unwrap(), tag);

        // mask is necessary when User/Group is set
        acl.calc_mask().unwrap();
        assert_eq!(entry.get_tag_type().unwrap(), tag);
        assert_eq!(acl.valid().unwrap(), None);

        let path = std::path::PathBuf::from("./file_to_test_acls");
        if !path.exists() {
            std::fs::File::create(&path).unwrap();
        }
        acl.set_for_file(&path, &AclType::TypeAccess).unwrap();

        let new_acl = Acl::for_file(&path, &AclType::TypeAccess).unwrap();
        std::fs::remove_file(&path).unwrap();
        let new_alc_str = String::from_utf8(new_acl.to_text().unwrap()).unwrap();
        assert_eq!(
            "user::r--\nuser:root:rwx\ngroup::-w-\nmask::rwx\nother::--x\n",
            &new_alc_str
        );

        // There are 5 entries: userobj, user, group, other, mask
        // TODO check those permsets. I dont know how that works. Linux has an extension "acl_get_perm" but thats not exposed by acl_sys?
        let entry1 = new_acl.get_entry(&EntryId::FirstEntry).unwrap().unwrap();
        let _permset1 = entry1.get_permset().unwrap();

        let entry2 = new_acl.get_entry(&EntryId::NextEntry).unwrap().unwrap();
        let _permset2 = entry2.get_permset().unwrap();

        let entry3 = new_acl.get_entry(&EntryId::NextEntry).unwrap().unwrap();
        let _permset3 = entry3.get_permset().unwrap();

        let entry4 = new_acl.get_entry(&EntryId::NextEntry).unwrap().unwrap();
        let _permset4 = entry4.get_permset().unwrap();

        let entry5 = new_acl.get_entry(&EntryId::NextEntry).unwrap().unwrap();
        let _permset5 = entry5.get_permset().unwrap();

        let err_entry = new_acl.get_entry(&EntryId::NextEntry).unwrap();
        assert_eq!(err_entry, None);
    }
}

extern crate acl_sys;
extern crate nix;

#[derive(PartialEq, Eq, Debug)]
pub struct AclEntry {
    raw_ptr: acl_sys::acl_entry_t,
    // if the parent acl was moved this has to become invalid
    is_valid: std::cell::RefCell<bool>,
}

pub enum AclPerm {
    Read,
    Write,
    Execute,
}

impl AclPerm {
    pub fn to_raw(&self) -> u32 {
        match self {
            AclPerm::Read => acl_sys::ACL_READ,
            AclPerm::Write => acl_sys::ACL_WRITE,
            AclPerm::Execute => acl_sys::ACL_EXECUTE,
        }
    }
}

pub struct AclPermSet {
    raw_ptr: acl_sys::acl_permset_t,
    // if the parent acl was moved this has to become invalid
    is_valid: std::cell::RefCell<bool>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AclType {
    TypeAccess,
    TypeDefault,
}

impl AclType {
    pub fn to_raw(&self) -> u32 {
        match self {
            AclType::TypeAccess => acl_sys::ACL_TYPE_ACCESS,
            AclType::TypeDefault => acl_sys::ACL_TYPE_DEFAULT,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AclTag {
    UserObj,
    User,
    GroupObj,
    Group,
    Mask,
    Other,
    Invalid,
}

impl AclTag {
    pub fn to_raw(&self) -> i32 {
        match self {
            AclTag::UserObj => acl_sys::ACL_USER_OBJ,
            AclTag::User => acl_sys::ACL_USER,
            AclTag::GroupObj => acl_sys::ACL_GROUP_OBJ,
            AclTag::Group => acl_sys::ACL_GROUP,
            AclTag::Mask => acl_sys::ACL_MASK,
            AclTag::Other => acl_sys::ACL_OTHER,
            AclTag::Invalid => acl_sys::ACL_UNDEFINED_TAG,
        }
    }
    pub fn from_raw(raw: i32) -> Self {
        match raw {
            acl_sys::ACL_USER_OBJ => AclTag::UserObj,
            acl_sys::ACL_USER => AclTag::User,
            acl_sys::ACL_GROUP_OBJ => AclTag::GroupObj,
            acl_sys::ACL_GROUP => AclTag::Group,
            acl_sys::ACL_MASK => AclTag::Mask,
            acl_sys::ACL_OTHER => AclTag::Other,
            _ => AclTag::Invalid,
        }
    }
}

#[derive(Debug)]
pub struct Acl {
    raw_ptr: acl_sys::acl_t,

    // if the acl is moved in create_entry this is set to true
    // and replaced with a new RefCell
    is_valid: std::cell::RefCell<bool>,
}

#[derive(Clone, Copy, Debug)]
pub enum AclError {
    Errno(nix::errno::Errno),
    UnknownReturn(i32),
    WasMoved,
}

#[derive(Clone, Copy, Debug)]
pub enum EntryId {
    NextEntry,
    FirstEntry,
}

pub enum Qualifier {
    User(nix::unistd::Uid),
    Group(nix::unistd::Gid),
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
            Ok(Acl {
                raw_ptr,
                is_valid: std::cell::RefCell::new(true),
            })
        }
    }

    pub fn from_text(text: &str) -> Result<Self, AclError> {
        let text_i8 = text.bytes().map(|x| x as i8).collect::<Vec<_>>();
        let raw_ptr = unsafe { acl_sys::acl_from_text(text_i8.as_ptr()) };
        if raw_ptr.is_null() {
            let errno = nix::errno::errno();
            Err(AclError::Errno(nix::errno::from_i32(errno)))
        } else {
            Ok(Acl {
                raw_ptr,
                is_valid: std::cell::RefCell::new(true),
            })
        }
    }

    pub fn to_text(&self) -> Result<Vec<u8>, AclError> {
        let mut len = 0;
        let raw_text = unsafe { acl_sys::acl_to_text(self.raw_ptr, &mut len) };

        if raw_text.is_null() {
            let errno = nix::errno::errno();
            Err(AclError::Errno(nix::errno::from_i32(errno)))
        } else {
            let mut text_bytes = Vec::new();
            let mut iter_ptr = raw_text;
            for _idx in 0..len {
                let byte = unsafe { *iter_ptr } as u8;
                text_bytes.push(byte);
                iter_ptr = unsafe { iter_ptr.add(1) };
            }

            unsafe { acl_sys::acl_free(std::mem::transmute(raw_text)) };

            Ok(text_bytes)
        }
    }

    pub fn for_fd(fd: i32) -> Result<Self, AclError> {
        let raw_ptr = unsafe { acl_sys::acl_get_fd(fd) };
        if raw_ptr.is_null() {
            let errno = nix::errno::errno();
            Err(AclError::Errno(nix::errno::from_i32(errno)))
        } else {
            Ok(Acl {
                raw_ptr,
                is_valid: std::cell::RefCell::new(true),
            })
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

    pub fn for_file(file_path: &std::path::PathBuf, typ: &AclType) -> Result<Self, AclError> {
        use std::os::unix::ffi::OsStrExt;
        let path_bytes = file_path.as_os_str().as_bytes().to_vec();
        let path_i8 = path_bytes.into_iter().map(|x| x as i8).collect::<Vec<_>>();
        let raw_ptr = unsafe { acl_sys::acl_get_file(path_i8.as_ptr(), typ.to_raw()) };
        if raw_ptr.is_null() {
            let errno = nix::errno::errno();
            Err(AclError::Errno(nix::errno::from_i32(errno)))
        } else {
            Ok(Acl {
                raw_ptr,
                is_valid: std::cell::RefCell::new(true),
            })
        }
    }

    pub fn set_for_file(
        &self,
        file_path: &std::path::PathBuf,
        typ: &AclType,
    ) -> Result<(), AclError> {
        use std::os::unix::ffi::OsStrExt;
        let path_bytes = file_path.as_os_str().as_bytes().to_vec();
        let path_i8 = path_bytes.into_iter().map(|x| x as i8).collect::<Vec<_>>();
        let result = unsafe { acl_sys::acl_set_file(path_i8.as_ptr(), typ.to_raw(), self.raw_ptr) };
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
            1 => Ok(Some(AclEntry {
                raw_ptr: entry_ptr,
                is_valid: self.is_valid.clone(),
            })),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    /// This is dangerous. The lifetime of all permsets and entries is bound to the liftime of the Acls raw_pointer.
    /// Since this operation might move the Acl to a bigger allocation this might introduce unsoundness.
    ///
    /// This should be prevented since we check in each call if is_valid is still true but it is pretty hacky.
    pub fn create_entry(&mut self) -> Result<AclEntry, AclError> {
        let mut entry_ptr = std::ptr::null_mut();
        let entry_ptr_ptr = &mut entry_ptr as *mut acl_sys::acl_entry_t;

        let acl_ptr_before = self.raw_ptr;
        let result = unsafe { acl_sys::acl_create_entry(&mut self.raw_ptr, entry_ptr_ptr) };

        if !acl_ptr_before.eq(&self.raw_ptr) {
            // The acl was moved. Need to invalidate all entries/permsets
            *self.is_valid.borrow_mut() = false;
            // The new acl is obviously valid again
            self.is_valid = std::cell::RefCell::new(true);
        }

        match result {
            0 => Ok(AclEntry {
                raw_ptr: entry_ptr,
                is_valid: self.is_valid.clone(),
            }),
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
            Ok(Acl {
                raw_ptr: new_acl,
                is_valid: self.is_valid.clone(),
            })
        }
    }

    pub fn size(&self) -> Result<usize, AclError> {
        let result = unsafe { acl_sys::acl_size(self.raw_ptr) };
        match result {
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Ok(result as usize),
        }
    }

    pub fn valid(&self) -> Result<Option<nix::errno::Errno>, AclError> {
        let result = unsafe { acl_sys::acl_valid(self.raw_ptr) };
        match result {
            0 => Ok(None),
            -1 => Ok(Some(nix::errno::from_i32(nix::errno::errno()))),
            _ => Err(AclError::UnknownReturn(result)),
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
    pub fn check_valid(&self) -> Result<(), AclError> {
        if *self.is_valid.borrow() == true {
            Ok(())
        } else {
            Err(AclError::WasMoved)
        }
    }

    pub fn add_perm(&mut self, perm: AclPerm) -> Result<(), AclError> {
        self.check_valid()?;
        let result = unsafe { acl_sys::acl_add_perm(self.raw_ptr, perm.to_raw()) };
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
        self.check_valid()?;
        let result = unsafe { acl_sys::acl_delete_perms(self.raw_ptr, perm.to_raw()) };
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
        self.check_valid()?;
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
    pub fn check_valid(&self) -> Result<(), AclError> {
        if *self.is_valid.borrow() == true {
            Ok(())
        } else {
            Err(AclError::WasMoved)
        }
    }

    pub fn copy_to(&self, dest: &mut AclEntry) -> Result<(), AclError> {
        self.check_valid()?;
        let result = unsafe { acl_sys::acl_copy_entry(dest.raw_ptr, self.raw_ptr) };
        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn get_permset(&self) -> Result<AclPermSet, AclError> {
        self.check_valid()?;
        let mut permset_ptr = std::ptr::null_mut();
        let permset_ptr_ptr = &mut permset_ptr as *mut acl_sys::acl_entry_t;
        let result = unsafe { acl_sys::acl_get_permset(self.raw_ptr, permset_ptr_ptr) };

        match result {
            0 => Ok(AclPermSet {
                raw_ptr: permset_ptr,
                is_valid: self.is_valid.clone(),
            }),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn set_permset(&mut self, permset: &AclPermSet) -> Result<(), AclError> {
        self.check_valid()?;
        let result = unsafe { acl_sys::acl_set_permset(self.raw_ptr, permset.raw_ptr) };

        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn get_tag_type(&self) -> Result<AclTag, AclError> {
        self.check_valid()?;
        let mut raw = 0 as acl_sys::acl_tag_t;
        let raw_ptr = &mut raw as *mut acl_sys::acl_tag_t;
        let result = unsafe { acl_sys::acl_get_tag_type(self.raw_ptr, raw_ptr) };

        match result {
            0 => Ok(AclTag::from_raw(raw)),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn set_tag_type(&mut self, tag_type: &AclTag) -> Result<(), AclError> {
        self.check_valid()?;
        let result = unsafe { acl_sys::acl_set_tag_type(self.raw_ptr, tag_type.to_raw()) };

        match result {
            0 => Ok(()),
            -1 => {
                let errno = nix::errno::errno();
                Err(AclError::Errno(nix::errno::from_i32(errno)))
            }
            _ => Err(AclError::UnknownReturn(result)),
        }
    }

    pub fn get_qualifier(&self) -> Result<Qualifier, AclError> {
        self.check_valid()?;
        match self.get_tag_type()? {
            AclTag::User => {
                let raw_ptr = unsafe { acl_sys::acl_get_qualifier(self.raw_ptr) };
                if raw_ptr.is_null() {
                    let errno = nix::errno::errno();
                    Err(AclError::Errno(nix::errno::from_i32(errno)))
                } else {
                    let raw: u32 = unsafe { *(std::mem::transmute::<_, *const u32>(raw_ptr)) };
                    Ok(Qualifier::User(nix::unistd::Uid::from_raw(raw)))
                }
            }
            AclTag::Group => {
                let raw_ptr = unsafe { acl_sys::acl_get_qualifier(self.raw_ptr) };
                if raw_ptr.is_null() {
                    let errno = nix::errno::errno();
                    Err(AclError::Errno(nix::errno::from_i32(errno)))
                } else {
                    let raw: u32 = unsafe { *(std::mem::transmute::<_, *const u32>(raw_ptr)) };
                    Ok(Qualifier::User(nix::unistd::Uid::from_raw(raw)))
                }
            }
            _ => return Err(AclError::Errno(nix::errno::Errno::EINVAL)),
        }
    }

    pub fn set_qualifier(&mut self, qual: &Qualifier) -> Result<(), AclError> {
        self.check_valid()?;
        let result = match qual {
            Qualifier::User(id) => {
                let raw = id.as_raw();
                let raw_ptr = &raw;
                unsafe { acl_sys::acl_set_qualifier(self.raw_ptr, std::mem::transmute(raw_ptr)) }
            }
            Qualifier::Group(id) => unsafe {
                acl_sys::acl_set_qualifier(self.raw_ptr, std::mem::transmute(&id.as_raw()))
            },
        };
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
