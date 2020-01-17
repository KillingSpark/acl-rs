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

pub enum AclError {
    InitFailed(i32),
}

impl Acl {
    pub fn init(count: i32) -> Result<Self, AclError> {
        let raw_ptr = unsafe { acl_sys::acl_init(count as i32) };
        if raw_ptr.is_null() {
            let errno = nix::errno::errno();
            Err(AclError::InitFailed(errno))
        } else {
            Ok(Acl { raw_ptr })
        }
    }
}
