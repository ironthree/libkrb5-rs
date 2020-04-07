#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

use std::error::Error;
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};

use libkrb5_sys::*;

static CONTEXT_INITIALIZED: AtomicBool = AtomicBool::new(false);

fn c_string_to_string(c_string: *const c_char) -> Result<String, String> {
    match unsafe { std::ffi::CStr::from_ptr(c_string) }.to_owned().into_string() {
        Ok(string) => Ok(string),
        Err(error) => Err(error.to_string()),
    }
}

#[derive(Debug)]
pub struct Krb5Context {
    context: krb5_context,
}

impl Krb5Context {
    pub fn init() -> Result<Krb5Context, String> {
        if CONTEXT_INITIALIZED.load(Ordering::Relaxed) {
            return Err(String::from("Context was already initialized."));
        }

        CONTEXT_INITIALIZED.store(true, Ordering::Relaxed);

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::uninit();

        let code: krb5_error_code = unsafe { krb5_init_context(context_ptr.as_mut_ptr()) };

        let context = Krb5Context {
            context: unsafe { context_ptr.assume_init() },
        };

        if code == 0 {
            Ok(context)
        } else {
            CONTEXT_INITIALIZED.store(false, Ordering::Relaxed);
            Err(context.code_to_message(code))
        }
    }

    pub fn init_secure() -> Result<Krb5Context, String> {
        if CONTEXT_INITIALIZED.load(Ordering::Relaxed) {
            return Err(String::from("Context was already initialized."));
        }

        CONTEXT_INITIALIZED.store(true, Ordering::Relaxed);

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::uninit();

        let code: krb5_error_code = unsafe { krb5_init_secure_context(context_ptr.as_mut_ptr()) };

        let context = Krb5Context {
            context: unsafe { context_ptr.assume_init() },
        };

        if code == 0 {
            Ok(context)
        } else {
            CONTEXT_INITIALIZED.store(false, Ordering::Relaxed);
            Err(context.code_to_message(code))
        }
    }

    fn code_to_message(&self, code: krb5_error_code) -> String {
        let message: *const c_char = unsafe { krb5_get_error_message(self.context, code) };

        match c_string_to_string(message) {
            Ok(string) => {
                unsafe { krb5_free_error_message(self.context, message) };
                string
            },
            Err(string) => string,
        }
    }
}

impl Drop for Krb5Context {
    fn drop(&mut self) {
        unsafe {
            krb5_free_context(self.context);
        }

        CONTEXT_INITIALIZED.store(false, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub struct Krb5CCCol<'a> {
    context: &'a Krb5Context,
    cursor: krb5_cccol_cursor,
}

impl<'a> Krb5CCCol<'a> {
    pub fn new(context: &Krb5Context) -> Result<Krb5CCCol, String> {
        let mut cursor_ptr: MaybeUninit<krb5_cccol_cursor> = MaybeUninit::uninit();

        let code: krb5_error_code = unsafe { krb5_cccol_cursor_new(context.context, cursor_ptr.as_mut_ptr()) };

        if code == 0 {
            let cursor = Krb5CCCol {
                context: &context,
                cursor: unsafe { cursor_ptr.assume_init() },
            };

            Ok(cursor)
        } else {
            Err(context.code_to_message(code))
        }
    }
}

impl<'a> Drop for Krb5CCCol<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_cccol_cursor_free(self.context.context, &mut self.cursor);
        }
    }
}

impl<'a> Iterator for Krb5CCCol<'a> {
    type Item = Result<Krb5CCache<'a>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::uninit();

        let code: krb5_error_code =
            unsafe { krb5_cccol_cursor_next(self.context.context, self.cursor, ccache_ptr.as_mut_ptr()) };

        if code == 0 {
            let ccache_ptr = unsafe { ccache_ptr.assume_init() };

            if ccache_ptr.is_null() {
                return None;
            }

            let ccache = Krb5CCache {
                context: &self.context,
                ccache: ccache_ptr,
            };

            Some(Ok(ccache))
        } else {
            Some(Err(self.context.code_to_message(code)))
        }
    }
}

#[derive(Debug)]
pub struct Krb5CCache<'a> {
    context: &'a Krb5Context,
    ccache: krb5_ccache,
}

impl<'a> Drop for Krb5CCache<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_cc_close(self.context.context, self.ccache);
        }
    }
}

impl<'a> Krb5CCache<'a> {
    pub fn principal(&self) -> Result<Option<Krb5Principal>, String> {
        let mut principal_ptr: MaybeUninit<krb5_principal> = MaybeUninit::uninit();

        let code: krb5_error_code =
            unsafe { krb5_cc_get_principal(self.context.context, self.ccache, principal_ptr.as_mut_ptr()) };

        if code == 0 {
            let principal_ptr = unsafe { principal_ptr.assume_init() };

            if principal_ptr.is_null() {
                return Ok(None);
            }

            let principal = Krb5Principal {
                context: &self.context,
                principal: principal_ptr,
            };

            Ok(Some(principal))
        } else {
            Err(self.context.code_to_message(code))
        }
    }
}

#[derive(Debug)]
pub struct Krb5Principal<'a> {
    context: &'a Krb5Context,
    principal: krb5_principal,
}

impl<'a> Drop for Krb5Principal<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_free_principal(self.context.context, self.principal);
        }
    }
}

impl<'a> Krb5Principal<'a> {
    pub fn data(&self) -> Krb5PrincipalData {
        Krb5PrincipalData {
            context: &self.context,
            principal_data: unsafe { *self.principal },
        }
    }
}

#[derive(Debug)]
pub struct Krb5PrincipalData<'a> {
    context: &'a Krb5Context,
    principal_data: krb5_principal_data,
}

impl<'a> Krb5PrincipalData<'a> {
    pub fn realm(&self) -> Result<String, String> {
        let realm: *const c_char = self.principal_data.realm.data;

        c_string_to_string(realm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_init_free() -> Result<(), String> {
        let _context = Krb5Context::init()?;
        Ok(())
    }

    #[test]
    fn context_init_twice() {
        let _context = Krb5Context::init().unwrap();
        let context2 = Krb5Context::init();

        assert!(context2.is_err());
    }

    #[test]
    fn context_secure_init_free() -> Result<(), String> {
        let _context = Krb5Context::init_secure()?;
        Ok(())
    }

    #[test]
    fn cccol_new_drop() -> Result<(), String> {
        let context = Krb5Context::init()?;
        let _cursor = Krb5CCCol::new(&context)?;
        Ok(())
    }

    #[test]
    fn cccol_iterate() -> Result<(), String> {
        let context = Krb5Context::init()?;
        let collection = Krb5CCCol::new(&context)?;

        for ccache in collection {
            ccache?;
        }

        Ok(())
    }

    #[test]
    fn cccol_principals() -> Result<(), String> {
        let context = Krb5Context::init()?;
        let collection = Krb5CCCol::new(&context)?;

        for ccache in collection {
            let ccache = ccache?;
            let principal = ccache.principal()?;

            if let Some(principal) = principal {
                let data = principal.data();
                println!("Realm: {}", data.realm()?);
            };
        }

        Ok(())
    }
}
