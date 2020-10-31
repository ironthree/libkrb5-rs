use std::error::Error;
use std::ffi::IntoStringError;
use std::fmt::{Display, Formatter};
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::sync::Mutex;

use lazy_static::lazy_static;

use libkrb5_sys::*;

lazy_static! {
    static ref CONTEXT_INIT_LOCK: Mutex<()> = Mutex::new(());
}

#[derive(Debug)]
pub enum Krb5Error {
    LibraryError { message: String },
    NullPointerDereference,
    StringConversion,
}

impl Display for Krb5Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        use Krb5Error::*;

        match self {
            LibraryError { message } => write!(f, "Library error: {}", message),
            NullPointerDereference => write!(f, "NULL Pointer dereference error"),
            StringConversion => write!(f, "String conversion / UTF8 error"),
        }
    }
}

impl Error for Krb5Error {}

impl From<IntoStringError> for Krb5Error {
    fn from(_: IntoStringError) -> Self {
        Krb5Error::StringConversion
    }
}

fn c_string_to_string(c_string: *const c_char) -> Result<String, Krb5Error> {
    if c_string.is_null() {
        return Err(Krb5Error::NullPointerDereference);
    }

    match unsafe { std::ffi::CStr::from_ptr(c_string) }.to_owned().into_string() {
        Ok(string) => Ok(string),
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug)]
pub struct Krb5Context {
    context: krb5_context,
}

impl Krb5Context {
    pub fn init() -> Result<Krb5Context, Krb5Error> {
        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::uninit();

        let code: krb5_error_code = unsafe { krb5_init_context(context_ptr.as_mut_ptr()) };

        let context = Krb5Context {
            context: unsafe { context_ptr.assume_init() },
        };

        if code == 0 {
            Ok(context)
        } else {
            Err(Krb5Error::LibraryError {
                message: context.code_to_message(code),
            })
        }
    }

    pub fn init_secure() -> Result<Krb5Context, Krb5Error> {
        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::uninit();

        let code: krb5_error_code = unsafe { krb5_init_secure_context(context_ptr.as_mut_ptr()) };

        let context = Krb5Context {
            context: unsafe { context_ptr.assume_init() },
        };

        if code == 0 {
            Ok(context)
        } else {
            Err(Krb5Error::LibraryError {
                message: context.code_to_message(code),
            })
        }
    }

    fn code_to_message(&self, code: krb5_error_code) -> String {
        let message: *const c_char = unsafe { krb5_get_error_message(self.context, code) };

        match c_string_to_string(message) {
            Ok(string) => {
                unsafe { krb5_free_error_message(self.context, message) };
                string
            },
            Err(error) => error.to_string(),
        }
    }
}

impl Drop for Krb5Context {
    fn drop(&mut self) {
        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context for de-initialization.");

        unsafe { krb5_free_context(self.context) };
    }
}

#[derive(Debug)]
pub struct Krb5CCCol<'a> {
    context: &'a Krb5Context,
    cursor: krb5_cccol_cursor,
}

impl<'a> Krb5CCCol<'a> {
    pub fn new(context: &Krb5Context) -> Result<Krb5CCCol, Krb5Error> {
        let mut cursor_ptr: MaybeUninit<krb5_cccol_cursor> = MaybeUninit::uninit();

        let code: krb5_error_code = unsafe { krb5_cccol_cursor_new(context.context, cursor_ptr.as_mut_ptr()) };

        if code == 0 {
            let cursor = Krb5CCCol {
                context: &context,
                cursor: unsafe { cursor_ptr.assume_init() },
            };

            Ok(cursor)
        } else {
            Err(Krb5Error::LibraryError {
                message: context.code_to_message(code),
            })
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
    type Item = Result<Krb5CCache<'a>, Krb5Error>;

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
            Some(Err(Krb5Error::LibraryError {
                message: self.context.code_to_message(code),
            }))
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
    pub fn principal(&self) -> Result<Option<Krb5Principal>, Krb5Error> {
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
            Err(Krb5Error::LibraryError {
                message: self.context.code_to_message(code),
            })
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
    pub fn realm(&self) -> Result<String, Krb5Error> {
        let realm: *const c_char = self.principal_data.realm.data;

        c_string_to_string(realm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_thread_safe() {
        // assert that libkrb5 was built in thread-safe mode
        assert_eq!(unsafe { krb5_is_thread_safe() }, 1u32);
    }

    #[test]
    fn context_init_free() -> Result<(), Krb5Error> {
        let _context = Krb5Context::init()?;
        Ok(())
    }

    #[test]
    fn context_secure_init_free() -> Result<(), Krb5Error> {
        let _context = Krb5Context::init_secure()?;
        Ok(())
    }

    #[test]
    fn cccol_new_drop() -> Result<(), Krb5Error> {
        let context = Krb5Context::init()?;
        let _cursor = Krb5CCCol::new(&context)?;
        Ok(())
    }

    #[test]
    fn cccol_iterate() -> Result<(), Krb5Error> {
        let context = Krb5Context::init()?;
        let collection = Krb5CCCol::new(&context)?;

        for ccache in collection {
            ccache?;
        }

        Ok(())
    }

    #[test]
    fn cccol_principals() -> Result<(), Krb5Error> {
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
