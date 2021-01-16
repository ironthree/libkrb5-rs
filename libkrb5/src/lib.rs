use std::error::Error;
use std::ffi::{CStr, CString, IntoStringError};
use std::fmt::{Display, Formatter};
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::sync::Mutex;

use lazy_static::lazy_static;

use libkrb5_sys::*;

lazy_static! {
    static ref CONTEXT_INIT_LOCK: Mutex<()> = Mutex::new(());
}

#[allow(dead_code)]
static C_FALSE: u32 = 0;
#[allow(dead_code)]
static C_TRUE: u32 = 1;

#[derive(Debug)]
pub enum Krb5Error {
    LibraryError { message: String },
    NullPointerDereference,
    StringConversion { error: Option<IntoStringError> },
    MaxVarArgsExceeded,
}

impl Display for Krb5Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        use Krb5Error::*;

        match self {
            LibraryError { message } => write!(f, "Library error: {}", message),
            NullPointerDereference => write!(f, "NULL Pointer dereference error"),
            StringConversion { error } => {
                match error {
                    Some(error) => write!(f, "String conversion / UTF8 error: {}", error),
                    None => write!(f, "String conversion / UTF8 error"),
                }
            },
            MaxVarArgsExceeded => write!(
                f,
                "Maximum number of supported arguments for a variadic function exceeded."
            ),
        }
    }
}

impl Error for Krb5Error {}

impl From<IntoStringError> for Krb5Error {
    fn from(error: IntoStringError) -> Self {
        Krb5Error::StringConversion { error: Some(error) }
    }
}

fn c_string_to_string(c_string: *const c_char) -> Result<String, Krb5Error> {
    if c_string.is_null() {
        return Err(Krb5Error::NullPointerDereference);
    }

    match unsafe { CStr::from_ptr(c_string) }.to_owned().into_string() {
        Ok(string) => Ok(string),
        Err(error) => Err(error.into()),
    }
}

fn string_to_c_string(string: &str) -> Result<*const c_char, Krb5Error> {
    let cstring = match CString::new(string) {
        Ok(value) => value,
        Err(_) => return Err(Krb5Error::StringConversion { error: None }),
    };

    Ok(cstring.as_ptr())
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

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_init_context(context_ptr.as_mut_ptr()) };

        let context = Krb5Context {
            context: unsafe { context_ptr.assume_init() },
        };

        krb5_error_code_escape_hatch(&context, code)?;

        Ok(context)
    }

    pub fn init_secure() -> Result<Krb5Context, Krb5Error> {
        let _guard = CONTEXT_INIT_LOCK
            .lock()
            .expect("Failed to lock context initialization.");

        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_init_secure_context(context_ptr.as_mut_ptr()) };

        let context = Krb5Context {
            context: unsafe { context_ptr.assume_init() },
        };

        krb5_error_code_escape_hatch(&context, code)?;

        Ok(context)
    }

    pub fn build_principal<'a>(&'a self, realm: &'a str, args: &'a [String]) -> Result<Krb5Principal<'a>, Krb5Error> {
        let crealm = string_to_c_string(realm)?;
        let realml = realm.len() as u32;

        let mut varargs = Vec::new();
        for arg in args {
            varargs.push(string_to_c_string(arg)?);
        }

        let mut principal_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();

        // TODO: write a macro to generate this match block
        let code: krb5_error_code = match args.len() {
            // varargs support in Rust is lacking, so only support a limited number of arguments for now
            0 => unsafe { krb5_build_principal(self.context, principal_ptr.as_mut_ptr(), realml, crealm) },
            1 => unsafe { krb5_build_principal(self.context, principal_ptr.as_mut_ptr(), realml, crealm, varargs[0]) },
            2 => unsafe {
                krb5_build_principal(
                    self.context,
                    principal_ptr.as_mut_ptr(),
                    realml,
                    crealm,
                    varargs[0],
                    varargs[1],
                )
            },
            3 => unsafe {
                krb5_build_principal(
                    self.context,
                    principal_ptr.as_mut_ptr(),
                    realml,
                    crealm,
                    varargs[0],
                    varargs[1],
                    varargs[2],
                )
            },
            4 => unsafe {
                krb5_build_principal(
                    self.context,
                    principal_ptr.as_mut_ptr(),
                    realml,
                    crealm,
                    varargs[0],
                    varargs[1],
                    varargs[2],
                    varargs[3],
                )
            },
            _ => return Err(Krb5Error::MaxVarArgsExceeded),
        };

        krb5_error_code_escape_hatch(self, code)?;

        let principal = Krb5Principal {
            context: self,
            principal: unsafe { principal_ptr.assume_init() },
        };

        Ok(principal)
    }

    // TODO: this produces invalid UTF-8?
    /*
    pub fn expand_hostname(&self, hostname: &str) -> Result<String, Krb5Error> {
        let hostname_c = string_to_c_string(hostname)?;
        let mut cstr_ptr: MaybeUninit<*mut c_char> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_expand_hostname(self.context, hostname_c, cstr_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(self, code)?;
        let cstr_ptr = unsafe { cstr_ptr.assume_init() };

        let result = c_string_to_string(cstr_ptr);
        unsafe { krb5_free_string(self.context, cstr_ptr) };

        result
    }
    */

    fn error_code_to_message(&self, code: krb5_error_code) -> String {
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
        let mut cursor_ptr: MaybeUninit<krb5_cccol_cursor> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_cccol_cursor_new(context.context, cursor_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(context, code)?;

        let cursor = Krb5CCCol {
            context: &context,
            cursor: unsafe { cursor_ptr.assume_init() },
        };

        Ok(cursor)
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
        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

        let code: krb5_error_code =
            unsafe { krb5_cccol_cursor_next(self.context.context, self.cursor, ccache_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(self.context, code).ok()?;

        let ccache_ptr = unsafe { ccache_ptr.assume_init() };

        if ccache_ptr.is_null() {
            return None;
        }

        let ccache = Krb5CCache {
            context: &self.context,
            ccache: ccache_ptr,
        };

        Some(Ok(ccache))
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

#[must_use]
fn krb5_error_code_escape_hatch(context: &Krb5Context, code: krb5_error_code) -> Result<(), Krb5Error> {
    if code == 0 {
        Ok(())
    } else {
        Err(Krb5Error::LibraryError {
            message: context.error_code_to_message(code),
        })
    }
}

impl<'a> Krb5CCache<'a> {
    pub fn default(context: &Krb5Context) -> Result<Krb5CCache, Krb5Error> {
        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_cc_default(context.context, ccache_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(context, code)?;

        let cursor = Krb5CCache {
            context,
            ccache: unsafe { ccache_ptr.assume_init() },
        };

        Ok(cursor)
    }

    pub fn default_name(context: &Krb5Context) -> Result<String, Krb5Error> {
        let name: *const c_char = unsafe { krb5_cc_default_name(context.context) };

        c_string_to_string(name)
    }

    pub fn destroy(self) -> Result<(), Krb5Error> {
        let code = unsafe { krb5_cc_destroy(self.context.context, self.ccache) };

        krb5_error_code_escape_hatch(self.context, code)?;

        Ok(())
    }

    pub fn dup(&self) -> Result<Krb5CCache, Krb5Error> {
        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_cc_dup(self.context.context, self.ccache, ccache_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(self.context, code)?;

        let ccache = Krb5CCache {
            context: self.context,
            ccache: unsafe { ccache_ptr.assume_init() },
        };

        Ok(ccache)
    }

    pub fn get_name(&self) -> Result<String, Krb5Error> {
        let name: *const c_char = unsafe { krb5_cc_get_name(self.context.context, self.ccache) };

        c_string_to_string(name)
    }

    pub fn get_principal(&self) -> Result<Option<Krb5Principal>, Krb5Error> {
        let mut principal_ptr: MaybeUninit<krb5_principal> = MaybeUninit::zeroed();

        let code: krb5_error_code =
            unsafe { krb5_cc_get_principal(self.context.context, self.ccache, principal_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(self.context, code)?;

        let principal_ptr = unsafe { principal_ptr.assume_init() };

        if principal_ptr.is_null() {
            return Ok(None);
        }

        let principal = Krb5Principal {
            context: &self.context,
            principal: principal_ptr,
        };

        Ok(Some(principal))
    }

    pub fn get_type(&self) -> Result<String, Krb5Error> {
        let cctype: *const c_char = unsafe { krb5_cc_get_type(self.context.context, self.ccache) };

        c_string_to_string(cctype)
    }

    pub fn initialize(&mut self, principal: &Krb5Principal) -> Result<(), Krb5Error> {
        let code: krb5_error_code =
            unsafe { krb5_cc_initialize(self.context.context, self.ccache, principal.principal) };

        krb5_error_code_escape_hatch(self.context, code)?;

        Ok(())
    }

    pub fn new_unique(context: &'a Krb5Context, cctype: &str) -> Result<Krb5CCache<'a>, Krb5Error> {
        let cctype = string_to_c_string(cctype)?;

        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

        let code: krb5_error_code =
            unsafe { krb5_cc_new_unique(context.context, cctype, std::ptr::null(), ccache_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(context, code)?;

        let cursor = Krb5CCache {
            context,
            ccache: unsafe { ccache_ptr.assume_init() },
        };

        Ok(cursor)
    }

    pub fn resolve(context: &'a Krb5Context, name: &str) -> Result<Krb5CCache<'a>, Krb5Error> {
        let name = string_to_c_string(name)?;

        let mut ccache_ptr: MaybeUninit<krb5_ccache> = MaybeUninit::zeroed();

        let code: krb5_error_code = unsafe { krb5_cc_resolve(context.context, name, ccache_ptr.as_mut_ptr()) };

        krb5_error_code_escape_hatch(context, code)?;

        let cursor = Krb5CCache {
            context,
            ccache: unsafe { ccache_ptr.assume_init() },
        };

        Ok(cursor)
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
        assert_eq!(unsafe { krb5_is_thread_safe() }, C_TRUE);
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

    /*
    #[test]
    fn expand_hostname() -> Result<(), Krb5Error> {
        let context = Krb5Context::init()?;
        let _expanded = context.expand_hostname("fedoraproject.org")?;
        println!("{}", _expanded);
        Ok(())
    }
    */

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
    fn cccol_get_principals() -> Result<(), Krb5Error> {
        let context = Krb5Context::init()?;
        let collection = Krb5CCCol::new(&context)?;

        for ccache in collection {
            let ccache = ccache?;
            let principal = ccache.get_principal()?;

            if let Some(principal) = principal {
                let data = principal.data();
                println!("Realm: {}", data.realm()?);
            };
        }

        Ok(())
    }
}
