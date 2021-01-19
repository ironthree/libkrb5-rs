use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::error::Krb5Error;

pub(crate) fn c_string_to_string(c_string: *const c_char) -> Result<String, Krb5Error> {
    if c_string.is_null() {
        return Err(Krb5Error::NullPointerDereference);
    }

    match unsafe { CStr::from_ptr(c_string) }.to_owned().into_string() {
        Ok(string) => Ok(string),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn string_to_c_string(string: &str) -> Result<*const c_char, Krb5Error> {
    let cstring = match CString::new(string) {
        Ok(value) => value,
        Err(_) => return Err(Krb5Error::StringConversion { error: None }),
    };

    Ok(cstring.as_ptr())
}
