use std::mem::MaybeUninit;
use std::os::raw::c_char;

use libkrb5_sys::*;

pub struct Krb5Context {
    context: krb5_context,
}

impl Krb5Context {
    pub fn init() -> Result<Krb5Context, String> {
        let mut context_ptr: MaybeUninit<krb5_context> = MaybeUninit::uninit();

        let code: krb5_error_code = unsafe { krb5_init_context(context_ptr.as_mut_ptr()) };

        let context = Krb5Context { context: unsafe { context_ptr.assume_init() } };

        if code == 0 {
            Ok(context)
        } else {
            Err(context.code_to_message(code))
        }
    }

    fn code_to_message(&self, code: krb5_error_code) -> String {
        let message: *const c_char = unsafe { krb5_get_error_message(self.context, code) };
        // FIXME: don't crash on invalid messages
        let string = unsafe { std::ffi::CStr::from_ptr(message).to_owned().into_string().unwrap() };
        unsafe { krb5_free_error_message(self.context, message) };
        string
    }
}

impl Drop for Krb5Context {
    fn drop(&mut self) {
        unsafe {
            krb5_free_context(self.context);
        }
    }
}

pub struct Krb5CCColCursor<'a> {
    context: &'a krb5_context,
    cursor: krb5_cccol_cursor,
}

impl<'a> Krb5CCColCursor<'a> {
    pub fn init(context: &Krb5Context) -> Result<Krb5CCColCursor, String> {
        let mut cursor_ptr: MaybeUninit<krb5_cccol_cursor> = MaybeUninit::uninit();

        let code: krb5_error_code = unsafe { krb5_cccol_cursor_new(context.context, cursor_ptr.as_mut_ptr()) };

        if code == 0 {
            let cursor = Krb5CCColCursor {
                cursor: unsafe {cursor_ptr.assume_init() },
                context: &context.context,
            };

            Ok(cursor)
        } else {
            Err(context.code_to_message(code))
        }
    }
}

impl<'a> Drop for Krb5CCColCursor<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_cccol_cursor_free(*self.context, &mut self.cursor);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_free_context() {
        let _context = Krb5Context::init().unwrap();
    }

    #[test]
    fn init_free_cccol_cursor() {
        let context = Krb5Context::init().unwrap();
        let _cursor = Krb5CCColCursor::init(&context).unwrap();
    }
}
