use std::mem::MaybeUninit;
use std::os::raw::c_char;

use libkrb5_sys::*;

use crate::context::Krb5Context;
use crate::error::{krb5_error_code_escape_hatch, Krb5Error};
use crate::principal::Krb5Principal;
use crate::strconv::{c_string_to_string, string_to_c_string};

#[derive(Debug)]
pub struct Krb5CCache<'a> {
    pub(crate) context: &'a Krb5Context,
    pub(crate) ccache: krb5_ccache,
}

impl<'a> Drop for Krb5CCache<'a> {
    fn drop(&mut self) {
        unsafe {
            krb5_cc_close(self.context.context, self.ccache);
        }
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
