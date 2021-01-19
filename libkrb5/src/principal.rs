use std::os::raw::c_char;

use libkrb5_sys::*;

use crate::context::Krb5Context;
use crate::error::Krb5Error;
use crate::strconv::c_string_to_string;

#[derive(Debug)]
pub struct Krb5Principal<'a> {
    pub(crate) context: &'a Krb5Context,
    pub(crate) principal: krb5_principal,
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
    pub(crate) context: &'a Krb5Context,
    pub(crate) principal_data: krb5_principal_data,
}

impl<'a> Krb5PrincipalData<'a> {
    pub fn realm(&self) -> Result<String, Krb5Error> {
        let realm: *const c_char = self.principal_data.realm.data;

        c_string_to_string(realm)
    }
}
