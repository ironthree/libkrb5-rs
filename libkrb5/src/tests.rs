use super::*;

#[test]
fn is_thread_safe() {
    // assert that libkrb5 was built in thread-safe mode
    assert_eq!(unsafe { libkrb5_sys::krb5_is_thread_safe() }, C_TRUE);
}

#[test]
fn init() {
    let _context = Krb5Context::init().unwrap();
}

#[test]
fn init_secure() {
    let _context = Krb5Context::init_secure().unwrap();
}

#[test]
fn get_default_realm() {
    let context = Krb5Context::init().unwrap();
    let _realm = context.get_default_realm().unwrap();
}

#[test]
fn get_host_realms() {
    let context = Krb5Context::init().unwrap();
    let _realms = context.get_host_realms(None).unwrap();
}

/*
#[test]
fn expand_hostname() {
    let context = Krb5Context::init().unwrap();
    let _expanded = context.expand_hostname("fedoraproject.org").unwrap();
}
*/

#[test]
fn cccol_new() {
    let context = Krb5Context::init().unwrap();
    let _cursor = Krb5CCCol::new(&context).unwrap();
}

#[test]
fn cccol_iterate() {
    let context = Krb5Context::init().unwrap();
    let collection = Krb5CCCol::new(&context).unwrap();

    for ccache in collection {
        ccache.unwrap();
    }
}

#[test]
fn cccol_get_principal() {
    let context = Krb5Context::init().unwrap();
    let collection = Krb5CCCol::new(&context).unwrap();

    for ccache in collection {
        let ccache = ccache.unwrap();
        let principal = ccache.get_principal().unwrap();

        if let Some(principal) = principal {
            let data = principal.data();
            println!("Realm: {}", data.realm().unwrap());
        };
    }
}
