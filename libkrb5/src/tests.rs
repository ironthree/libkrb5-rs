use super::*;

#[test]
fn is_thread_safe() {
    // assert that libkrb5 was built in thread-safe mode
    assert_eq!(unsafe { libkrb5_sys::krb5_is_thread_safe() }, C_TRUE);
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
fn get_default_realm() -> Result<(), Krb5Error> {
    let context = Krb5Context::init()?;
    let _realm = context.get_default_realm()?;
    Ok(())
}

#[test]
fn get_host_realms() -> Result<(), Krb5Error> {
    let context = Krb5Context::init()?;
    let _realms = context.get_host_realms(None)?;
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
