use std::env;
use std::path::PathBuf;

use pkg_config::probe_library;

fn main() {
    let library = probe_library("krb5").expect("Unable to find library 'krb5'.");

    for lib in library.libs {
        println!("cargo:rustc-link-lib={}", lib);
    }

    let bindings = bindgen::Builder::default()
        .rust_target(bindgen::RustTarget::Stable_1_40)
        .header("src/wrapper.h")
        .whitelist_type("(_|)krb5.*")
        .whitelist_function("krb5.*")
        .whitelist_var("ADDRTYPE_.*")
        .whitelist_var("AD_TYPE_.*")
        .whitelist_var("AP_OPTS_.*")
        .whitelist_var("CKSUMTYPE_.*")
        .whitelist_var("ENCTYPE_.*")
        .whitelist_var("KDC_OPT_.*")
        .whitelist_var("KRB5.*")
        .whitelist_var("LR_TYPE_.*")
        .whitelist_var("MAX_KEYTAB_NAME_LEN")
        .whitelist_var("MSEC_.*")
        .whitelist_var("TKT_FLG_.*")
        .generate()
        .expect("Unable to generate bindings.");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Unable to write bindings to file.");
}
