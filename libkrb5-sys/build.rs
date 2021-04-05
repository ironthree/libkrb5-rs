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
        .allowlist_type("(_|)krb5.*")
        .allowlist_function("krb5.*")
        .allowlist_var("ADDRTYPE_.*")
        .allowlist_var("AD_TYPE_.*")
        .allowlist_var("AP_OPTS_.*")
        .allowlist_var("CKSUMTYPE_.*")
        .allowlist_var("ENCTYPE_.*")
        .allowlist_var("KDC_OPT_.*")
        .allowlist_var("KRB5.*")
        .allowlist_var("LR_TYPE_.*")
        .allowlist_var("MAX_KEYTAB_NAME_LEN")
        .allowlist_var("MSEC_.*")
        .allowlist_var("TKT_FLG_.*")
        .size_t_is_usize(true)
        .generate()
        .expect("Unable to generate bindings.");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Unable to write bindings to file.");
}
