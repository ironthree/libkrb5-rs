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
        .blacklist_type("div_t")
        .blacklist_type("fd_set")
        .blacklist_type("fsid_t")
        .blacklist_type("ldiv_t")
        .blacklist_type("lldiv_t")
        .blacklist_type("max_align_t")
        .blacklist_type("timespec")
        .blacklist_type("timeval")
        .blacklist_type("__fsid_t")
        .blacklist_type("__pthread_cond_s")
        .blacklist_type("__pthread_internal_list")
        .blacklist_type("__pthread_list_t")
        .blacklist_type("__pthread_mutex_s")
        .blacklist_type("__pthread_rwlock_arch_t")
        .blacklist_type("__sigset_t")
        .blacklist_type("sigset_t")
        .blacklist_type("pthread_attr_t")
        .blacklist_type("pthread_barrier_t")
        .blacklist_type("pthread_barrierattr_t")
        .blacklist_type("pthread_cond_t")
        .blacklist_type("pthread_condattr_t")
        .blacklist_type("pthread_mutex_t")
        .blacklist_type("pthread_mutexattr_t")
        .blacklist_type("pthread_rwlock_t")
        .blacklist_type("pthread_rwlockattr_t")
        .blacklist_item("_Float64x")
        .blacklist_function("div")
        .blacklist_function("ldiv")
        .blacklist_function("lldiv")
        .blacklist_function("select")
        .blacklist_function("pselect")
        .blacklist_function("strtold")
        .blacklist_function("qecvt")
        .blacklist_function("qfcvt")
        .blacklist_function("qgcvt")
        .blacklist_function("qecvt_r")
        .blacklist_function("qfcvt_r")
        .generate()
        .expect("Unable to generate bindings.");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Unable to write bindings to file.");
}
