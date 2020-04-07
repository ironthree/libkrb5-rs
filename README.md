# libkrb5

This repository contains work-in-progress safe, idiomatic rust bindings for `libkrb5`, the client library of
[MIT Kerberos 5][krb5].

Under the hood, it uses the unsafe, automatically generated `libkrb5-sys` bindings crate.

Bear in mind that `libkrb5` is not entirely thread-safe, according to its
documentation.

For this reason, a Kerberos context can only be created once globally with this
crate, and since that context does not implement `Send` or `Sync`, this only
allows access to the `libkrb5` library on a single thread.

This also means that tests must be executed with
`cargo test -- --test-threads 1` to pass, otherwise they must fail.

[krb5]: https://web.mit.edu/kerberos/

